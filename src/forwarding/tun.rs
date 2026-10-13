//! Tunnel device forwarding (`tun@openssh.com`, what `ssh -w` asks for).
//!
//! The client opens a local tun (or tap) device and a `tun@openssh.com`
//! channel naming the mode and the unit the server should open; packets
//! then flow between the two devices, one per `CHANNEL_DATA` message:
//!
//! - point-to-point mode (layer 3, `tun`): an IP packet behind a 4-byte
//!   address family, in OpenBSD's numbering (2 for IPv4, 24 for IPv6) —
//!   Linux devices carry no such header, so it is added and removed here,
//!   as OpenSSH's portable code does;
//! - Ethernet mode (layer 2, `tap`): the frame as is.
//!
//! A packet that does not fit the peer's window is dropped, never split or
//! queued: the tunnel carries datagrams.
//!
//! Opening the device is left to the caller (the `ssh` and `sshd` binaries
//! use `/dev/net/tun` on Linux); [`splice`] then moves its packets.

use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Point-to-point (layer 3) mode.
pub const MODE_POINTOPOINT: u32 = 1;
/// Ethernet (layer 2) mode.
pub const MODE_ETHERNET: u32 = 2;
/// "Any unit": the peer picks a free device.
pub const UNIT_ANY: u32 = 0x7fff_ffff;

const OPENBSD_AF_INET: u32 = 2;
const OPENBSD_AF_INET6: u32 = 24;
/// Size of an IPv4 header without options (`struct ip`): shorter packets
/// are not forwarded, as in OpenSSH.
const MIN_IP_PACKET: usize = 20;

/// Parse a `TunnelDevice` / `-w` unit: a number or `any`.
pub fn parse_unit(s: &str) -> Option<u32> {
    if s.eq_ignore_ascii_case("any") {
        return Some(UNIT_ANY);
    }
    s.parse::<u32>().ok().filter(|u| *u < UNIT_ANY)
}

/// OpenSSH's `a2tun`: `local[:remote]` units (the remote one defaults to
/// any).
pub fn parse_units(s: &str) -> Option<(u32, u32)> {
    match s.split_once(':') {
        Some((l, r)) => Some((parse_unit(l)?, parse_unit(r)?)),
        None => Some((parse_unit(s)?, UNIT_ANY)),
    }
}

/// A packet read from the device, as sent in a `CHANNEL_DATA` message;
/// `None` for one that is not forwarded (too short to be an IP packet).
pub fn to_wire(mode: u32, packet: &[u8]) -> Option<Vec<u8>> {
    if mode != MODE_POINTOPOINT {
        return Some(packet.to_vec());
    }
    if packet.len() <= MIN_IP_PACKET {
        return None;
    }
    let af = if packet[0] >> 4 == 6 {
        OPENBSD_AF_INET6
    } else {
        OPENBSD_AF_INET
    };
    let mut msg = Vec::with_capacity(4 + packet.len());
    msg.extend_from_slice(&af.to_be_bytes());
    msg.extend_from_slice(packet);
    Some(msg)
}

/// The packet a `CHANNEL_DATA` message carries, as written to the device;
/// `None` when it is too short to have the address family.
pub fn from_wire(mode: u32, msg: &[u8]) -> Option<&[u8]> {
    if mode != MODE_POINTOPOINT {
        return Some(msg);
    }
    msg.get(4..)
}

/// Move packets between `dev` and a channel until either ends: `recv`
/// returns the next `CHANNEL_DATA` message (`None` once the channel is
/// done) and `send` sends one (`false` once the channel is gone). Device
/// reads run on a thread of their own; this returns when the channel side
/// ends, after stopping it.
pub fn splice<R, S>(dev: File, mode: u32, mut recv: R, mut send: S) -> io::Result<()>
where
    R: FnMut() -> Option<Vec<u8>>,
    S: FnMut(Vec<u8>) -> bool + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let mut reader = dev.try_clone()?;
    let reader_stop = Arc::clone(&stop);
    let device_to_channel = std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        while !reader_stop.load(Ordering::Relaxed) {
            if !readable(&reader, 200) {
                continue;
            }
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            if let Some(msg) = to_wire(mode, &buf[..n])
                && !send(msg)
            {
                break;
            }
        }
        reader_stop.store(true, Ordering::Relaxed);
    });
    let mut writer = dev;
    while let Some(msg) = recv() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if let Some(packet) = from_wire(mode, &msg) {
            // A packet the device refuses (bad header, interface down) is
            // lost, as a datagram would be.
            let _ = writer.write(packet);
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = device_to_channel.join();
    Ok(())
}

/// Whether `f` becomes readable within `timeout_ms`.
#[cfg(unix)]
fn readable(f: &File, timeout_ms: u16) -> bool {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use std::os::fd::AsFd;
    let mut fds = [PollFd::new(f.as_fd(), PollFlags::POLLIN)];
    matches!(poll(&mut fds, PollTimeout::from(timeout_ms)), Ok(n) if n > 0)
}

/// Elsewhere reads simply block.
#[cfg(not(unix))]
fn readable(_f: &File, _timeout_ms: u16) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn point_to_point_framing() {
        let mut v4 = vec![0x45u8; 40];
        v4[0] = 0x45;
        let msg = to_wire(MODE_POINTOPOINT, &v4).unwrap();
        assert_eq!(&msg[..4], &2u32.to_be_bytes());
        assert_eq!(from_wire(MODE_POINTOPOINT, &msg).unwrap(), &v4[..]);
        let mut v6 = vec![0u8; 60];
        v6[0] = 0x60;
        let msg = to_wire(MODE_POINTOPOINT, &v6).unwrap();
        assert_eq!(&msg[..4], &24u32.to_be_bytes());
        // Too short to be an IP packet, or to carry the family.
        assert!(to_wire(MODE_POINTOPOINT, &[0x45; 20]).is_none());
        assert!(from_wire(MODE_POINTOPOINT, &[0, 0, 2]).is_none());
    }

    #[test]
    fn ethernet_frames_pass_as_is() {
        let frame = [1u8, 2, 3, 4, 5];
        assert_eq!(to_wire(MODE_ETHERNET, &frame).unwrap(), frame);
        assert_eq!(from_wire(MODE_ETHERNET, &frame).unwrap(), &frame);
    }
}
