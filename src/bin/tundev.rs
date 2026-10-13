//! Opening tun / tap devices for tunnel forwarding (`ssh -w`, sshd's
//! `PermitTunnel`); included by `ssh` and `sshd` via `#[path]`.

#![allow(dead_code)]

/// Open the tun (point-to-point, `mode` 1) or tap (Ethernet, `mode` 2)
/// device `unit` (`0x7fffffff`: any), returning it and its interface name,
/// as OpenSSH's `sys_tun_open` on Linux.
#[cfg(target_os = "linux")]
pub fn open(unit: u32, mode: u32) -> std::io::Result<(std::fs::File, String)> {
    use std::os::fd::AsRawFd;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_TAP: libc::c_short = 0x0002;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    let dev = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    let (flags, prefix) = if mode == puressh::forwarding::tun::MODE_ETHERNET {
        (IFF_TAP, "tap")
    } else {
        (IFF_TUN, "tun")
    };
    let mut req = IfReq {
        name: [0; 16],
        flags: flags | IFF_NO_PI,
        _pad: [0; 22],
    };
    if unit != puressh::forwarding::tun::UNIT_ANY {
        let name = format!("{prefix}{unit}");
        if name.len() >= req.name.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid tunnel unit",
            ));
        }
        req.name[..name.len()].copy_from_slice(name.as_bytes());
    }
    // SAFETY: TUNSETIFF reads and writes a `struct ifreq`, which `IfReq`
    // lays out (name, flags, then the rest of the union); `req` outlives
    // the call.
    if unsafe { libc::ioctl(dev.as_raw_fd(), TUNSETIFF as _, &mut req) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let end = req
        .name
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(req.name.len());
    let name = String::from_utf8_lossy(&req.name[..end]).into_owned();
    Ok((dev, name))
}

/// Tunnel devices are only supported on Linux.
#[cfg(not(target_os = "linux"))]
pub fn open(_unit: u32, _mode: u32) -> std::io::Result<(std::fs::File, String)> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "tunnel devices are not supported on this platform",
    ))
}
