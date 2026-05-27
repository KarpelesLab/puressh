use alloc::string::ToString;
use alloc::vec;

use super::*;
use super::msg::*;

fn pair() -> (ConnectionState, ConnectionState) {
    (ConnectionState::new(), ConnectionState::new())
}

#[test]
fn open_session_round_trip() {
    let (mut client, mut server) = pair();

    let (client_local, payload) = client.open(ChannelOpen::Session).unwrap();
    let ev = server.on_packet(&payload).unwrap();
    let (server_local, server_kind) = match ev {
        ChannelEvent::OpenRequest { channel, kind } => (channel, kind),
        other => panic!("expected OpenRequest, got {:?}", other),
    };
    assert_eq!(server_kind, ChannelOpen::Session);

    let server_ch = server.channel(server_local).unwrap();
    assert_eq!(server_ch.remote_id, client_local);
    assert_eq!(server_ch.remote_window, client.default_window);
    assert_eq!(server_ch.remote_max_packet, client.default_max_packet);

    let confirm = server.accept_open(server_local).unwrap();
    let ev = client.on_packet(&confirm).unwrap();
    let confirmed_id = match ev {
        ChannelEvent::OpenConfirmed { channel } => channel,
        other => panic!("expected OpenConfirmed, got {:?}", other),
    };
    assert_eq!(confirmed_id, client_local);

    let client_ch = client.channel(client_local).unwrap();
    assert_eq!(client_ch.remote_id, server_local);
    assert_eq!(client_ch.remote_window, server.default_window);
    assert_eq!(client_ch.remote_max_packet, server.default_max_packet);
    assert!(client_ch.is_open());
}

#[test]
fn open_failure_drops_channel() {
    let (mut client, mut server) = pair();
    let (client_local, payload) = client.open(ChannelOpen::Session).unwrap();
    let ev = server.on_packet(&payload).unwrap();
    let server_local = match ev {
        ChannelEvent::OpenRequest { channel, .. } => channel,
        _ => unreachable!(),
    };
    let reject = server
        .reject_open(server_local, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, "nope", "en")
        .unwrap();
    assert!(server.channel(server_local).is_none());

    let ev = client.on_packet(&reject).unwrap();
    match ev {
        ChannelEvent::OpenFailed { channel, reason, description } => {
            assert_eq!(channel, client_local);
            assert_eq!(reason, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
            assert_eq!(description, "nope");
        }
        other => panic!("expected OpenFailed, got {:?}", other),
    }
    assert!(client.channel(client_local).is_none());
}

fn fully_open(client: &mut ConnectionState, server: &mut ConnectionState) -> (u32, u32) {
    let (client_local, payload) = client.open(ChannelOpen::Session).unwrap();
    let ev = server.on_packet(&payload).unwrap();
    let server_local = match ev {
        ChannelEvent::OpenRequest { channel, .. } => channel,
        _ => unreachable!(),
    };
    let confirm = server.accept_open(server_local).unwrap();
    client.on_packet(&confirm).unwrap();
    (client_local, server_local)
}

#[test]
fn data_splits_on_remote_max_packet() {
    let (mut client, mut server) = pair();
    server.default_max_packet = 32;
    let (client_local, _) = fully_open(&mut client, &mut server);

    let initial_remote = client.channel(client_local).unwrap().remote_window;
    let payload = vec![0xab; 100];
    let (wire, n) = client.send_data(client_local, &payload).unwrap();
    assert_eq!(n, 32 - 9);
    assert_eq!(
        client.channel(client_local).unwrap().remote_window,
        initial_remote - n as u32
    );

    let ev = server.on_packet(&wire).unwrap();
    let received = match ev {
        ChannelEvent::Data { data, .. } => data,
        other => panic!("expected Data, got {:?}", other),
    };
    assert_eq!(received, &payload[..n]);
}

#[test]
fn data_splits_on_remote_window() {
    let (mut client, mut server) = pair();
    server.default_window = 50;
    let (client_local, _) = fully_open(&mut client, &mut server);

    let payload = vec![0xcd; 200];
    let (_wire, n1) = client.send_data(client_local, &payload).unwrap();
    assert_eq!(n1, 50);
    let (_wire2, n2) = client.send_data(client_local, &payload[n1..]).unwrap();
    assert_eq!(n2, 0);
}

#[test]
fn window_adjust_increases_remote_window() {
    let (mut client, mut server) = pair();
    server.default_window = 16;
    let (client_local, server_local) = fully_open(&mut client, &mut server);

    let payload = vec![0u8; 16];
    let (wire, n) = client.send_data(client_local, &payload).unwrap();
    assert_eq!(n, 16);
    assert_eq!(client.channel(client_local).unwrap().remote_window, 0);
    let _ = server.on_packet(&wire).unwrap();

    let adj = server.replenish_window(server_local, 16).unwrap();
    let adj = adj.expect("threshold should trigger immediately for window=16");
    let ev = client.on_packet(&adj).unwrap();
    match ev {
        ChannelEvent::WindowAdjust { channel, added } => {
            assert_eq!(channel, client_local);
            assert_eq!(added, 16);
        }
        other => panic!("expected WindowAdjust, got {:?}", other),
    }
    assert_eq!(client.channel(client_local).unwrap().remote_window, 16);
}

#[test]
fn replenish_threshold_holds_then_releases() {
    let (mut client, mut server) = pair();
    server.default_window = 100;
    let (_cl, server_local) = fully_open(&mut client, &mut server);

    assert!(server.replenish_window(server_local, 10).unwrap().is_none());
    assert!(server.replenish_window(server_local, 20).unwrap().is_none());
    let payload = server.replenish_window(server_local, 25).unwrap();
    let payload = payload.expect("crossing half (50) should emit WINDOW_ADJUST");

    let mut r = crate::format::Reader::new(&payload);
    assert_eq!(r.read_u8().unwrap(), MSG_CHANNEL_WINDOW_ADJUST);
    let _id = r.read_u32().unwrap();
    let added = r.read_u32().unwrap();
    assert_eq!(added, 55);
}

#[test]
fn eof_then_close_cycle() {
    let (mut client, mut server) = pair();
    let (client_local, server_local) = fully_open(&mut client, &mut server);

    let eof = client.send_eof(client_local).unwrap();
    assert!(client.channel(client_local).unwrap().local_eof);
    let ev = server.on_packet(&eof).unwrap();
    match ev {
        ChannelEvent::Eof { channel } => assert_eq!(channel, server_local),
        _ => panic!(),
    }
    assert!(server.channel(server_local).unwrap().remote_eof);

    let close_c = client.send_close(client_local).unwrap();
    assert!(client.channel(client_local).unwrap().local_closed);
    let ev = server.on_packet(&close_c).unwrap();
    match ev {
        ChannelEvent::Close { channel } => assert_eq!(channel, server_local),
        _ => panic!(),
    }
    let close_s = server.send_close(server_local).unwrap();
    assert!(server.channel(server_local).is_none());
    let ev = client.on_packet(&close_s).unwrap();
    match ev {
        ChannelEvent::Close { channel } => assert_eq!(channel, client_local),
        _ => panic!(),
    }
    assert!(client.channel(client_local).is_none());

    assert!(matches!(
        client.send_data(client_local, b"x"),
        Err(crate::Error::BadChannelState)
    ));
}

#[test]
fn channel_request_exec_round_trip() {
    let (mut client, mut server) = pair();
    let (client_local, server_local) = fully_open(&mut client, &mut server);

    let req = ChannelRequest::Exec { command: "ls -la".to_string() };
    let payload = client.send_request(client_local, req.clone(), true).unwrap();
    let ev = server.on_packet(&payload).unwrap();
    match ev {
        ChannelEvent::Request { channel, request, want_reply } => {
            assert_eq!(channel, server_local);
            assert!(want_reply);
            assert_eq!(request, req);
        }
        _ => panic!(),
    }

    let succ = server.send_request_success(server_local).unwrap();
    let ev = client.on_packet(&succ).unwrap();
    assert!(matches!(ev, ChannelEvent::Success { channel } if channel == client_local));
}

#[test]
fn channel_request_pty_round_trip() {
    let (mut client, mut server) = pair();
    let (client_local, server_local) = fully_open(&mut client, &mut server);

    let req = ChannelRequest::PtyReq {
        term: "xterm-256color".to_string(),
        cols: 132,
        rows: 43,
        px_w: 1056,
        px_h: 688,
        modes: vec![0x01, 0x00, 0x00, 0x00, 0x03, 0x00],
    };
    let payload = client.send_request(client_local, req.clone(), false).unwrap();
    let ev = server.on_packet(&payload).unwrap();
    match ev {
        ChannelEvent::Request { channel, request, want_reply } => {
            assert_eq!(channel, server_local);
            assert!(!want_reply);
            assert_eq!(request, req);
        }
        _ => panic!(),
    }
}

#[test]
fn channel_request_subsystem_round_trip() {
    let (mut client, mut server) = pair();
    let (client_local, _) = fully_open(&mut client, &mut server);
    let req = ChannelRequest::Subsystem { name: "sftp".to_string() };
    let payload = client.send_request(client_local, req.clone(), true).unwrap();
    let ev = server.on_packet(&payload).unwrap();
    match ev {
        ChannelEvent::Request { request, .. } => assert_eq!(request, req),
        _ => panic!(),
    }
}

#[test]
fn direct_tcpip_open_round_trip() {
    let (mut client, mut server) = pair();
    let open = ChannelOpen::DirectTcpip {
        dest_host: "example.com".to_string(),
        dest_port: 22,
        orig_host: "10.0.0.1".to_string(),
        orig_port: 51234,
    };
    let (_client_local, payload) = client.open(open.clone()).unwrap();
    let ev = server.on_packet(&payload).unwrap();
    match ev {
        ChannelEvent::OpenRequest { kind, .. } => assert_eq!(kind, open),
        _ => panic!(),
    }
}

#[test]
fn forwarded_tcpip_open_round_trip() {
    let (mut client, mut server) = pair();
    let open = ChannelOpen::ForwardedTcpip {
        dest_host: "0.0.0.0".to_string(),
        dest_port: 8080,
        orig_host: "192.168.1.5".to_string(),
        orig_port: 47000,
    };
    let (_, payload) = client.open(open.clone()).unwrap();
    let ev = server.on_packet(&payload).unwrap();
    match ev {
        ChannelEvent::OpenRequest { kind, .. } => assert_eq!(kind, open),
        _ => panic!(),
    }
}

#[test]
fn extended_data_stderr_round_trip() {
    let (mut client, mut server) = pair();
    let (client_local, _server_local) = fully_open(&mut client, &mut server);
    let (wire, n) = client
        .send_extended_data(client_local, SSH_EXTENDED_DATA_STDERR, b"oops\n")
        .unwrap();
    assert_eq!(n, 5);
    let ev = server.on_packet(&wire).unwrap();
    match ev {
        ChannelEvent::ExtendedData { code, data, .. } => {
            assert_eq!(code, SSH_EXTENDED_DATA_STDERR);
            assert_eq!(data, b"oops\n");
        }
        _ => panic!(),
    }
}

#[test]
fn exit_status_request() {
    let (mut client, mut server) = pair();
    let (_, server_local) = fully_open(&mut client, &mut server);
    let req = ChannelRequest::ExitStatus { code: 42 };
    let payload = server.send_request(server_local, req.clone(), false).unwrap();
    let ev = client.on_packet(&payload).unwrap();
    match ev {
        ChannelEvent::Request { request, want_reply, .. } => {
            assert!(!want_reply);
            assert_eq!(request, req);
        }
        _ => panic!(),
    }
}

#[test]
fn exit_signal_request_round_trip() {
    let req = ChannelRequest::ExitSignal {
        name: "TERM".to_string(),
        core_dumped: true,
        message: "terminated by user".to_string(),
        language: "en-US".to_string(),
    };
    let mut w = crate::format::Writer::new();
    req.encode(&mut w);
    let decoded = ChannelRequest::decode("exit-signal", w.as_slice()).unwrap();
    assert_eq!(decoded, req);
}

#[test]
fn env_request_round_trip() {
    let req = ChannelRequest::Env { name: "LANG".to_string(), value: "C.UTF-8".to_string() };
    let mut w = crate::format::Writer::new();
    req.encode(&mut w);
    let decoded = ChannelRequest::decode("env", w.as_slice()).unwrap();
    assert_eq!(decoded, req);
}

#[test]
fn window_change_request_round_trip() {
    let req = ChannelRequest::WindowChange { cols: 80, rows: 24, px_w: 640, px_h: 384 };
    let mut w = crate::format::Writer::new();
    req.encode(&mut w);
    let decoded = ChannelRequest::decode("window-change", w.as_slice()).unwrap();
    assert_eq!(decoded, req);
}

#[test]
fn signal_request_round_trip() {
    let req = ChannelRequest::Signal { name: "INT".to_string() };
    let mut w = crate::format::Writer::new();
    req.encode(&mut w);
    let decoded = ChannelRequest::decode("signal", w.as_slice()).unwrap();
    assert_eq!(decoded, req);
}

#[test]
fn unknown_channel_request_preserves_bytes() {
    let bytes = vec![1u8, 2, 3, 4, 5];
    let req = ChannelRequest::decode("xon-xoff", &bytes).unwrap();
    match req {
        ChannelRequest::Other { name, raw } => {
            assert_eq!(name, "xon-xoff");
            assert_eq!(raw, bytes);
        }
        _ => panic!(),
    }
}

#[test]
fn global_request_tcpip_forward_round_trip() {
    let conn = ConnectionState::new();
    let req = GlobalRequest::TcpipForward {
        bind_address: "0.0.0.0".to_string(),
        bind_port: 0,
    };
    let payload = conn.send_global_request(req.clone(), true);

    let mut peer = ConnectionState::new();
    let ev = peer.on_packet(&payload).unwrap();
    match ev {
        ChannelEvent::GlobalRequest { request, want_reply } => {
            assert!(want_reply);
            assert_eq!(request, req);
        }
        _ => panic!(),
    }
}

#[test]
fn global_request_keepalive_replies_failure() {
    let conn = ConnectionState::new();
    let payload = conn.send_global_request(GlobalRequest::Keepalive, true);

    let mut peer = ConnectionState::new();
    let ev = peer.on_packet(&payload).unwrap();
    let want_reply = match ev {
        ChannelEvent::GlobalRequest { request, want_reply } => {
            assert_eq!(request, GlobalRequest::Keepalive);
            want_reply
        }
        _ => panic!(),
    };
    assert!(want_reply);

    let reply = peer.send_global_failure();
    let mut originator = ConnectionState::new();
    let ev = originator.on_packet(&reply).unwrap();
    assert!(matches!(ev, ChannelEvent::GlobalFailure));
}

#[test]
fn global_request_cancel_forward_round_trip() {
    let req = GlobalRequest::CancelTcpipForward {
        bind_address: "::1".to_string(),
        bind_port: 2222,
    };
    let mut w = crate::format::Writer::new();
    req.encode(&mut w);
    let decoded = GlobalRequest::decode("cancel-tcpip-forward", w.as_slice()).unwrap();
    assert_eq!(decoded, req);
}

#[test]
fn data_after_eof_local_fails() {
    let (mut client, mut server) = pair();
    let (client_local, _) = fully_open(&mut client, &mut server);
    let _ = client.send_eof(client_local).unwrap();
    let err = client.send_data(client_local, b"x").unwrap_err();
    assert!(matches!(err, crate::Error::BadChannelState));
}

#[test]
fn peer_window_violation_is_protocol_error() {
    let (mut client, mut server) = pair();
    client.default_window = 4;
    let (_, server_local) = fully_open(&mut client, &mut server);

    let payload = {
        let remote_id = server.channel(server_local).unwrap().remote_id;
        let mut w = crate::format::Writer::new();
        w.write_u8(MSG_CHANNEL_DATA);
        w.write_u32(remote_id);
        w.write_string(b"too much data");
        w.into_vec()
    };
    let err = client.on_packet(&payload).unwrap_err();
    assert!(matches!(err, crate::Error::Protocol(_)));
}

#[test]
fn channel_request_for_unknown_channel_is_bad_state() {
    let mut server = ConnectionState::new();
    let mut w = crate::format::Writer::new();
    w.write_u8(MSG_CHANNEL_REQUEST);
    w.write_u32(999);
    w.write_string(b"shell");
    w.write_bool(false);
    let err = server.on_packet(&w.into_vec()).unwrap_err();
    assert!(matches!(err, crate::Error::BadChannelState));
}
