//! GUI smoke tests.
//!
//! Verifies app instantiation, RPC bridge channel flow, and state
//! updates without full UI rendering (no GPU required).

use tokio::sync::mpsc;

// We test the bridge and data types directly since they don't
// require a windowing system.

/// Simulates the channel pair used by the GUI.
fn create_test_channels() -> (
    mpsc::Sender<bitevachat_gui::rpc_bridge::UiCommand>,
    mpsc::Receiver<bitevachat_gui::rpc_bridge::UiCommand>,
    mpsc::Sender<bitevachat_gui::rpc_bridge::UiEvent>,
    mpsc::Receiver<bitevachat_gui::rpc_bridge::UiEvent>,
) {
    bitevachat_gui::rpc_bridge::create_channels()
}

#[test]
fn channels_are_bounded() {
    let (cmd_tx, _cmd_rx, evt_tx, _evt_rx) = create_test_channels();

    // Fill the command channel beyond capacity should fail with try_send.
    for i in 0..300 {
        let cmd = bitevachat_gui::rpc_bridge::UiCommand::GetStatus;
        match cmd_tx.try_send(cmd) {
            Ok(_) => {
                // Should succeed up to CMD_CHANNEL_SIZE (256).
                assert!(
                    i < bitevachat_gui::rpc_bridge::CMD_CHANNEL_SIZE,
                    "channel should be bounded at {}",
                    bitevachat_gui::rpc_bridge::CMD_CHANNEL_SIZE,
                );
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Expected after channel is full.
                assert!(
                    i >= bitevachat_gui::rpc_bridge::CMD_CHANNEL_SIZE,
                    "channel full too early at {i}",
                );
                break;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                panic!("channel should not be closed");
            }
        }
    }

    // Same for event channel.
    for i in 0..1100 {
        let evt = bitevachat_gui::rpc_bridge::UiEvent::Error("test".into());
        match evt_tx.try_send(evt) {
            Ok(_) => {
                assert!(
                    i < bitevachat_gui::rpc_bridge::EVT_CHANNEL_SIZE,
                    "event channel should be bounded at {}",
                    bitevachat_gui::rpc_bridge::EVT_CHANNEL_SIZE,
                );
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                assert!(
                    i >= bitevachat_gui::rpc_bridge::EVT_CHANNEL_SIZE,
                    "event channel full too early at {i}",
                );
                break;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                panic!("event channel should not be closed");
            }
        }
    }
}

#[test]
fn event_receive_non_blocking() {
    let (_cmd_tx, _cmd_rx, evt_tx, mut evt_rx) = create_test_channels();

    // try_recv on empty channel should return Empty, not block.
    match evt_rx.try_recv() {
        Err(mpsc::error::TryRecvError::Empty) => {
            // Expected.
        }
        other => {
            panic!("expected TryRecvError::Empty, got {:?}", other);
        }
    }

    // Send an event, then receive it.
    let _ = evt_tx.try_send(bitevachat_gui::rpc_bridge::UiEvent::Connected);
    match evt_rx.try_recv() {
        Ok(bitevachat_gui::rpc_bridge::UiEvent::Connected) => {
            // Expected.
        }
        other => {
            panic!("expected UiEvent::Connected, got {:?}", other);
        }
    }
}

#[test]
fn node_status_default() {
    let status = bitevachat_gui::rpc_bridge::NodeStatus::default();
    assert!(status.state.is_empty());
    assert!(status.address.is_empty());
    assert_eq!(status.pending_count, 0);
}

#[test]
fn profile_data_default() {
    let profile = bitevachat_gui::rpc_bridge::ProfileData::default();
    assert!(!profile.found);
    assert!(profile.name.is_empty());
    assert_eq!(profile.version, 0);
}

#[test]
fn command_send_message_via_channel() {
    let (cmd_tx, mut cmd_rx, _evt_tx, _evt_rx) = create_test_channels();

    let cmd = bitevachat_gui::rpc_bridge::UiCommand::SendMessage {
        recipient: "ab".repeat(32),
        text: "hello".into(),
    };
    let send_result = cmd_tx.try_send(cmd);
    assert!(send_result.is_ok());

    match cmd_rx.try_recv() {
        Ok(bitevachat_gui::rpc_bridge::UiCommand::SendMessage {
            recipient,
            text,
        }) => {
            assert_eq!(recipient.len(), 64);
            assert_eq!(text, "hello");
        }
        other => {
            panic!("expected SendMessage, got {:?}", other);
        }
    }
}

#[test]
fn event_status_updates() {
    let (_cmd_tx, _cmd_rx, evt_tx, mut evt_rx) = create_test_channels();

    let status = bitevachat_gui::rpc_bridge::NodeStatus {
        state: "running".into(),
        address: "ab".repeat(32),
        peer_id: "peer123".into(),
        node_id: "node456".into(),
        listeners: vec!["/ip4/127.0.0.1/tcp/9000".into()],
        pending_count: 5,
    };

    let _ = evt_tx.try_send(bitevachat_gui::rpc_bridge::UiEvent::Status(
        status.clone(),
    ));

    match evt_rx.try_recv() {
        Ok(bitevachat_gui::rpc_bridge::UiEvent::Status(s)) => {
            assert_eq!(s.state, "running");
            assert_eq!(s.pending_count, 5);
        }
        other => {
            panic!("expected Status event, got {:?}", other);
        }
    }
}

#[tokio::test]
async fn bridge_exits_on_sender_drop() {
    let (cmd_tx, cmd_rx, evt_tx, _evt_rx) = create_test_channels();

    let bridge_handle = tokio::spawn(async move {
        bitevachat_gui::rpc_bridge::run_bridge(cmd_rx, evt_tx).await;
    });

    // Drop the command sender — bridge should exit cleanly.
    drop(cmd_tx);

    // Bridge should finish within a reasonable time.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        bridge_handle,
    )
    .await;

    assert!(result.is_ok(), "bridge should exit when sender is dropped");
}