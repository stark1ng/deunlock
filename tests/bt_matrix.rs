//! Bluetooth transport matrix; mock only the radio boundary.
//!
//! | Peer | Production path | Required result |
//! |---|---|---|
//! | BLE-only emulator peer | Pair exchange, persistent notify and response | LE connection and exact fixture bytes |
//! | Dual-mode emulator peer | Same operations with Classic available | LE connection and exact fixture bytes |
//!
//! Journey: specs/journeys/JOURNEY-S-016-android-pairing.md

#[test]
fn emulator_gate_rejects_skipped_instrumentation() {
    let status = std::process::Command::new("python3")
        .args(["-m", "unittest", "discover", "-s", "tests", "-p", "test_ble_transport.py"])
        .status()
        .expect("run instrumentation result tests");
    assert!(status.success());
}

#[test]
#[ignore = "requires built APKs, uv, and DEUNLOCK_BLE_EMULATOR_SERIAL naming an owned emulator"]
fn android_pairing_and_notifications_select_le_for_both_peer_types() {
    let status = std::process::Command::new("python3")
        .arg("scripts/test-ble-transport.py")
        .status()
        .expect("run emulator BLE transport matrix");
    assert!(status.success(), "emulator BLE transport matrix failed");
}
