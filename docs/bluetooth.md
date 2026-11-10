# Bluetooth pairing troubleshooting

The desktop advertises; the phone connects using LE Secure Connections.
Keep the devices nearby and compare the numeric code before accepting a bond.
Unlocks require approval on the phone for each challenge.

If Android reports `host-pubkey read failed status=1` while the desktop
already lists an active peer, update the companion app. Pairing reads the
desktop key first, then sends the phone key. Sending the phone key commits
pairing and permits the daemon to replace the pair service with its unlock
service. Repeating the exchange after that transition uses invalid handles.

If `deunlock status --json` shows no peers, check `deunlock list`: revoked records
are retained for audit and cannot authenticate. Complete fresh pairing.
Revoke access with `deunlock revoke --id <peer_id>`.

Regression coverage: PairGattOrderTest and RealPairBackendRuntimeTest verify
service replacement ordering and duplicate callback handling without radio I/O.

Open the desktop pairing window with `deunlock pair --waybar --force` before
selecting Pair with computer on Android. Confirm matching codes on both sides
within the pairing deadline. Done refreshes the home card and starts the unlock
connection immediately; reopening the app also loads the persisted bond.

## Reconnecting an existing phone

Returning into range uses the stored bond; do not run pairing again. The updated
companion service closes its GATT handle when Bluetooth is disabled and starts
the same owned client immediately when Bluetooth is enabled. Setup retries stay
active through service discovery and notification subscription, rather than
stopping at the first connection callback. Retries pause while the radio is off.

A nearby-phone radio cycle measured approximately 8 seconds to subscription
after this repair, versus 22 seconds before. These are individual observations,
not a guaranteed latency. Physical leave-and-return and Doze need separate
qualification. Android and radio scheduling still affect reconnection.

Inspect both sides when recovery stalls:

```sh
adb logcat -s deunlock.bg.persistent
journalctl --user -u deunlock-presenced --since '5 minutes ago'
```

On the phone, `descriptor write status=0` for UUID
`00002902-0000-1000-8000-00805f9b34fb` means notification subscription succeeded.
The desktop should log `phone subscribed`. A desktop `cached writer dead`
followed by `rebuilding GATT application` identifies the remaining desktop
recovery problem; repeated pairing does not repair that lifecycle.
The desktop repair in BUG-20261018-1736 instead logs
`notification session closed; awaiting re-subscribe` and retains its GATT
registration. Confirm which daemon build is running when comparing these logs.
`last_connect_ms_ago` currently records a challenge timestamp, not actual
Bluetooth readiness.

The [recovery design investigation](../specs/frds/FRD-20261018-recovery.md)
records the desktop registration, pairing confirmation, CDM association, and
observability changes still needed, with a qualification matrix.

Desktop RPM release 0.1.0-3 uses standard BlueZ notifications. Acquired-FD
cleanup alone is insufficient on the reference BlueZ: a successful phone CCCD
write may not yield another AcquireNotify callback. Release 3 keeps a valid
standard notifier across reconnects. One radio cycle recovered in about 3 s
without GATT rebuilding, followed by a successful real swaylock phone unlock.
These observations do not qualify all adapters, Doze, or physical range loss.

## Explicit LE transport

The Android pairing exchange and persistent unlock connection explicitly select
`BluetoothDevice.TRANSPORT_LE`, including when the desktop supports both LE and
Classic Bluetooth. This does not require enabling an audio profile. The pairing
exchange still reads the host public key before writing the phone public key:
the write can cause the desktop to replace its pair service.

The transport selection and its JVM/emulator tests come from
[D3SOX commit 83e5d69e](https://github.com/D3SOX/deunlock/commit/83e5d69ec3db0bfaadc3f379ffc3686a939f282f).
Upstream notification ownership, numeric comparison, app OOB confirmation, and
per-unlock biometric signing retain their existing behavior.

## Emulator transport matrix

Use a disposable Android 13+ emulator with Bluetooth netsim support, a full
JDK 17 or 21 installation, the Android SDK, `adb`, and `uv`. The existing native
AAR must include the emulator's ABI; `make android-aar` builds it when needed.

```sh
cd deunlock-android
./gradlew :app:testDebugUnitTest :app:assembleDebug :app:assembleDebugAndroidTest
cd ..
```

Create an owned AVD rather than using a personal phone or an existing user's AVD.
For example, start the SDK emulator with an available even-numbered port:

```sh
emulator -avd DEUNLOCK_TEST_AVD -port 5556 -no-window -no-audio \
  -gpu swangle -feature -Vulkan -no-snapshot -netsim-args '--pcap'
adb -s emulator-5556 shell cmd bluetooth_manager enable
adb -s emulator-5556 install --user 0 -r deunlock-android/app/build/outputs/apk/debug/app-debug.apk
adb -s emulator-5556 install --user 0 -r deunlock-android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
DEUNLOCK_BLE_EMULATOR_SERIAL=emulator-5556 cargo test --test bt_matrix -- --ignored --nocapture
```

The runner requires an emulator serial, verifies its emulator identity and
Android user 0, then starts the pinned Bumble peer with BLE-only and dual-mode
configurations. Each case must exchange both fixture keys, receive a notification,
and write the expected response over LE. It requires `OK (1 test)`, rejects a
skipped instrumentation test, and checks the peer's independent `PASS` and exit
status. It stops only the fixture processes it starts. If `uv` selects an
unsuitable Python environment, set `UV_PYTHON` to an installed Python executable.

These cases exercise GATT transport with synthetic fixture bytes. They do not
qualify numeric comparison, Keystore signing, biometrics, power consumption, or
physical-radio recovery. The matrix is explicitly ignored by the ordinary
workspace suite; the explicit command above runs it without accepting skips.
