#!/usr/bin/env python3
"""Run both BLE transport fixtures on an explicitly selected Android emulator."""

import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
TEST = "com.sy.deunlock.android.bg.BluetoothLeTransportTest"
RUNNER = "com.sy.deunlock.android.test/androidx.test.runner.AndroidJUnitRunner"


def run(command):
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=120).stdout.strip()


def assert_instrumentation(result):
    assert "OK (1 test)" in result and "INSTRUMENTATION_FAILED" not in result, result
    statuses = re.findall(r"(?m)^INSTRUMENTATION_STATUS_CODE: (-?\d+)\r?$", result)
    assert statuses == ["1", "0"], f"instrumentation did not execute successfully: {statuses}"


def fixture(adb, dual_mode):
    command = ["uv", "run", str(ROOT / "scripts/ble-emulator-peer.py")]
    if dual_mode:
        command.append("--dual-mode")
    lines = queue.Queue()
    captured = []
    peer = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, start_new_session=True)

    def read():
        for line in peer.stdout:
            lines.put(line)
        lines.put(None)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()

    def until(pattern):
        deadline = time.monotonic() + 200
        while time.monotonic() < deadline:
            try:
                line = lines.get(timeout=min(1, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if line is None:
                break
            captured.append(line)
            print(line, end="", flush=True)
            match = re.search(pattern, line)
            if match:
                return match
        raise AssertionError("BLE fixture did not complete:\n" + "".join(captured))

    try:
        address = until(r"READY blePeerAddress=([0-9A-Fa-f:]{17})").group(1)
        result = run([*adb, "shell", "am", "instrument", "-w", "-r", "-e", "class", TEST,
                      "-e", "blePeerAddress", address, RUNNER])
        print(result, flush=True)
        assert_instrumentation(result)
        until(r"PASS: public-key exchange, notification and response;")
        assert peer.wait(timeout=15) == 0, "BLE peer failed after its response assertion"
    finally:
        if peer.poll() is None:
            os.killpg(peer.pid, signal.SIGTERM)
            try:
                peer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(peer.pid, signal.SIGKILL)
                peer.wait(timeout=5)
        reader.join(timeout=5)
        peer.stdout.close()


def main():
    serial = os.environ.get("DEUNLOCK_BLE_EMULATOR_SERIAL", "")
    if not re.fullmatch(r"emulator-\d+", serial):
        raise ValueError("Set DEUNLOCK_BLE_EMULATOR_SERIAL to an owned emulator serial")
    adb = ["adb", "-s", serial]
    assert run([*adb, "shell", "getprop", "ro.kernel.qemu"]) == "1", "emulator required"
    assert run([*adb, "shell", "am", "get-current-user"]) == "0", "Android user 0 required"
    for dual_mode in (False, True):
        print(f"Testing BLE transport: dual_mode={dual_mode}", flush=True)
        fixture(adb, dual_mode)


if __name__ == "__main__":
    main()
