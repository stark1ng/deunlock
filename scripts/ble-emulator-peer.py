# /// script
# requires-python = ">=3.10"
# dependencies = ["bumble[android]==0.0.235"]
# ///
"""Virtual BLE peer for BluetoothLeTransportTest, using emulator netsim only."""

import argparse
import asyncio

from bumble.core import AdvertisingData, PhysicalTransport
from bumble.device import Device, DeviceConfiguration
from bumble.gatt import Characteristic, CharacteristicValue, Service
from bumble.hci import OwnAddressType
from bumble.transport import open_transport


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transport", default="android-netsim:name=deunlock-ble-test")
    parser.add_argument("--dual-mode", action="store_true")
    args = parser.parse_args()
    if not args.transport.startswith("android-netsim:"):
        parser.error("Only the emulator android-netsim transport is allowed")

    async with await open_transport(args.transport) as transport:
        config = DeviceConfiguration()
        config.name = "deunlock BLE test"
        config.classic_enabled = args.dual_mode
        device = Device.from_config_with_hci(config, transport.source, transport.sink)
        completed = asyncio.get_running_loop().create_future()
        phone_key_received = False
        connections = 0

        def fail(message):
            if not completed.done():
                completed.set_exception(AssertionError(message))

        def connected(connection):
            nonlocal connections
            connections += 1
            print(f"CONNECTED transport={connection.transport.name}", flush=True)
            if connection.transport != PhysicalTransport.LE:
                fail("Unexpected Classic Bluetooth connection")

        def phone_key_written(connection, value):
            nonlocal phone_key_received
            if value != bytes(range(32)):
                fail("Phone public-key write differed from the test fixture")
            else:
                phone_key_received = True

        def response_written(connection, value):
            if not phone_key_received or value != b"ble-response":
                fail("Missing public-key exchange or incorrect response")
            elif not completed.done():
                completed.set_result(None)

        def uuid(suffix):
            return f"5a4e8e3c-1c4c-4a17-9c81-d518a55a{suffix}"

        challenge = Characteristic(
            uuid("0002"),
            Characteristic.Properties.NOTIFY,
            Characteristic.Permissions.READABLE,
            b"ble-challenge",
        )
        device.add_services(
            [
                Service(
                    uuid("0101"),
                    [
                        Characteristic(
                            uuid("0102"),
                            Characteristic.Properties.READ,
                            Characteristic.Permissions.READABLE,
                            bytes(reversed(range(32))),
                        ),
                        Characteristic(
                            uuid("0103"),
                            Characteristic.Properties.WRITE,
                            Characteristic.Permissions.WRITEABLE,
                            CharacteristicValue(write=phone_key_written),
                        ),
                    ],
                ),
                Service(
                    uuid("0001"),
                    [
                        challenge,
                        Characteristic(
                            uuid("0003"),
                            Characteristic.Properties.WRITE,
                            Characteristic.Permissions.WRITEABLE,
                            CharacteristicValue(write=response_written),
                        ),
                    ],
                ),
            ]
        )

        async def notify_when_subscribed():
            # Leave time for Android's descriptor-write callback, then repeat
            # until the test responds. No authentication data is involved.
            while not completed.done():
                await asyncio.sleep(0.5)
                await device.notify_subscribers(challenge)

        notify_task = None

        def subscribed(connection, characteristic, notify_enabled, indicate_enabled):
            nonlocal notify_task
            if characteristic is challenge and notify_enabled and notify_task is None:
                notify_task = asyncio.create_task(notify_when_subscribed())

        device.on("connection", connected)
        device.on("characteristic_subscription", subscribed)
        await device.power_on()
        device.advertising_data = bytes(
            AdvertisingData(
                [
                    (
                        AdvertisingData.FLAGS,
                        bytes(
                            [
                                AdvertisingData.LE_GENERAL_DISCOVERABLE_MODE_FLAG
                                | AdvertisingData.BR_EDR_NOT_SUPPORTED_FLAG
                            ]
                        )
                        if not args.dual_mode
                        else bytes([AdvertisingData.LE_GENERAL_DISCOVERABLE_MODE_FLAG]),
                    ),
                    (AdvertisingData.COMPLETE_LOCAL_NAME, b"deunlock BLE test"),
                ]
            )
        )
        await device.start_advertising(
            own_address_type=OwnAddressType.PUBLIC, auto_restart=True
        )
        print(
            f"READY blePeerAddress={device.public_address} classic_enabled={args.dual_mode}",
            flush=True,
        )
        try:
            await asyncio.wait_for(completed, timeout=180)
            print(
                f"PASS: public-key exchange, notification and response; {connections} LE connection(s), no Classic connection",
                flush=True,
            )
            await asyncio.sleep(2)
        finally:
            if notify_task is not None:
                notify_task.cancel()
                await asyncio.gather(notify_task, return_exceptions=True)
            # Closing the netsim transport removes this virtual controller.
            # This also avoids racing auto_restart after Android disconnects.


if __name__ == "__main__":
    asyncio.run(main())
