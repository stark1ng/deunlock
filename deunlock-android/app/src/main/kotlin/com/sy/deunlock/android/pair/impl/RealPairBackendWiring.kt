// DEV-001 (re-march): production wrappers around the Android
// Bluetooth platform surface used by [RealPairBackend].
//
// Every wrapper here implements one of the [RealPairBackend]
// constructor's seam interfaces with a real Android dependency. The
// Robolectric tests do NOT touch this file — they inject hand-rolled
// fakes directly into [RealPairBackend].
package com.sy.deunlock.android.pair.impl

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.content.BroadcastReceiver
import android.content.Context
import android.content.IntentFilter
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import uniffi.deunlock_mobile.sessionUuidForBond

/**
 * Fixed UUID of the desktop's transient pair service. Byte-identical
 * to the Rust constant `DEUNLOCK_PAIR_SERVICE_UUID` in
 * `crates/deunlock-transport/src/bluez.rs`.
 */
public val DEUNLOCK_PAIR_SERVICE_UUID: UUID = UUID.fromString("5a4e8e3c-1c4c-4a17-9c81-d518a55a0101")

/**
 * Characteristic holding the desktop's 32-byte Ed25519 host pubkey.
 * Byte-identical to the Rust constant
 * `DEUNLOCK_PAIR_HOST_PUBKEY_CHAR_UUID`.
 */
public val DEUNLOCK_PAIR_HOST_PUBKEY_CHAR_UUID: UUID = UUID.fromString("5a4e8e3c-1c4c-4a17-9c81-d518a55a0102")

/**
 * Characteristic the phone writes its 32-byte Ed25519 pubkey to.
 * Byte-identical to the Rust constant
 * `DEUNLOCK_PAIR_PHONE_PUBKEY_CHAR_UUID`.
 */
public val DEUNLOCK_PAIR_PHONE_PUBKEY_CHAR_UUID: UUID = UUID.fromString("5a4e8e3c-1c4c-4a17-9c81-d518a55a0103")

/** Default GATT-exchange wait window for service discovery + char read/write. */
public const val PAIR_GATT_EXCHANGE_TIMEOUT_SECS: Long = 30L

/** Exchange against a pair service whose phone-key write completes pairing. */
internal fun exchangeCodePairingFrame(
    readHost: () -> ByteArray,
    buildWrite: (ByteArray) -> ByteArray,
    writePhone: (ByteArray) -> Unit,
): ByteArray {
    val host = readHost()
    writePhone(buildWrite(host))
    return host
}

/**
 * Production [ReceiverRegistrar] wrapping
 * `Context.registerReceiver` / `Context.unregisterReceiver`.
 */
public class ContextReceiverRegistrar(private val context: Context) : ReceiverRegistrar {
    override fun register(receiver: BroadcastReceiver, filter: IntentFilter) {
        context.registerReceiver(receiver, filter)
    }
    override fun unregister(receiver: BroadcastReceiver) {
        context.unregisterReceiver(receiver)
    }
}

/**
 * Production [PairClock] wrapping the system wall-clock.
 */
public class SystemPairClock : PairClock {
    override fun nowEpochSeconds(): Long = System.currentTimeMillis() / MILLIS_PER_SECOND

    private companion object {
        const val MILLIS_PER_SECOND: Long = 1_000L
    }
}

/**
 * Production [PairSessionUuidLookup] delegating to UniFFI's
 * `sessionUuidForBond` — byte-identical to the Rust
 * `deunlock_transport::session_uuid_for`.
 */
public class UniffiPairSessionUuidLookup : PairSessionUuidLookup {
    override fun lookup(bondKey: ByteArray, minute: Long): ByteArray =
        sessionUuidForBond(bondKey, minute)
}

/**
 * Production [PairGattExchange] wrapping
 * `BluetoothDevice.connectGatt(...)`. Used by [RealPairBackend] after
 * `BOND_BONDED` lands; opens a fresh GATT client connection to the
 * (now bonded) device, discovers the pair service, reads the host key,
 * then writes the phone key. The phone write commits pairing and may
 * replace the pair service, so it must be the final operation.
 *
 * The implementation uses blocking `CountDownLatch`-driven callbacks
 * because the [PairBackend] surface is synchronous. The backend
 * already calls [PairGattExchange.exchangeCodePairing] from a coroutine
 * pumped via `awaitLescResult` -> `runBlocking`, so the blocking is
 * intentional and bounded by [PAIR_GATT_EXCHANGE_TIMEOUT_SECS].
 */
public class AndroidPairGattExchange(
    private val context: Context,
    private val adapter: BluetoothAdapter,
) : PairGattExchange {

    override fun exchangeCodePairing(
        address: String,
        buildWrite: (hostPubkey: ByteArray) -> ByteArray,
    ): ByteArray {
        val device = adapter.getRemoteDevice(address)
        val servicesDiscovered = CountDownLatch(1)
        val writeDone = CountDownLatch(1)
        val readDone = CountDownLatch(1)
        val hostPubkey: AtomicReference<ByteArray?> = AtomicReference(null)
        val failure: AtomicReference<String?> = AtomicReference(null)

        val callback = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                if (newState == BluetoothGatt.STATE_CONNECTED) {
                    runCatching { gatt.discoverServices() }
                } else if (newState == BluetoothGatt.STATE_DISCONNECTED) {
                    if (hostPubkey.get() == null && failure.get() == null) {
                        failure.set("GATT disconnected before host-pubkey read")
                    }
                    servicesDiscovered.countDown()
                    writeDone.countDown()
                    readDone.countDown()
                }
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                servicesDiscovered.countDown()
            }

            override fun onCharacteristicWrite(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int,
            ) {
                if (characteristic.uuid == DEUNLOCK_PAIR_PHONE_PUBKEY_CHAR_UUID) {
                    if (status != BluetoothGatt.GATT_SUCCESS) {
                        failure.set("phone-pubkey write failed status=$status")
                    }
                    writeDone.countDown()
                }
            }

            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int,
            ) {
                if (characteristic.uuid == DEUNLOCK_PAIR_HOST_PUBKEY_CHAR_UUID) {
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        hostPubkey.set(characteristic.value?.copyOf())
                    } else {
                        failure.set("host-pubkey read failed status=$status")
                    }
                    readDone.countDown()
                }
            }
        }

        val gatt = device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
        try {
            if (!servicesDiscovered.await(PAIR_GATT_EXCHANGE_TIMEOUT_SECS, TimeUnit.SECONDS)) {
                throw RuntimeException("service-discovery timeout")
            }
            failure.get()?.let { throw RuntimeException(it) }
            val service = gatt.getService(DEUNLOCK_PAIR_SERVICE_UUID)
                ?: throw RuntimeException("pair service not present on bonded device")
            val phoneChar = service.getCharacteristic(DEUNLOCK_PAIR_PHONE_PUBKEY_CHAR_UUID)
                ?: throw RuntimeException("phone-pubkey characteristic missing")
            val hostChar = service.getCharacteristic(DEUNLOCK_PAIR_HOST_PUBKEY_CHAR_UUID)
                ?: throw RuntimeException("host-pubkey characteristic missing")
            return exchangeCodePairingFrame(readHost = {
                if (!gatt.readCharacteristic(hostChar)) {
                    throw RuntimeException("host-pubkey readCharacteristic refused")
                }
                if (!readDone.await(PAIR_GATT_EXCHANGE_TIMEOUT_SECS, TimeUnit.SECONDS)) {
                    throw RuntimeException("host-pubkey read timeout")
                }
                failure.get()?.let { throw RuntimeException(it) }
                hostPubkey.get() ?: throw RuntimeException("host-pubkey read returned null")
            }, buildWrite = buildWrite, writePhone = { frame ->
                phoneChar.value = frame
                if (!gatt.writeCharacteristic(phoneChar)) {
                    throw RuntimeException("phone-pubkey writeCharacteristic refused")
                }
                if (!writeDone.await(PAIR_GATT_EXCHANGE_TIMEOUT_SECS, TimeUnit.SECONDS)) {
                    throw RuntimeException("phone-pubkey write timeout")
                }
                failure.get()?.let { throw RuntimeException(it) }
            })
        } finally {
            runCatching { gatt.disconnect() }
            runCatching { gatt.close() }
        }
    }
}
