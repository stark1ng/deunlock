package com.sy.deunlock.android.pair.impl

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.sy.deunlock.android.bg.DefaultGattOpener
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowBluetoothDevice

private class GattConnectionRequested(val transport: Int, val autoConnect: Boolean) : RuntimeException()

/** Capture the real platform call, before Android needs a Bluetooth service. */
@Implements(BluetoothDevice::class)
class TransportRecordingDevice : ShadowBluetoothDevice() {
    @Implementation
    override fun connectGatt(context: Context, autoConnect: Boolean, callback: BluetoothGattCallback): BluetoothGatt {
        throw GattConnectionRequested(BluetoothDevice.TRANSPORT_AUTO, autoConnect)
    }

    @Implementation
    override fun connectGatt(context: Context, autoConnect: Boolean, callback: BluetoothGattCallback, transport: Int): BluetoothGatt {
        throw GattConnectionRequested(transport, autoConnect)
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], shadows = [TransportRecordingDevice::class])
class BluetoothLeTransportTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val adapter = BluetoothAdapter.getDefaultAdapter()
    private val address = "AA:BB:CC:DD:EE:FF"

    @Test
    fun pairing_exchange_explicitly_uses_ble() {
        val request = assertThrows(GattConnectionRequested::class.java) {
            AndroidPairGattExchange(context, adapter).exchangePubkeys(address, ByteArray(32))
        }
        assertEquals(BluetoothDevice.TRANSPORT_LE, request.transport)
        assertEquals(false, request.autoConnect)
    }

    @Test
    fun persistent_connection_explicitly_uses_ble() {
        val request = assertThrows(GattConnectionRequested::class.java) {
            DefaultGattOpener(context).open(adapter.getRemoteDevice(address), true, object : BluetoothGattCallback() {})
        }
        assertEquals(BluetoothDevice.TRANSPORT_LE, request.transport)
        assertEquals(true, request.autoConnect)
    }
}
