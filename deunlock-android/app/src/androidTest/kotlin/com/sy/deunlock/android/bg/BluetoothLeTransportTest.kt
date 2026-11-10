package com.sy.deunlock.android.bg

import android.Manifest
import android.bluetooth.BluetoothManager
import android.content.Context
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.GrantPermissionRule
import com.sy.deunlock.android.pair.impl.AndroidPairGattExchange
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeNotNull
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Requires scripts/ble-emulator-peer.py; never connects to a physical host. */
@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 33)
class BluetoothLeTransportTest {
    @get:Rule
    val permissions: GrantPermissionRule = GrantPermissionRule.grant(Manifest.permission.BLUETOOTH_CONNECT)

    @Test
    fun pairing_exchange_and_persistent_notifications_over_ble() {
        assumeTrue("This test requires an emulator", Build.HARDWARE == "ranchu")
        val address = InstrumentationRegistry.getArguments().getString("blePeerAddress")
        assumeNotNull(address)
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
        assertTrue("Enable emulator Bluetooth before the test", adapter.isEnabled)
        val phonePubkey = ByteArray(32) { it.toByte() }
        val hostPubkey = ByteArray(32) { (31 - it).toByte() }
        assertArrayEquals(hostPubkey, AndroidPairGattExchange(context, adapter).exchangePubkeys(address!!, phonePubkey))

        val received = CountDownLatch(1)
        val frame = AtomicReference<ByteArray>()
        val client = PersistentGattClient(context, adapter, "emulator-peer", address) { peerId, bytes ->
            assertEquals("emulator-peer", peerId)
            frame.set(bytes)
            received.countDown()
        }
        try {
            client.start()
            assertTrue("No challenge notification", received.await(30, TimeUnit.SECONDS))
            assertArrayEquals("ble-challenge".toByteArray(), frame.get())
            assertTrue("Response write refused", client.writeResponse("ble-response".toByteArray()))
            // The fixture verifies the write and prints PASS independently.
            Thread.sleep(1000)
        } finally {
            client.stop()
        }
    }
}
