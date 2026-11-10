package com.sy.deunlock.android

import com.sy.deunlock.android.bond.BondRecord
import com.sy.deunlock.android.bond.BondStore
import com.sy.deunlock.android.bg.DeUnlockCompanionService
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PairingCompletionTest {
    @Test
    fun completing_pairing_refreshes_the_home_card_and_unlock_provider() {
        val context = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()
        androidx.work.testing.WorkManagerTestInitHelper.initializeTestWorkManager(context)
        val controller = Robolectric.buildActivity(MainActivity::class.java).create()
        val activity = controller.get()
        val record = BondRecord(
            peerId = "50:BB:B5:B9:93:AB", hostName = "desktop",
            bondKey = ByteArray(32) { 1 }, keystoreAlias = "test-key",
            phonePubkey = ByteArray(32) { 2 },
        )
        BondStore(activity.filesDir).save(record)
        activity.onPairingCompleted()
        assertEquals(record.peerId, activity.bondRecord.value?.peerId)
        assertEquals(record.peerId, DeUnlockCompanionService.bondListProvider?.bonds()?.single()?.peerId)
        controller.destroy()
        DeUnlockCompanionService.resetSeams()
    }
}
