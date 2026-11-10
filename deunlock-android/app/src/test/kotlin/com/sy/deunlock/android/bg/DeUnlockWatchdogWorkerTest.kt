// Roadmap item S-012 — Robolectric JVM test for the
// `DeUnlockWatchdogWorker`. Pins the DoD bullet verbatim:
//
//   - `resurrects_killed_service` — given `isRunning = false` and a
//     bond on disk, running the worker queues a `startForegroundService`
//     against `DeUnlockCompanionService` and returns `Result.success()`.
//
// Journey: specs/journeys/JOURNEY-S-012-boot-receiver-watchdog.md
package com.sy.deunlock.android.bg

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import androidx.work.ListenableWorker
import androidx.work.testing.TestListenableWorkerBuilder
import com.sy.deunlock.android.bond.BondRecord
import com.sy.deunlock.android.bond.BondStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

private const val FIXTURE_BOND_KEY_LEN: Int = 32
private const val FIXTURE_HOST: String = "alex-desktop"
private const val FIXTURE_PEER: String = "DD:EE:FF:00:11:22"
private const val FIXTURE_KEYSTORE_ALIAS: String = "deunlock.watchdog.alias"

private fun fixtureBond(): BondRecord = BondRecord(
    peerId = FIXTURE_PEER,
    hostName = FIXTURE_HOST,
    bondKey = ByteArray(FIXTURE_BOND_KEY_LEN) { it.toByte() },
    keystoreAlias = FIXTURE_KEYSTORE_ALIAS,
    phonePubkey = ByteArray(FIXTURE_BOND_KEY_LEN) { it.toByte() },
)

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DeUnlockWatchdogWorkerTest {

    private val app: Application
        get() = ApplicationProvider.getApplicationContext()

    @After
    fun cleanup() {
        BondStore(app.filesDir).storePath.delete()
        DeUnlockCompanionService.isRunning.set(false)
    }

    @Test
    fun resurrects_killed_service() {
        DeUnlockCompanionService.isRunning.set(false)
        BondStore(app.filesDir).save(fixtureBond())

        val worker = TestListenableWorkerBuilder
            .from(app, DeUnlockWatchdogWorker::class.java)
            .build()
        val result = worker.startWork().get()

        assertEquals(ListenableWorker.Result.success(), result)
        val started = shadowOf(app).nextStartedService
        assertNotNull("expected DeUnlockCompanionService start, got null", started)
        assertEquals(
            DeUnlockCompanionService::class.java.name,
            started!!.component?.className,
        )
    }
}
