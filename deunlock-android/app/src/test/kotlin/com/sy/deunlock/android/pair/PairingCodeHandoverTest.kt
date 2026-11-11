// AUDIT-001 D-08 — the pairing code has to reach the backend, or the desktop
// refuses every write and the phone shows a generic failure after the user typed
// ten characters for nothing.
package com.sy.deunlock.android.pair

import com.sy.deunlock.android.pair.api.BluetoothBondRemover
import com.sy.deunlock.android.pair.api.BondPersister
import com.sy.deunlock.android.pair.api.LescResult
import com.sy.deunlock.android.pair.api.OobCalculator
import com.sy.deunlock.android.pair.api.PairBackend
import com.sy.deunlock.android.pair.api.PeerHandle
import com.sy.deunlock.android.pair.api.PickPeerResult
import kotlinx.coroutines.Dispatchers
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

private class CodeRecordingBackend : PairBackend {
    var lastCode: String? = null

    override fun startScan() = Unit

    override fun stopScan() = Unit

    override fun pickPeer(peer: PeerHandle): PickPeerResult = PickPeerResult.LescStarted("123456")

    override fun awaitLescResult(): LescResult = LescResult.Failed("not exercised")

    override fun supplyPairingCode(code: String) {
        lastCode = code
    }
}

private object NoopPersister : BondPersister {
    override fun persist(record: com.sy.deunlock.android.pair.api.BondRecord) = Unit
}

private object NoopRemover : BluetoothBondRemover {
    override fun remove(address: String): Boolean = true
}

private val countingOob = OobCalculator { listOf("1F600") }

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PairingCodeHandoverTest {

    private fun viewModel(backend: PairBackend) = PairingViewModel(
        backend = backend,
        oobCalculator = countingOob,
        bondPersister = NoopPersister,
        bondRemover = NoopRemover,
        associateDispatcher = Dispatchers.Unconfined,
    )

    @Test
    fun the_typed_code_reaches_the_backend() {
        val backend = CodeRecordingBackend()
        val vm = viewModel(backend)
        vm.onPairingCodeChanged("7QK2M9XPDB")
        assertEquals("7QK2M9XPDB", backend.lastCode)
    }

    @Test
    fun the_code_is_echoed_to_the_screen() {
        val backend = CodeRecordingBackend()
        val vm = viewModel(backend)
        vm.onPairingCodeChanged("ABCDE12345")
        assertEquals("ABCDE12345", vm.pairingCode.value)
    }

    @Test
    fun typing_again_replaces_the_previous_code() {
        val backend = CodeRecordingBackend()
        val vm = viewModel(backend)
        vm.onPairingCodeChanged("ABCDE12345")
        vm.onPairingCodeChanged("ABCDE1234")
        assertEquals("ABCDE1234", backend.lastCode)
        assertEquals("ABCDE1234", vm.pairingCode.value)
    }
}
