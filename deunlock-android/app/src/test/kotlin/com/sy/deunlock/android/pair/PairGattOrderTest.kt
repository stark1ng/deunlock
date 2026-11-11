package com.sy.deunlock.android.pair

import com.sy.deunlock.android.pair.impl.exchangeCodePairingFrame
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class PairGattOrderTest {
    @Test fun reads_host_key_before_phone_write_replaces_pair_service() {
        val hostKey = ByteArray(32) { it.toByte() }
        var pairServiceRegistered = true
        val result = exchangeCodePairingFrame(
            readHost = { check(pairServiceRegistered) { "pair service was replaced" }; hostKey },
            buildWrite = { host ->
                // The proof is tagged over the host key that was just read.
                assertArrayEquals(hostKey, host)
                ByteArray(101)
            },
            writePhone = { frame ->
                check(frame.size == 101) { "the pairing frame has the wrong length" }
                pairServiceRegistered = false
            },
        )
        assertArrayEquals(hostKey, result)
    }
}
