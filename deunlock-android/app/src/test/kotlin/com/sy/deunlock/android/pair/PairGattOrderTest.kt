package com.sy.deunlock.android.pair

import com.sy.deunlock.android.pair.impl.exchangePairPubkeys
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class PairGattOrderTest {
    @Test fun reads_host_key_before_phone_write_replaces_pair_service() {
        val hostKey = ByteArray(32) { it.toByte() }
        var pairServiceRegistered = true
        val result = exchangePairPubkeys(
            readHost = { check(pairServiceRegistered) { "pair service was replaced" }; hostKey },
            writePhone = { pairServiceRegistered = false },
        )
        assertArrayEquals(hostKey, result)
    }
}
