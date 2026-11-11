// AUDIT-001 D-14: the phone-side half of revocation.
//
// `revoke` used to be one-sided. The phone deleted its record and its Keystore
// key; the desktop kept challenging a device that no longer held the key and,
// because pair mode is exclusive to "no bonds", stopped advertising itself as
// pairable. The operator's symptom was "the computer is not in the list".
//
// The fix keeps a tombstone: the signing key dies immediately, the record and
// its MAC key survive so the revocation frame can be delivered on the next
// contact. These probes pin the on-disk shape of that tombstone.
package com.sy.deunlock.android.bond

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RevocationTombstoneTest {

    @Test
    fun a_tombstone_round_trips_through_disk() {
        val record = BondRecord(
            peerId = PEER_ID,
            hostName = HOSTNAME,
            bondKey = ByteArray(BOND_KEY_BYTES_LEN) { it.toByte() },
            keystoreAlias = KEYSTORE_ALIAS,
            phonePubkey = ByteArray(BOND_KEY_BYTES_LEN) { (it + 1).toByte() },
            revokePending = true,
            revokeDeadlineMs = 1_794_400_000_000L,
        )
        val parsed = parseBondRecord(serializeBondRecord(record))
        assertTrue("revoke flag must survive the round trip", parsed.revokePending)
        assertEquals(
            "a deadline in millis does not fit in an Int; the parser must keep it whole",
            1_794_400_000_000L,
            parsed.revokeDeadlineMs,
        )
        assertEquals(record, parsed)
    }

    @Test
    fun a_record_from_before_the_tombstone_reads_as_not_revoked() {
        val body = buildString {
            appendLine("schema_version = $BOND_RECORD_SCHEMA_VERSION")
            appendLine("host_name = \"$HOSTNAME\"")
            appendLine("peer_id = \"$PEER_ID\"")
            appendLine("bond_key_hex = \"$HEX32\"")
            appendLine("keystore_alias = \"$KEYSTORE_ALIAS\"")
            appendLine("phone_pubkey_hex = \"$HEX32\"")
        }
        val parsed = parseBondRecord(body)
        assertFalse("an older record must not be mistaken for a revocation", parsed.revokePending)
        assertEquals(0L, parsed.revokeDeadlineMs)
    }

    @Test
    fun a_live_bond_does_not_write_tombstone_keys() {
        val record = BondRecord(
            peerId = PEER_ID,
            hostName = HOSTNAME,
            bondKey = ByteArray(BOND_KEY_BYTES_LEN) { it.toByte() },
            keystoreAlias = KEYSTORE_ALIAS,
            phonePubkey = ByteArray(BOND_KEY_BYTES_LEN) { (it + 1).toByte() },
        )
        val body = serializeBondRecord(record)
        assertFalse(
            "a live bond should not advertise a tombstone: $body",
            body.contains("revoke_pending"),
        )
    }
}

// Fixtures are local to this probe: the schema test keeps its own private set,
// and sharing them would couple two independent contracts.
private const val PEER_ID: String = "abcdef0123456789abcdef0123456789"
private const val HOSTNAME: String = "test-desktop"
private const val HEX32: String = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
private const val KEYSTORE_ALIAS: String = "deunlock.ed25519.test-peer"
