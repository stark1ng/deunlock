// DEV-002: persisted bond record after the LESC + app-OOB pair flow
// completes.
//
// The Ed25519 private key NEVER appears in this record. The pair flow
// generates the keypair inside the Android Keystore under
// [keystoreAlias]; the only material this record persists is the
// alias the unlock path uses to open the Keystore-resident handle.
// Closes the SPEC §3.2 D6 gap row `docs/known-gaps.md` DEV-002 — the
// Ed25519 seed is no longer present on disk in any form.
//
// The [bondKey] field stays plaintext because it is the symmetric MAC
// key for the unlock channel (used by `verifyChallengeFrame` to gate
// peer authenticity), not the long-term identity key. Moving the
// bond_key into Keystore is residual surface area called out in the
// DEV-002 journey doc's Closure section as a future strengthening
// candidate.
package com.sy.deunlock.android.bond

/**
 * In-memory bond record consumed by the GATT host service and the
 * approve route at unlock time.
 *
 * The shape mirrors what the unlock path needs: [bondKey] for
 * `verifyChallengeFrame`, [keystoreAlias] for opening the
 * Keystore-resident Ed25519 signing key at sign time, and the
 * human-readable [hostName] / [peerId] for the approve notification +
 * the GATT response transport registry.
 */
public data class BondRecord(
    val peerId: String,
    val hostName: String,
    val bondKey: ByteArray,
    val keystoreAlias: String,
    val phonePubkey: ByteArray,
    /**
     * The operator revoked this bond on the phone, but the desktop has not been
     * told yet: it is out of range, or the phone was revoked somewhere the
     * computer was not.
     *
     * A revocation used to be one-sided — the phone forgot the bond, the desktop
     * kept challenging a device that no longer held the key, and because pair
     * mode is exclusive to "no bonds" it also stopped advertising itself as
     * pairable (AUDIT-001 D-14). The fix is a tombstone: the Keystore signing
     * key is destroyed immediately, so nothing can ever be approved again, while
     * the record and its MAC key survive just long enough to carry the
     * revocation frame to the desktop on the next contact.
     */
    val revokePending: Boolean = false,
    /**
     * When the tombstone stops being worth carrying, as Unix epoch millis.
     * `0` when [revokePending] is false. After this, the record is deleted and
     * the desktop is expected to notice by itself (a peer that never answers).
     */
    val revokeDeadlineMs: Long = 0,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is BondRecord) return false
        return peerId == other.peerId &&
            hostName == other.hostName &&
            bondKey.contentEquals(other.bondKey) &&
            revokePending == other.revokePending &&
            revokeDeadlineMs == other.revokeDeadlineMs &&
            keystoreAlias == other.keystoreAlias &&
            phonePubkey.contentEquals(other.phonePubkey)
    }

    override fun hashCode(): Int {
        var result = peerId.hashCode()
        result = 31 * result + hostName.hashCode()
        result = 31 * result + bondKey.contentHashCode()
        result = 31 * result + revokePending.hashCode()
        result = 31 * result + revokeDeadlineMs.hashCode()
        result = 31 * result + keystoreAlias.hashCode()
        result = 31 * result + phonePubkey.contentHashCode()
        return result
    }
}
