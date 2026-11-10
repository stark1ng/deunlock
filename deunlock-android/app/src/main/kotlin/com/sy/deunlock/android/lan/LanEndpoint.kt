package com.sy.deunlock.android.lan

/**
 * A desktop reachable over Wi-Fi, as learned at pairing time.
 *
 * [fingerprintHex] is the SHA-256 of the desktop's TLS certificate in lowercase
 * hex, exactly what `deunlock doctor` prints and what the pairing QR carries.
 * It is the *only* thing that decides trust on this transport: the address and
 * the port are routing hints that an attacker on the LAN can rewrite freely.
 */
public data class LanEndpoint(
    val host: String,
    val port: Int,
    val fingerprintHex: String,
) {
    /** The pin as bytes. Rejects anything that is not a 32-byte SHA-256 digest. */
    public fun pin(): ByteArray {
        val clean = fingerprintHex.trim().replace(":", "").replace(" ", "")
        require(clean.length == FINGERPRINT_HEX_CHARS) {
            "fingerprint must be $FINGERPRINT_HEX_CHARS hex characters, got ${clean.length}"
        }
        val out = ByteArray(FINGERPRINT_BYTES)
        for (i in out.indices) {
            val hi = clean[2 * i].digitToIntOrNull(16)
            val lo = clean[2 * i + 1].digitToIntOrNull(16)
            require(hi != null && lo != null) { "fingerprint is not hexadecimal" }
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    override fun toString(): String = "$host:$port pin=${fingerprintHex.take(TXT_PREFIX_CHARS)}…"

    public companion object {
        /** SHA-256 digest length. */
        public const val FINGERPRINT_BYTES: Int = 32

        /** Hex characters in a full fingerprint. */
        public const val FINGERPRINT_HEX_CHARS: Int = FINGERPRINT_BYTES * 2

        /** How much of the pin is worth showing in a log line. */
        private const val TXT_PREFIX_CHARS: Int = 16

        /** Default port the desktop listens on. */
        public const val DEFAULT_PORT: Int = 47823

        /** ALPN protocol identifier; must match the desktop. */
        public const val ALPN_PROTOCOL: String = "deunlock/2"

        /** Largest frame either side accepts. */
        public const val MAX_FRAME_BYTES: Int = 4096
    }
}
