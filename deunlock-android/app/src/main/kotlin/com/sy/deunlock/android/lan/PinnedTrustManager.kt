package com.sy.deunlock.android.lan

import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

/**
 * Trusts exactly one certificate: the one whose `SHA-256(cert DER)` equals the
 * fingerprint stored at pairing.
 *
 * Chain and hostname validation are **deliberately skipped**: the desktop's
 * certificate is self-signed, there is no CA to consult, and the pin is a
 * stronger statement than any chain — it names one specific key. Do not "fix"
 * this by reintroducing a trust store; that would make any CA-issued
 * certificate for `deunlock.local` acceptable, which is exactly the attack the
 * pin exists to stop.
 */
public class PinnedTrustManager(private val expectedPin: ByteArray) : X509TrustManager {

    init {
        require(expectedPin.size == LanEndpoint.FINGERPRINT_BYTES) {
            "pin must be ${LanEndpoint.FINGERPRINT_BYTES} bytes"
        }
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        // The desktop never asks for a client certificate; nothing to check.
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        val leaf = chain?.firstOrNull() ?: throw CertificateException("server presented no certificate")
        val digest = MessageDigest.getInstance("SHA-256").digest(leaf.encoded)
        if (!constantTimeEquals(digest, expectedPin)) {
            throw CertificateException("presented certificate does not match the pinned fingerprint")
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) {
            return false
        }
        var diff = 0
        for (i in a.indices) {
            diff = diff or (a[i].toInt() xor b[i].toInt())
        }
        return diff == 0
    }
}
