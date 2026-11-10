package com.sy.deunlock.android.lan

import java.security.KeyManagementException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager

/**
 * A byte-pipe view of one LAN session.
 *
 * The protocol logic in [LanClient] talks to this rather than to `SSLSocket`, so
 * the whole challenge/hello/signature conversation can be exercised in a JVM
 * test with a scripted peer — no phone, no radio, no TLS stack.
 */
public interface LanTransport {
    /** Read one frame. */
    public fun readFrame(): ByteArray

    /** Write one frame. */
    public fun writeFrame(body: ByteArray)

    /** Close the session, ignoring double-close. */
    public fun close()
}

/**
 * One Wi-Fi unlock attempt against a paired desktop.
 *
 * The conversation, in order — every step is a refusal point:
 *
 * 1. TLS 1.3 with the desktop's certificate pinned to [LanEndpoint.fingerprintHex].
 * 2. Read `"DLS1" ‖ session_nonce` — the desktop speaks first.
 * 3. Send the hello, which tags `host_id ‖ peer_id ‖ session_nonce` under a key
 *    derived from the bond. A desktop that is not ours, or a replayed hello,
 *    fails here.
 * 4. Read the v2 challenge frame, verify its MAC and sign the transcript
 *    ([signChallenge] — the same Rust path the BLE flow uses, so the biometric
 *    prompt is only reached once everything above has passed).
 * 5. Send the 64-byte signature.
 *
 * Nothing in this class touches a private key: signing is delegated, exactly as
 * on the BLE path.
 */
public class LanClient(
    private val endpoint: LanEndpoint,
    private val helloBuilder: (sessionNonce: ByteArray) -> ByteArray,
    private val signChallenge: (challengeFrame: ByteArray) -> ByteArray,
    private val transportFactory: (LanEndpoint, Long) -> LanTransport = ::openPinnedTransport,
) {

    /** One attempt. Never throws; every failure is a reason string. */
    public fun unlock(timeoutMs: Long = DEFAULT_TIMEOUT_MS): LanOutcome {
        var transport: LanTransport? = null
        return try {
            transport = transportFactory(endpoint, timeoutMs)
            val sessionChallenge = transport.readFrame()
            val sessionNonce = parseSessionChallenge(sessionChallenge)

            transport.writeFrame(helloBuilder(sessionNonce))

            val challengeFrame = transport.readFrame()
            val signature = signChallenge(challengeFrame)
            require(signature.size == SIGNATURE_BYTES) {
                "signer returned ${signature.size} bytes, expected $SIGNATURE_BYTES"
            }
            transport.writeFrame(signature)
            LanOutcome.Sent
        } catch (t: Throwable) {
            LanOutcome.Failed(t.message ?: t::class.java.simpleName)
        } finally {
            runCatching { transport?.close() }
        }
    }

    /** Parse `"DLS1" ‖ nonce[32]`, rejecting everything else. */
    private fun parseSessionChallenge(bytes: ByteArray): ByteArray {
        require(bytes.size == SESSION_CHALLENGE_BYTES) {
            "session challenge is ${bytes.size} bytes, expected $SESSION_CHALLENGE_BYTES"
        }
        require(
            bytes[0] == MAGIC[0] && bytes[1] == MAGIC[1] && bytes[2] == MAGIC[2] && bytes[3] == MAGIC[3],
        ) { "session challenge magic mismatch" }
        return bytes.copyOfRange(4, SESSION_CHALLENGE_BYTES)
    }

    public companion object {
        /** How long a whole attempt may take before the prompt gives up. */
        public const val DEFAULT_TIMEOUT_MS: Long = 5_000

        /** Ed25519 signature length the desktop reads back. */
        public const val SIGNATURE_BYTES: Int = 64

        /** `"DLS1" ‖ session_nonce[32]`. */
        public const val SESSION_CHALLENGE_BYTES: Int = 36

        private val MAGIC = byteArrayOf('D'.code.toByte(), 'L'.code.toByte(), 'S'.code.toByte(), '1'.code.toByte())
    }
}

/** Result of one LAN attempt. */
public sealed class LanOutcome {
    /** The signature was written to the desktop. */
    public data object Sent : LanOutcome()

    /** Nothing was written, or the session died; [reason] is for the log. */
    public data class Failed(val reason: String) : LanOutcome()
}

/**
 * Open a TLS 1.3 session pinned to the endpoint's fingerprint.
 *
 * ALPN is `deunlock/2` and is checked after the handshake: a port scanner's
 * HTTPS client cannot complete a session, and a peer that answers without our
 * protocol is refused rather than half-trusted.
 */
@Throws(NoSuchAlgorithmException::class, KeyManagementException::class, java.io.IOException::class)
public fun openPinnedTransport(endpoint: LanEndpoint, timeoutMs: Long): LanTransport {
    // `TLSv1.3` on the context plus the explicit protocol list below: the LAN
    // path must not silently fall back to TLS 1.2 or plaintext.
    val context = SSLContext.getInstance("TLSv1.3")
    context.init(null, arrayOf<TrustManager>(PinnedTrustManager(endpoint.pin())), SecureRandom())

    val socket = context.socketFactory.createSocket(endpoint.host, endpoint.port) as SSLSocket
    socket.soTimeout = timeoutMs.toInt()
    socket.enabledProtocols = arrayOf("TLSv1.3")
    socket.sslParameters = socket.sslParameters.apply {
        applicationProtocols = arrayOf(LanEndpoint.ALPN_PROTOCOL)
    }
    socket.startHandshake()

    val negotiated = socket.applicationProtocol
    if (negotiated != LanEndpoint.ALPN_PROTOCOL) {
        socket.close()
        throw java.io.IOException("peer negotiated ALPN '$negotiated', expected '${LanEndpoint.ALPN_PROTOCOL}'")
    }

    val input = socket.inputStream
    val output = socket.outputStream
    return object : LanTransport {
        override fun readFrame(): ByteArray = LanFrames.read(input)
        override fun writeFrame(body: ByteArray) = LanFrames.write(output, body)
        override fun close() = runCatching { socket.close() }.let { }
    }
}
