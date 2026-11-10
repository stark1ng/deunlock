package com.sy.deunlock.android.lan

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException

/**
 * JVM tests for the LAN transport's protocol logic.
 *
 * The TLS layer itself needs a device (or an emulator with a real socket), but
 * everything that decides *whether a session may proceed* is testable here with
 * a scripted peer: framing boundaries, pin parsing, the session-challenge
 * handshake, and the refusal paths.
 */
public class LanClientTest {

    private class FakeTransport(
        private val incoming: MutableList<ByteArray>,
        private val onWrite: (ByteArray) -> Unit = {},
    ) : LanTransport {
        val written: MutableList<ByteArray> = mutableListOf()
        var closed: Boolean = false

        override fun readFrame(): ByteArray {
            if (incoming.isEmpty()) {
                throw EOFException("peer closed the session")
            }
            return incoming.removeAt(0)
        }

        override fun writeFrame(body: ByteArray) {
            written.add(body)
            onWrite(body)
        }

        override fun close() {
            closed = true
        }
    }

    private fun sessionChallenge(nonce: ByteArray): ByteArray =
        "DLS1".toByteArray(Charsets.US_ASCII) + nonce

    // ---------------------------------------------------------------- endpoint

    @Test
    public fun a_full_fingerprint_parses_into_a_pin() {
        val endpoint = LanEndpoint("192.168.1.10", 47823, "ab".repeat(32))
        val pin = endpoint.pin()
        assertEquals(32, pin.size)
        assertEquals(0xAB.toByte(), pin[0])
        assertEquals(0xAB.toByte(), pin[31])
    }

    @Test
    public fun a_pin_with_colons_or_spaces_still_parses() {
        val chopped = "ab:cd:ef:01".repeat(8).replace(":", " ")
        val endpoint = LanEndpoint("host", 1, chopped)
        assertEquals(32, endpoint.pin().size)
    }

    @Test(expected = IllegalArgumentException::class)
    public fun a_short_fingerprint_is_refused() {
        LanEndpoint("host", 1, "abcd").pin()
    }

    @Test(expected = IllegalArgumentException::class)
    public fun a_non_hex_fingerprint_is_refused() {
        LanEndpoint("host", 1, "zz".repeat(32)).pin()
    }

    // ------------------------------------------------------------------ frames

    @Test
    public fun a_frame_survives_the_round_trip() {
        val sink = ByteArrayOutputStream()
        LanFrames.write(sink, byteArrayOf(1, 2, 3, 4))
        val body = LanFrames.read(ByteArrayInputStream(sink.toByteArray()))
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), body)
    }

    @Test(expected = IllegalArgumentException::class)
    public fun an_oversized_frame_is_refused_by_the_writer() {
        LanFrames.write(ByteArrayOutputStream(), ByteArray(LanEndpoint.MAX_FRAME_BYTES + 1))
    }

    @Test(expected = IllegalArgumentException::class)
    public fun a_hostile_length_prefix_is_refused_before_allocating() {
        // 0xFFFFFFFF declared, nothing behind it.
        val hostile = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
        LanFrames.read(ByteArrayInputStream(hostile))
    }

    @Test(expected = EOFException::class)
    public fun a_truncated_frame_is_not_an_empty_message() {
        val truncated = byteArrayOf(0, 0, 0, 10, 'a'.code.toByte(), 'b'.code.toByte())
        LanFrames.read(ByteArrayInputStream(truncated))
    }

    // -------------------------------------------------------------- unlock flow

    @Test
    public fun the_hello_covers_the_desktop_session_nonce() {
        val nonce = ByteArray(32) { it.toByte() }
        val challengeFrame = byteArrayOf(2, 16) + ByteArray(16)
        var helloNonce: ByteArray? = null
        var signedFrame: ByteArray? = null
        val transport = FakeTransport(mutableListOf(sessionChallenge(nonce), challengeFrame))

        val client = LanClient(
            endpoint = LanEndpoint("host", 47823, "ab".repeat(32)),
            helloBuilder = { sessionNonce ->
                helloNonce = sessionNonce
                ByteArray(4) { 0x11 }
            },
            signChallenge = { frame ->
                signedFrame = frame
                ByteArray(64) { 0x22 }
            },
            transportFactory = { _, _ -> transport },
        )

        assertTrue(client.unlock() is LanOutcome.Sent)
        assertArrayEquals(nonce, helloNonce)
        assertArrayEquals(challengeFrame, signedFrame)
        assertEquals("hello then signature", 2, transport.written.size)
        assertEquals(64, transport.written[1].size)
        assertTrue(transport.closed)
    }

    @Test
    public fun a_desktop_that_does_not_speak_our_magic_is_refused() {
        val transport = FakeTransport(mutableListOf("HTTP/1.1 400".toByteArray()))
        var helloBuilt = false
        val client = LanClient(
            endpoint = LanEndpoint("host", 1, "ab".repeat(32)),
            helloBuilder = {
                helloBuilt = true
                ByteArray(4)
            },
            signChallenge = { ByteArray(64) },
            transportFactory = { _, _ -> transport },
        )

        val outcome = client.unlock()
        assertTrue(outcome is LanOutcome.Failed)
        assertTrue("no hello may leave before the challenge is understood", !helloBuilt)
        assertTrue(transport.written.isEmpty())
    }

    @Test
    public fun a_signer_that_returns_the_wrong_length_sends_nothing() {
        val nonce = ByteArray(32)
        val transport = FakeTransport(
            mutableListOf(sessionChallenge(nonce), byteArrayOf(2, 16) + ByteArray(16)),
        )
        val client = LanClient(
            endpoint = LanEndpoint("host", 1, "ab".repeat(32)),
            helloBuilder = { ByteArray(4) },
            signChallenge = { ByteArray(32) }, // wrong width
            transportFactory = { _, _ -> transport },
        )

        val outcome = client.unlock()
        assertTrue(outcome is LanOutcome.Failed)
        assertEquals("only the hello went out", 1, transport.written.size)
    }

    @Test
    public fun a_failing_signer_is_reported_and_the_session_closes() {
        val nonce = ByteArray(32)
        val transport = FakeTransport(
            mutableListOf(sessionChallenge(nonce), byteArrayOf(2, 16) + ByteArray(16)),
        )
        val client = LanClient(
            endpoint = LanEndpoint("host", 1, "ab".repeat(32)),
            helloBuilder = { ByteArray(4) },
            signChallenge = { throw IllegalStateException("challenge MAC did not verify") },
            transportFactory = { _, _ -> transport },
        )

        val outcome = client.unlock()
        assertTrue(outcome is LanOutcome.Failed)
        assertTrue((outcome as LanOutcome.Failed).reason.contains("MAC"))
        assertTrue(transport.closed)
    }
}
