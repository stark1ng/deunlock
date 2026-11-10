package com.sy.deunlock.android.lan

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream

/**
 * `u32be(len) ‖ body` framing, the same contract as the desktop's
 * `deunlock-net::framing`.
 *
 * A length prefix is attacker-controlled input, so it is checked against
 * [LanEndpoint.MAX_FRAME_BYTES] *before* any buffer is allocated: a peer that
 * claims 4 GiB gets an error, not an `OutOfMemoryError`.
 */
public object LanFrames {

    /** Write one frame. */
    @Throws(IllegalArgumentException::class)
    public fun write(out: OutputStream, body: ByteArray) {
        require(body.size <= LanEndpoint.MAX_FRAME_BYTES) {
            "frame of ${body.size} bytes exceeds ${LanEndpoint.MAX_FRAME_BYTES}"
        }
        val len = body.size
        out.write(byteArrayOf((len ushr 24).toByte(), (len ushr 16).toByte(), (len ushr 8).toByte(), len.toByte()))
        out.write(body)
        out.flush()
    }

    /**
     * Read one frame.
     *
     * @throws EOFException when the stream ends mid-frame — a truncated LAN
     *   session must not be mistaken for an empty message.
     * @throws IllegalArgumentException when the declared length exceeds
     *   [LanEndpoint.MAX_FRAME_BYTES].
     */
    @Throws(EOFException::class, IllegalArgumentException::class)
    public fun read(input: InputStream): ByteArray {
        val prefix = ByteArray(4)
        readFully(input, prefix)
        // Long, not Int: a prefix of 0xFFFFFFFF must read as 4294967295 and be
        // refused, not wrap to -1 and slip past a `<= MAX` check.
        val declared = ((prefix[0].toLong() and 0xFF) shl 24) or
            ((prefix[1].toLong() and 0xFF) shl 16) or
            ((prefix[2].toLong() and 0xFF) shl 8) or
            (prefix[3].toLong() and 0xFF)
        require(declared in 0..LanEndpoint.MAX_FRAME_BYTES.toLong()) {
            "peer declared $declared bytes, limit is ${LanEndpoint.MAX_FRAME_BYTES}"
        }
        val body = ByteArray(declared.toInt())
        readFully(input, body)
        return body
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
        var read = 0
        while (read < buffer.size) {
            val n = input.read(buffer, read, buffer.size - read)
            if (n < 0) {
                throw EOFException("stream ended after $read of ${buffer.size} bytes")
            }
            read += n
        }
    }
}
