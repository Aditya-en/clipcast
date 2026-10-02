package com.clipcast.protocol

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Large-text TCP side channel (v2): pure protocol pieces, no I/O.
 *
 * Contract shared with the Rust daemon (clipcast docs/test-vectors-v2.md).
 * All integers big-endian. Android SDK + Kotlin stdlib only.
 *
 * Request header (70 bytes, sent in the clear, used as AEAD AAD):
 * - magic: 4 bytes ASCII "CCLT"
 * - version: u8 = 1
 * - msg_type: u8 = 0x01 (FETCH)
 * - client_device_id: 16 bytes
 * - transfer_id: 16 bytes
 * - client_nonce: 32 random bytes
 *
 * Session key (32 bytes): HKDF-SHA256 (RFC 5869) with IKM = the shared
 * 32-byte clipcast key, salt = client_nonce,
 * info = ASCII "clipcast tcp v1" followed by the 16 transfer_id bytes.
 *
 * AEAD nonces (12 bytes): byte 0 = direction (0x00 client-to-server,
 * 0x01 server-to-client), bytes 1..3 = zero, bytes 4..11 = u64 frame
 * counter big-endian, starting at 0 per direction. AAD for every sealed
 * frame in both directions = the 70-byte request header.
 */
object TcpCrypto {
    const val REQUEST_HEADER_LEN = 70
    const val CLIENT_NONCE_LEN = 32
    const val TRANSFER_ID_LEN = 16
    const val SESSION_KEY_LEN = 32
    const val TAG_LEN = 16

    /** Max plaintext data bytes per server data frame. */
    const val MAX_FRAME_DATA = 65536

    /** flags(1) + data(<=65536) + tag(16): largest accepted ciphertext. */
    const val MAX_FRAME_CIPHERTEXT = 1 + MAX_FRAME_DATA + TAG_LEN

    /** flags byte bit 0 = FINAL (last frame). All other bits must be zero. */
    const val FLAG_FINAL: Byte = 0x01

    const val DIR_CLIENT_TO_SERVER: Byte = 0x00
    const val DIR_SERVER_TO_CLIENT: Byte = 0x01

    /** Info prefix for the HKDF expand step (followed by 16 transfer_id bytes). */
    val HKDF_INFO_PREFIX: ByteArray = "clipcast tcp v1".toByteArray(Charsets.US_ASCII)

    const val TCP_VERSION: Byte = 1
    const val TCP_MSG_FETCH: Byte = 0x01

    /** Failure to seal/open/verify a frame or reassemble a stream. */
    class TcpException(message: String) : Exception(message)

    data class RequestHeader(
        val clientDeviceId: ByteArray,
        val transferId: ByteArray,
        val clientNonce: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RequestHeader) return false
            return clientDeviceId.contentEquals(other.clientDeviceId) &&
                transferId.contentEquals(other.transferId) &&
                clientNonce.contentEquals(other.clientNonce)
        }

        override fun hashCode(): Int {
            var r = clientDeviceId.contentHashCode()
            r = 31 * r + transferId.contentHashCode()
            r = 31 * r + clientNonce.contentHashCode()
            return r
        }
    }

    fun encodeRequestHeader(h: RequestHeader): ByteArray {
        require(h.clientDeviceId.size == 16) { "client_device_id must be 16 bytes" }
        require(h.transferId.size == TRANSFER_ID_LEN) { "transfer_id must be 16 bytes" }
        require(h.clientNonce.size == CLIENT_NONCE_LEN) { "client_nonce must be 32 bytes" }
        val buf = ByteArray(REQUEST_HEADER_LEN)
        "CCLT".toByteArray(Charsets.US_ASCII).copyInto(buf, 0)
        buf[4] = TCP_VERSION
        buf[5] = TCP_MSG_FETCH
        h.clientDeviceId.copyInto(buf, 6)
        h.transferId.copyInto(buf, 22)
        h.clientNonce.copyInto(buf, 38)
        return buf
    }

    /** Null on any malformed header (length, magic, version, msg_type). */
    fun decodeRequestHeader(bytes: ByteArray): RequestHeader? {
        if (bytes.size != REQUEST_HEADER_LEN) return null
        if (!(bytes[0] == 'C'.code.toByte() && bytes[1] == 'C'.code.toByte() &&
                bytes[2] == 'L'.code.toByte() && bytes[3] == 'T'.code.toByte())
        ) return null
        if (bytes[4] != TCP_VERSION) return null
        if (bytes[5] != TCP_MSG_FETCH) return null
        return RequestHeader(
            clientDeviceId = bytes.copyOfRange(6, 22),
            transferId = bytes.copyOfRange(22, 38),
            clientNonce = bytes.copyOfRange(38, 70)
        )
    }

    /**
     * RFC 5869 HKDF-SHA256 with IKM = shared key, salt = client_nonce,
     * info = "clipcast tcp v1" || transfer_id, output 32 bytes (single block).
     * Implemented with HmacSHA256 (extract, then one expand block).
     */
    fun deriveSessionKey(
        sharedKey: ByteArray,
        clientNonce: ByteArray,
        transferId: ByteArray
    ): ByteArray {
        require(sharedKey.size == 32) { "shared key must be 32 bytes" }
        require(clientNonce.size == CLIENT_NONCE_LEN) { "client_nonce must be 32 bytes" }
        require(transferId.size == TRANSFER_ID_LEN) { "transfer_id must be 16 bytes" }
        // Extract: PRK = HMAC-SHA256(salt=client_nonce, IKM=shared_key).
        val prk = hmacSha256(clientNonce, sharedKey)
        // Expand (single 32-byte block): T(1) = HMAC-SHA256(PRK, info || 0x01).
        val info = ByteArray(HKDF_INFO_PREFIX.size + TRANSFER_ID_LEN)
        HKDF_INFO_PREFIX.copyInto(info, 0)
        transferId.copyInto(info, HKDF_INFO_PREFIX.size)
        val blockInput = ByteArray(info.size + 1)
        info.copyInto(blockInput, 0)
        blockInput[info.size] = 0x01
        return hmacSha256(prk, blockInput)
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** 12-byte AEAD nonce: direction || 0x000000 || counter (big-endian u64). */
    fun frameNonce(direction: Byte, counter: Long): ByteArray {
        val n = ByteArray(12)
        n[0] = direction
        // bytes 1..3 stay zero
        var v = counter
        for (i in 11 downTo 4) {
            n[i] = (v and 0xFF).toByte()
            v = v ushr 8
        }
        return n
    }

    private fun seal(
        sessionKey: ByteArray,
        aadHeader: ByteArray,
        direction: Byte,
        counter: Long,
        plaintext: ByteArray
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(sessionKey, "AES"),
            GCMParameterSpec(TAG_LEN * 8, frameNonce(direction, counter))
        )
        cipher.updateAAD(aadHeader)
        return cipher.doFinal(plaintext)
    }

    private fun open(
        sessionKey: ByteArray,
        aadHeader: ByteArray,
        direction: Byte,
        counter: Long,
        ciphertext: ByteArray
    ): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(sessionKey, "AES"),
                GCMParameterSpec(TAG_LEN * 8, frameNonce(direction, counter))
            )
            cipher.updateAAD(aadHeader)
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Client handshake: AES-256-GCM of the empty plaintext, direction
     * client-to-server, counter 0 — exactly a 16-byte tag, no length prefix.
     */
    fun sealHandshake(sessionKey: ByteArray, aadHeader: ByteArray): ByteArray {
        require(aadHeader.size == REQUEST_HEADER_LEN) { "AAD must be the 70-byte header" }
        val tag = seal(sessionKey, aadHeader, DIR_CLIENT_TO_SERVER, 0, ByteArray(0))
        check(tag.size == TAG_LEN) { "handshake seal must be exactly the 16-byte tag" }
        return tag
    }

    /** False on wrong length, bad tag, or tampered header. */
    fun verifyHandshake(sessionKey: ByteArray, aadHeader: ByteArray, tag: ByteArray): Boolean {
        if (tag.size != TAG_LEN) return false
        if (aadHeader.size != REQUEST_HEADER_LEN) return false
        val plaintext = open(sessionKey, aadHeader, DIR_CLIENT_TO_SERVER, 0, tag) ?: return false
        return plaintext.isEmpty()
    }

    /**
     * Seal one frame plaintext (flags || data) under the session key.
     * Returns the raw ciphertext including the 16-byte tag (no length prefix).
     */
    fun sealFrame(
        sessionKey: ByteArray,
        aadHeader: ByteArray,
        direction: Byte,
        counter: Long,
        flags: Byte,
        data: ByteArray
    ): ByteArray {
        val plaintext = ByteArray(1 + data.size)
        plaintext[0] = flags
        data.copyInto(plaintext, 1)
        return seal(sessionKey, aadHeader, direction, counter, plaintext)
    }

    /**
     * Open one server/client data frame. Checks the length bound, the AEAD
     * tag, and that no reserved flag bits are set. Null on any failure.
     */
    fun openFrame(
        sessionKey: ByteArray,
        aadHeader: ByteArray,
        direction: Byte,
        counter: Long,
        ciphertext: ByteArray
    ): Pair<Byte, ByteArray>? {
        if (ciphertext.size > MAX_FRAME_CIPHERTEXT) return null
        val plaintext = open(sessionKey, aadHeader, direction, counter, ciphertext) ?: return null
        if (plaintext.isEmpty()) return null
        val flags = plaintext[0]
        if ((flags.toInt() and FLAG_FINAL.toInt().inv()) != 0) return null
        return Pair(flags, plaintext.copyOfRange(1, plaintext.size))
    }

    /**
     * Incremental reassembly of server data frames on the client.
     * Enforces: non-final frames carry exactly [MAX_FRAME_DATA] bytes,
     * exactly one FINAL frame, nothing after it, total == total_len.
     * (Counter order is enforced by the AEAD nonce in [openFrame]; the
     * counter is passed through for API symmetry with the Rust caller.)
     */
    class FrameAssembler(val totalLen: Long) {
        // Pre-sized from total_len (clamped for safety); the buffer never
        // grows past total_len (feed rejects any overflow).
        private val buf = java.io.ByteArrayOutputStream(
            totalLen.coerceIn(0, 16L * 1024 * 1024).toInt()
        )
        private var gotFinal = false

        /**
         * Feed one opened frame. Returns true when the FINAL frame arrived
         * (the stream is complete; call [finish] to validate).
         * @throws TcpException on any protocol violation.
         */
        fun feed(flags: Byte, data: ByteArray, counter: Long): Boolean {
            if (gotFinal) throw TcpException("data after FINAL frame")
            if ((flags.toInt() and FLAG_FINAL.toInt().inv()) != 0) {
                throw TcpException("frame flags have reserved bits set: 0x%02x".format(flags))
            }
            val finalFrame = (flags.toInt() and FLAG_FINAL.toInt()) != 0
            if (!finalFrame && data.size != MAX_FRAME_DATA) {
                throw TcpException(
                    "non-final frame must carry exactly $MAX_FRAME_DATA data bytes, got ${data.size}"
                )
            }
            val newTotal = buf.size().toLong() + data.size.toLong()
            if (newTotal > totalLen) {
                throw TcpException("byte count $newTotal != announced total_len $totalLen")
            }
            buf.write(data, 0, data.size)
            if (finalFrame) {
                if (buf.size().toLong() != totalLen) {
                    throw TcpException("byte count ${buf.size()} != announced total_len $totalLen")
                }
                gotFinal = true
                return true
            }
            return false
        }

        /** @throws TcpException if no FINAL frame was seen. */
        fun finish(): ByteArray {
            if (!gotFinal) throw TcpException("missing FINAL frame")
            return buf.toByteArray()
        }
    }

    /**
     * Final content checks after all frames arrived: exact length, SHA-256
     * match, and valid strict UTF-8 for inner type 0x01 (text).
     * @throws TcpException on any mismatch.
     */
    fun verifyContent(
        data: ByteArray,
        totalLen: Long,
        expectedSha256: ByteArray,
        innerContentType: Byte
    ) {
        if (data.size.toLong() != totalLen) {
            throw TcpException("byte count ${data.size} != announced total_len $totalLen")
        }
        if (!sha256(data).contentEquals(expectedSha256)) throw TcpException("SHA-256 mismatch")
        if (innerContentType == 0x01.toByte()) {
            try {
                val decoder = Charsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                decoder.decode(java.nio.ByteBuffer.wrap(data))
            } catch (e: Exception) {
                throw TcpException("invalid UTF-8 for text content")
            }
        }
    }

    fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }
}
