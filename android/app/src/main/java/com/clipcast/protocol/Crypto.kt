package com.clipcast.protocol

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import java.util.Arrays

object Crypto {
    private const val KEY_SIZE = 32
    private const val NONCE_SIZE = 12
    private const val TAG_SIZE = 16
    private const val HEADER_SIZE = 34
    private const val MAX_DATAGRAM_SIZE = 1400
    private const val MAX_PAYLOAD_SIZE = 1200

    /** content_type for the large-text UDP announce (v2 side channel). */
    const val CONTENT_ANNOUNCE: Byte = 0x80.toByte()

    /**
     * Announce payload length: inner(1) + transfer_id(16) + total_len(8) +
     * sha256(32) + tcp_port(2) = 59 bytes.
     */
    const val ANNOUNCE_PAYLOAD_LEN = 59

    /** Inner content type for text/plain UTF-8 inside an announce. */
    const val INNER_TEXT: Byte = 0x01

    /**
     * Inner content type for an image announce: the announced bytes are raw
     * image bytes in the payload's MIME type, fetched over the TCP side
     * channel exactly like large text. Old clients only accept the 59-byte
     * text announce and ignore longer image announces.
     */
    const val INNER_IMAGE: Byte = 0x02

    /** Maximum MIME type length inside an image announce payload. */
    const val MAX_MIME_LEN = 63

    /** Longest image announce payload: 59 base + mime_len(1) + 63 MIME. */
    const val IMAGE_ANNOUNCE_MAX_LEN = ANNOUNCE_PAYLOAD_LEN + 1 + MAX_MIME_LEN

    /** Image MIME types a Clipcast peer may announce. Anything else is ignored. */
    val SUPPORTED_IMAGE_MIMES = arrayOf("image/png", "image/jpeg", "image/webp")

    /** True for a MIME type Clipcast will synchronize. */
    fun isSupportedImageMime(mime: String): Boolean = SUPPORTED_IMAGE_MIMES.contains(mime)

    private val secureRandom = SecureRandom()

    data class DecodedMessage(
        val deviceId: ByteArray,
        val nonce: ByteArray,
        val lamport: Long,
        val timestampMs: Long,
        val contentType: Byte,
        val payload: ByteArray
    )

    /** A decoded large-text UDP announce (content_type 0x80). */
    data class DecodedAnnounce(
        val deviceId: ByteArray,
        val nonce: ByteArray,
        val lamport: Long,
        val timestampMs: Long,
        val innerContentType: Byte,
        val transferId: ByteArray,
        val totalLen: Long,
        val sha256: ByteArray,
        val tcpPort: Int
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is DecodedAnnounce) return false
            return deviceId.contentEquals(other.deviceId) &&
                nonce.contentEquals(other.nonce) &&
                lamport == other.lamport &&
                timestampMs == other.timestampMs &&
                innerContentType == other.innerContentType &&
                transferId.contentEquals(other.transferId) &&
                totalLen == other.totalLen &&
                sha256.contentEquals(other.sha256) &&
                tcpPort == other.tcpPort
        }

        override fun hashCode(): Int {
            var r = deviceId.contentHashCode()
            r = 31 * r + nonce.contentHashCode()
            r = 31 * r + lamport.hashCode()
            r = 31 * r + timestampMs.hashCode()
            r = 31 * r + innerContentType.hashCode()
            r = 31 * r + transferId.contentHashCode()
            r = 31 * r + totalLen.hashCode()
            r = 31 * r + sha256.contentHashCode()
            r = 31 * r + tcpPort
            return r
        }
    }

    fun generateDeviceId(): ByteArray {
        val bytes = ByteArray(16)
        secureRandom.nextBytes(bytes)
        return bytes
    }

    fun generateNonce(): ByteArray {
        val bytes = ByteArray(NONCE_SIZE)
        secureRandom.nextBytes(bytes)
        return bytes
    }

    fun validateKey(keyBase64: String): Boolean {
        return try {
            decodeKey(keyBase64).size == KEY_SIZE
        } catch (e: IllegalArgumentException) {
            false
        }
    }

    fun decodeKey(keyBase64: String): ByteArray {
        // Tolerate missing padding (users may strip trailing '=').
        var s = keyBase64.trim()
        val missing = (4 - s.length % 4) % 4
        if (missing == 3) throw IllegalArgumentException("Invalid base64 length")
        repeat(missing) { s += "=" }
        return java.util.Base64.getDecoder().decode(s)
    }

    fun encodeKey(key: ByteArray): String {
        return java.util.Base64.getEncoder().encodeToString(key)
    }

    fun encode(
        key: ByteArray,
        deviceId: ByteArray,
        lamport: Long,
        timestampMs: Long,
        payload: ByteArray
    ): ByteArray? {
        return encode(key, deviceId, lamport, timestampMs, payload, generateNonce())
    }

    fun encode(
        key: ByteArray,
        deviceId: ByteArray,
        lamport: Long,
        timestampMs: Long,
        payload: ByteArray,
        nonce: ByteArray
    ): ByteArray? {
        if (payload.size > MAX_PAYLOAD_SIZE) {
            return null
        }

        val header = buildHeader(deviceId, nonce)

        val body = buildBody(lamport, timestampMs, payload)
        val ciphertext = encrypt(key, nonce, header, body)
        if (ciphertext == null) return null

        val datagram = ByteArray(header.size + ciphertext.size)
        System.arraycopy(header, 0, datagram, 0, header.size)
        System.arraycopy(ciphertext, 0, datagram, header.size, ciphertext.size)

        if (datagram.size > MAX_DATAGRAM_SIZE) {
            return null
        }

        return datagram
    }

    private fun buildHeader(deviceId: ByteArray, nonce: ByteArray): ByteArray {
        val header = ByteArray(HEADER_SIZE)
        var offset = 0

        "CCLP".toByteArray().copyInto(header, offset)
        offset += 4

        header[offset] = 1
        offset += 1

        header[offset] = 0x01
        offset += 1

        deviceId.copyInto(header, offset)
        offset += 16

        nonce.copyInto(header, offset)

        return header
    }

    private fun buildBody(lamport: Long, timestampMs: Long, payload: ByteArray): ByteArray {
        return buildBodyWithType(lamport, timestampMs, 0x01, payload)
    }

    private fun buildBodyWithType(lamport: Long, timestampMs: Long, contentType: Byte, payload: ByteArray): ByteArray {
        val body = ByteArray(8 + 8 + 1 + 4 + payload.size)
        var offset = 0

        writeUint64(lamport, body, offset)
        offset += 8

        writeUint64(timestampMs, body, offset)
        offset += 8

        body[offset] = contentType
        offset += 1

        writeUint32(payload.size, body, offset)
        offset += 4

        payload.copyInto(body, offset)

        return body
    }

    /**
     * Build the 59-byte announce payload:
     * inner_content_type(1) || transfer_id(16) || total_len u64(8) ||
     * sha256(32) || tcp_port u16(2). All integers big-endian.
     */
    fun encodeAnnouncePayload(
        innerContentType: Byte,
        transferId: ByteArray,
        totalLen: Long,
        sha256: ByteArray,
        tcpPort: Int
    ): ByteArray {
        require(transferId.size == 16) { "transfer_id must be 16 bytes" }
        require(sha256.size == 32) { "sha256 must be 32 bytes" }
        require(tcpPort in 1..65535) { "tcp_port out of range" }
        val buf = ByteArray(ANNOUNCE_PAYLOAD_LEN)
        buf[0] = innerContentType
        transferId.copyInto(buf, 1)
        writeUint64(totalLen, buf, 17)
        sha256.copyInto(buf, 25)
        buf[57] = ((tcpPort ushr 8) and 0xFF).toByte()
        buf[58] = (tcpPort and 0xFF).toByte()
        return buf
    }

    /** Null unless [bytes] is exactly a 59-byte announce payload. */
    fun decodeAnnouncePayload(bytes: ByteArray): DecodedAnnouncePayload? {
        if (bytes.size != ANNOUNCE_PAYLOAD_LEN) return null
        val transferId = bytes.copyOfRange(1, 17)
        val totalLen = readUint64(bytes, 17)
        val sha256 = bytes.copyOfRange(25, 57)
        val tcpPort = ((bytes[57].toInt() and 0xFF) shl 8) or (bytes[58].toInt() and 0xFF)
        if (tcpPort < 1 || tcpPort > 65535) return null
        return DecodedAnnouncePayload(bytes[0], transferId, totalLen, sha256, tcpPort)
    }

    data class DecodedAnnouncePayload(
        val innerContentType: Byte,
        val transferId: ByteArray,
        val totalLen: Long,
        val sha256: ByteArray,
        val tcpPort: Int
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is DecodedAnnouncePayload) return false
            return innerContentType == other.innerContentType &&
                transferId.contentEquals(other.transferId) &&
                totalLen == other.totalLen &&
                sha256.contentEquals(other.sha256) &&
                tcpPort == other.tcpPort
        }

        override fun hashCode(): Int {
            var r = innerContentType.hashCode()
            r = 31 * r + transferId.contentHashCode()
            r = 31 * r + totalLen.hashCode()
            r = 31 * r + sha256.contentHashCode()
            r = 31 * r + tcpPort
            return r
        }
    }

    /**
     * Encode a large-text announce as a normal v1 UDP datagram (existing
     * header, nonce, AES-GCM, body) with content_type 0x80 and the 59-byte
     * announce payload. Null only on encryption failure (the 59-byte payload
     * always fits the datagram).
     */
    fun encodeAnnounce(
        key: ByteArray,
        deviceId: ByteArray,
        lamport: Long,
        timestampMs: Long,
        announcePayload: ByteArray,
        nonce: ByteArray = generateNonce()
    ): ByteArray? {
        if (announcePayload.size != ANNOUNCE_PAYLOAD_LEN) return null
        val header = buildHeader(deviceId, nonce)
        val body = buildBodyWithType(lamport, timestampMs, CONTENT_ANNOUNCE, announcePayload)
        val ciphertext = encrypt(key, nonce, header, body) ?: return null
        val datagram = ByteArray(header.size + ciphertext.size)
        System.arraycopy(header, 0, datagram, 0, header.size)
        System.arraycopy(ciphertext, 0, datagram, header.size, ciphertext.size)
        if (datagram.size > MAX_DATAGRAM_SIZE) return null
        return datagram
    }

    /**
     * Decode a large-text announce datagram. Null for non-announce messages
     * (including v1 text), malformed framing, failed authentication, wrong
     * payload length, or out-of-range port. v1 text behavior is unchanged:
     * use [decode] for content_type 0x01.
     */
    fun decodeAnnounce(key: ByteArray, datagram: ByteArray): DecodedAnnounce? {
        if (datagram.size < HEADER_SIZE + TAG_SIZE + 1) return null
        val header = datagram.copyOfRange(0, HEADER_SIZE)
        if (!Arrays.equals(header.copyOfRange(0, 4), "CCLP".toByteArray())) return null
        if (header[4] != 1.toByte()) return null
        if (header[5] != 0x01.toByte()) return null
        val deviceId = header.copyOfRange(6, 22)
        val nonce = header.copyOfRange(22, 34)
        val ciphertext = datagram.copyOfRange(HEADER_SIZE, datagram.size)
        val plaintext = decrypt(key, nonce, header, ciphertext) ?: return null
        if (plaintext.size < 21) return null
        var offset = 0
        val lamport = readUint64(plaintext, offset)
        offset += 8
        val timestampMs = readUint64(plaintext, offset)
        offset += 8
        if (plaintext[offset] != CONTENT_ANNOUNCE) return null
        offset += 1
        if (plaintext.size < offset + 4) return null
        val payloadLen = readUint32(plaintext, offset)
        offset += 4
        if (plaintext.size != offset + payloadLen) return null
        if (payloadLen != ANNOUNCE_PAYLOAD_LEN) return null
        val payload = plaintext.copyOfRange(offset, offset + payloadLen)
        val parsed = decodeAnnouncePayload(payload) ?: return null
        return DecodedAnnounce(
            deviceId = deviceId,
            nonce = nonce,
            lamport = lamport,
            timestampMs = timestampMs,
            innerContentType = parsed.innerContentType,
            transferId = parsed.transferId,
            totalLen = parsed.totalLen,
            sha256 = parsed.sha256,
            tcpPort = parsed.tcpPort
        )
    }

    /**
     * Build the image announce payload: the 59-byte base announce with
     * inner 0x02, followed by mime_len u8 + MIME bytes. Total 60..123 bytes.
     * Throws [IllegalArgumentException] for bad lengths or MIME types.
     */
    fun encodeImageAnnouncePayload(
        transferId: ByteArray,
        totalLen: Long,
        sha256: ByteArray,
        tcpPort: Int,
        mimeType: String
    ): ByteArray {
        require(transferId.size == 16) { "transfer_id must be 16 bytes" }
        require(sha256.size == 32) { "sha256 must be 32 bytes" }
        require(tcpPort in 1..65535) { "tcp_port out of range" }
        val mime = mimeType.toByteArray(java.nio.charset.StandardCharsets.UTF_8)
        require(mime.size in 1..MAX_MIME_LEN + 1) { "MIME length out of range" }
        require(isSupportedImageMime(mimeType)) { "unsupported image MIME: $mimeType" }
        val buf = ByteArray(ANNOUNCE_PAYLOAD_LEN + 1 + mime.size)
        buf[0] = INNER_IMAGE
        transferId.copyInto(buf, 1)
        writeUint64(totalLen, buf, 17)
        sha256.copyInto(buf, 25)
        buf[57] = ((tcpPort ushr 8) and 0xFF).toByte()
        buf[58] = (tcpPort and 0xFF).toByte()
        buf[59] = mime.size.toByte()
        mime.copyInto(buf, 60)
        return buf
    }

    /** A decoded image announce payload (60..123 bytes, inner 0x02). */
    data class DecodedImageAnnouncePayload(
        val transferId: ByteArray,
        val totalLen: Long,
        val sha256: ByteArray,
        val tcpPort: Int,
        val mimeType: String
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is DecodedImageAnnouncePayload) return false
            return transferId.contentEquals(other.transferId) &&
                totalLen == other.totalLen &&
                sha256.contentEquals(other.sha256) &&
                tcpPort == other.tcpPort &&
                mimeType == other.mimeType
        }

        override fun hashCode(): Int {
            var r = transferId.contentHashCode()
            r = 31 * r + totalLen.hashCode()
            r = 31 * r + sha256.contentHashCode()
            r = 31 * r + tcpPort
            r = 31 * r + mimeType.hashCode()
            return r
        }
    }

    /** Null unless [bytes] is a well-formed 60..123-byte image announce. */
    fun decodeImageAnnouncePayload(bytes: ByteArray): DecodedImageAnnouncePayload? {
        if (bytes.size < ANNOUNCE_PAYLOAD_LEN + 1 || bytes.size > IMAGE_ANNOUNCE_MAX_LEN) return null
        if (bytes[0] != INNER_IMAGE) return null
        val transferId = bytes.copyOfRange(1, 17)
        val totalLen = readUint64(bytes, 17)
        val sha256 = bytes.copyOfRange(25, 57)
        val tcpPort = ((bytes[57].toInt() and 0xFF) shl 8) or (bytes[58].toInt() and 0xFF)
        if (tcpPort < 1 || tcpPort > 65535) return null
        val mimeLen = bytes[59].toInt() and 0xFF
        if (mimeLen != bytes.size - 60) return null
        // Strict UTF-8: malformed MIME bytes are a protocol violation.
        val mimeType = try {
            val decoder = java.nio.charset.StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
            decoder.decode(java.nio.ByteBuffer.wrap(bytes.copyOfRange(60, 60 + mimeLen))).toString()
        } catch (e: Exception) {
            return null
        }
        if (!isSupportedImageMime(mimeType)) return null
        return DecodedImageAnnouncePayload(transferId, totalLen, sha256, tcpPort, mimeType)
    }

    /** A decoded image announce datagram (content_type 0x80, inner 0x02). */
    data class DecodedImageAnnounce(
        val deviceId: ByteArray,
        val nonce: ByteArray,
        val lamport: Long,
        val timestampMs: Long,
        val transferId: ByteArray,
        val totalLen: Long,
        val sha256: ByteArray,
        val tcpPort: Int,
        val mimeType: String
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is DecodedImageAnnounce) return false
            return deviceId.contentEquals(other.deviceId) &&
                nonce.contentEquals(other.nonce) &&
                lamport == other.lamport &&
                timestampMs == other.timestampMs &&
                transferId.contentEquals(other.transferId) &&
                totalLen == other.totalLen &&
                sha256.contentEquals(other.sha256) &&
                tcpPort == other.tcpPort &&
                mimeType == other.mimeType
        }

        override fun hashCode(): Int {
            var r = deviceId.contentHashCode()
            r = 31 * r + nonce.contentHashCode()
            r = 31 * r + lamport.hashCode()
            r = 31 * r + timestampMs.hashCode()
            r = 31 * r + transferId.contentHashCode()
            r = 31 * r + totalLen.hashCode()
            r = 31 * r + sha256.contentHashCode()
            r = 31 * r + tcpPort
            r = 31 * r + mimeType.hashCode()
            return r
        }
    }

    /**
     * Encode an image announce as a v1 UDP datagram (existing header, nonce,
     * AES-GCM, body) with content_type 0x80 and the 60..123-byte image
     * payload. Null only on encryption failure.
     */
    fun encodeImageAnnounce(
        key: ByteArray,
        deviceId: ByteArray,
        lamport: Long,
        timestampMs: Long,
        announcePayload: ByteArray,
        nonce: ByteArray = generateNonce()
    ): ByteArray? {
        if (announcePayload.size < ANNOUNCE_PAYLOAD_LEN + 1 ||
            announcePayload.size > IMAGE_ANNOUNCE_MAX_LEN
        ) return null
        val header = buildHeader(deviceId, nonce)
        val body = buildBodyWithType(lamport, timestampMs, CONTENT_ANNOUNCE, announcePayload)
        val ciphertext = encrypt(key, nonce, header, body) ?: return null
        val datagram = ByteArray(header.size + ciphertext.size)
        System.arraycopy(header, 0, datagram, 0, header.size)
        System.arraycopy(ciphertext, 0, datagram, header.size, ciphertext.size)
        if (datagram.size > MAX_DATAGRAM_SIZE) return null
        return datagram
    }

    /**
     * Decode an image announce datagram. Null for non-announce messages
     * (including v1 text and 59-byte text announces), malformed framing,
     * failed authentication, or an invalid image payload.
     */
    fun decodeImageAnnounce(key: ByteArray, datagram: ByteArray): DecodedImageAnnounce? {
        if (datagram.size < HEADER_SIZE + TAG_SIZE + 1) return null
        val header = datagram.copyOfRange(0, HEADER_SIZE)
        if (!Arrays.equals(header.copyOfRange(0, 4), "CCLP".toByteArray())) return null
        if (header[4] != 1.toByte()) return null
        if (header[5] != 0x01.toByte()) return null
        val deviceId = header.copyOfRange(6, 22)
        val nonce = header.copyOfRange(22, 34)
        val ciphertext = datagram.copyOfRange(HEADER_SIZE, datagram.size)
        val plaintext = decrypt(key, nonce, header, ciphertext) ?: return null
        if (plaintext.size < 21) return null
        var offset = 0
        val lamport = readUint64(plaintext, offset)
        offset += 8
        val timestampMs = readUint64(plaintext, offset)
        offset += 8
        if (plaintext[offset] != CONTENT_ANNOUNCE) return null
        offset += 1
        if (plaintext.size < offset + 4) return null
        val payloadLen = readUint32(plaintext, offset)
        offset += 4
        if (plaintext.size != offset + payloadLen) return null
        val payload = plaintext.copyOfRange(offset, offset + payloadLen)
        val parsed = decodeImageAnnouncePayload(payload) ?: return null
        return DecodedImageAnnounce(
            deviceId = deviceId,
            nonce = nonce,
            lamport = lamport,
            timestampMs = timestampMs,
            transferId = parsed.transferId,
            totalLen = parsed.totalLen,
            sha256 = parsed.sha256,
            tcpPort = parsed.tcpPort,
            mimeType = parsed.mimeType
        )
    }

    private fun encrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(key, "AES")
            val gcmSpec = GCMParameterSpec(TAG_SIZE * 8, nonce)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
            cipher.updateAAD(aad)
            cipher.doFinal(plaintext)
        } catch (e: Exception) {
            null
        }
    }

    fun decode(key: ByteArray, datagram: ByteArray): DecodedMessage? {
        if (datagram.size < HEADER_SIZE + TAG_SIZE + 1) {
            return null
        }

        val header = datagram.copyOfRange(0, HEADER_SIZE)

        if (!Arrays.equals(header.copyOfRange(0, 4), "CCLP".toByteArray())) {
            return null
        }

        if (header[4] != 1.toByte()) {
            return null
        }

        if (header[5] != 0x01.toByte()) {
            return null
        }

        val deviceId = header.copyOfRange(6, 22)
        val nonce = header.copyOfRange(22, 34)
        val ciphertext = datagram.copyOfRange(HEADER_SIZE, datagram.size)

        val plaintext = decrypt(key, nonce, header, ciphertext)
        if (plaintext == null) return null

        return parseBody(deviceId, nonce, plaintext)
    }

    private fun decrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(key, "AES")
            val gcmSpec = GCMParameterSpec(TAG_SIZE * 8, nonce)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
            cipher.updateAAD(aad)
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            null
        }
    }

    private fun parseBody(deviceId: ByteArray, nonce: ByteArray, plaintext: ByteArray): DecodedMessage? {
        if (plaintext.size < 21) {
            return null
        }

        var offset = 0
        val lamport = readUint64(plaintext, offset)
        offset += 8
        val timestampMs = readUint64(plaintext, offset)
        offset += 8
        val contentType = plaintext[offset]
        offset += 1

        if (contentType != 0x01.toByte()) {
            return null
        }

        if (plaintext.size < offset + 4) {
            return null
        }

        val payloadLen = readUint32(plaintext, offset)
        offset += 4

        if (plaintext.size != offset + payloadLen) {
            return null
        }

        if (payloadLen > MAX_PAYLOAD_SIZE) {
            return null
        }

        val payload = plaintext.copyOfRange(offset, offset + payloadLen)

        // Strict UTF-8 validation: reject malformed sequences instead of
        // silently replacing them (Kotlin's decodeToString never throws).
        return try {
            val decoder = java.nio.charset.StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
            decoder.decode(java.nio.ByteBuffer.wrap(payload))
            DecodedMessage(deviceId, nonce, lamport, timestampMs, contentType, payload)
        } catch (e: Exception) {
            null
        }
    }

    private fun writeUint64(value: Long, buffer: ByteArray, offset: Int) {
        var v = value
        for (i in 7 downTo 0) {
            buffer[offset + i] = (v and 0xFF).toByte()
            v = v.ushr(8)
        }
    }

    private fun writeUint32(value: Int, buffer: ByteArray, offset: Int) {
        var v = value
        for (i in 3 downTo 0) {
            buffer[offset + i] = (v and 0xFF).toByte()
            v = v ushr 8
        }
    }

    private fun readUint64(buffer: ByteArray, offset: Int): Long {
        var result = 0L
        for (i in 0..7) {
            result = (result shl 8) + (buffer[offset + i].toLong() and 0xFF)
        }
        return result
    }

    private fun readUint32(buffer: ByteArray, offset: Int): Int {
        var result = 0
        for (i in 0..3) {
            result = (result shl 8) + (buffer[offset + i].toInt() and 0xFF)
        }
        return result
    }

    fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun hexToBytes(hex: String): ByteArray {
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}