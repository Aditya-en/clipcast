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

    private val secureRandom = SecureRandom()

    data class DecodedMessage(
        val deviceId: ByteArray,
        val nonce: ByteArray,
        val lamport: Long,
        val timestampMs: Long,
        val contentType: Byte,
        val payload: ByteArray
    )

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
        val body = ByteArray(8 + 8 + 1 + 4 + payload.size)
        var offset = 0

        writeUint64(lamport, body, offset)
        offset += 8

        writeUint64(timestampMs, body, offset)
        offset += 8

        body[offset] = 0x01
        offset += 1

        writeUint32(payload.size, body, offset)
        offset += 4

        payload.copyInto(body, offset)

        return body
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