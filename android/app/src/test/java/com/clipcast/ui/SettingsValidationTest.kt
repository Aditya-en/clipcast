package com.clipcast.ui

import org.junit.Assert.*
import org.junit.Test

class SettingsValidationTest {

    @Test
    fun key_validBase64() {
        assertTrue(
            SettingsValidation.validateKey(
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
            ) is SettingsValidation.KeyResult.Valid
        )
    }

    @Test
    fun key_toleratesWhitespaceAndNewlines() {
        assertTrue(
            SettingsValidation.validateKey(
                "  AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"
            ) is SettingsValidation.KeyResult.Valid
        )
        assertEquals(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            SettingsValidation.canonicalKey("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n")
        )
    }

    @Test
    fun key_rejectsEmpty() {
        val result = SettingsValidation.validateKey("   ")
        assertTrue(result is SettingsValidation.KeyResult.Invalid)
    }

    @Test
    fun key_rejectsNonBase64() {
        val result = SettingsValidation.validateKey("!!!not-base64!!!")
        assertTrue(result is SettingsValidation.KeyResult.Invalid)
        assertEquals("Not valid base64", (result as SettingsValidation.KeyResult.Invalid).reason)
    }

    @Test
    fun key_rejectsWrongLength() {
        // 31 bytes.
        val short = java.util.Base64.getEncoder().encodeToString(ByteArray(31) { it.toByte() })
        val result = SettingsValidation.validateKey(short)
        assertTrue(result is SettingsValidation.KeyResult.Invalid)
        assertTrue((result as SettingsValidation.KeyResult.Invalid).reason.contains("32 bytes"))
    }

    @Test
    fun port_acceptsRange() {
        assertEquals(
            SettingsValidation.PortResult.Valid(1024),
            SettingsValidation.validatePort("1024")
        )
        assertEquals(
            SettingsValidation.PortResult.Valid(47474),
            SettingsValidation.validatePort(" 47474 ")
        )
        assertEquals(
            SettingsValidation.PortResult.Valid(65535),
            SettingsValidation.validatePort("65535")
        )
    }

    @Test
    fun port_rejectsOutOfRangeAndGarbage() {
        for (bad in listOf("", "abc", "0", "80", "1023", "65536", "-1", "4.5")) {
            val result = SettingsValidation.validatePort(bad)
            assertTrue("input $bad", result is SettingsValidation.PortResult.Invalid)
        }
    }

    @Test
    fun ports_mustDiffer() {
        assertFalse(SettingsValidation.portsDiffer(47474, 47474))
        assertTrue(SettingsValidation.portsDiffer(47474, 47475))
    }

    @Test
    fun presets_indexAndLabel() {
        assertArrayEquals(
            intArrayOf(64 * 1024, 256 * 1024, 512 * 1024, 900 * 1024),
            SettingsValidation.MAX_APPLY_PRESETS
        )
        assertEquals(2, SettingsValidation.presetIndexFor(512 * 1024))
        assertEquals(3, SettingsValidation.presetIndexFor(900 * 1024))
        assertEquals(0, SettingsValidation.presetIndexFor(0))
        assertEquals("512 KB", SettingsValidation.presetLabel(512 * 1024))
    }

    @Test
    fun fingerprint_matchesIndependentVector() {
        // Independent vector (python hashlib): SHA-256("clipcast key
        // fingerprint" || 32 zero bytes) starts d5 81 b5.
        assertEquals("d5 81 b5", SettingsValidation.keyFingerprint(ByteArray(32)))
        assertEquals(
            "8b 46 cf",
            SettingsValidation.keyFingerprint(ByteArray(32) { it.toByte() })
        )
        // Sensitivity: different keys differ.
        assertNotEquals(
            SettingsValidation.keyFingerprint(ByteArray(32)),
            SettingsValidation.keyFingerprint(ByteArray(32) { 1 })
        )
    }
}
