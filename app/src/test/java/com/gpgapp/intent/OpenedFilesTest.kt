package com.gpgapp.intent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host-side tests for the "open with" dispatch behind the `.asc` intent filters (issue #3).
 *
 * The file extension cannot decide anything: `.asc` is what GnuPG writes for keys, ciphertext
 * and signatures alike, so these tests pin the classification down by content. The probe
 * stands in for `PGPManager.containsKeyRing`, which has its own tests in `PGPManagerTest`.
 */
class OpenedFilesTest {

    private val isKey: (ByteArray) -> Boolean = { it.toString(Charsets.UTF_8).startsWith("KEY:") }
    private val notKey: (ByteArray) -> Boolean = { false }

    @Test
    fun `key data opens as a key regardless of its file name`() {
        // A keyserver download has no meaningful extension; the bytes are what count.
        val opened = OpenedFiles.classify("downloaded", "KEY:body".toByteArray(), isKey)

        assertTrue(opened is OpenedFile.Key)
        assertEquals("KEY:body", String((opened as OpenedFile.Key).data))
        assertEquals("downloaded", opened.name)
    }

    @Test
    fun `armored ciphertext opens as a message even though it is named asc`() {
        val ciphertext = "-----BEGIN PGP MESSAGE-----\n\nbody\n-----END PGP MESSAGE-----"
        val opened = OpenedFiles.classify("secret.asc", ciphertext.toByteArray(), notKey)

        assertTrue("armored ciphertext must route to Decrypt", opened is OpenedFile.Message)
        assertEquals(ciphertext, String((opened as OpenedFile.Message).data))
    }

    @Test
    fun `empty file is refused`() {
        assertNull(OpenedFiles.classify("empty.asc", ByteArray(0), isKey))
    }

    @Test
    fun `oversized file is refused before it is decoded`() {
        val big = ByteArray((OpenedFiles.MAX_BYTES + 1).toInt()) { 'A'.code.toByte() }
        assertNull(OpenedFiles.classify("big.asc", big, notKey))
    }

    @Test
    fun `a probe that throws is treated as message material`() {
        val opened = OpenedFiles.classify(
            "signed.asc",
            "text".toByteArray(),
            { throw RuntimeException("parser blew up") }
        )
        assertTrue(opened is OpenedFile.Message)
    }

    @Test
    fun `binary packet stream is refused because the screens edit text`() {
        // A non-armored message cannot be represented in a text field; decoding it would only
        // produce mojibake that never decrypts.
        val binary = byteArrayOf(0x85.toByte(), 0x02, 0x0c, 0x03, 0x00, 0x00, 0x00, 0x00)
        assertNull(OpenedFiles.classify("secret.gpg", binary, notKey))
    }

    @Test
    fun `plain text is message material`() {
        val opened = OpenedFiles.classify("notes.txt", "just some text\n".toByteArray(), notKey)
        assertTrue(opened is OpenedFile.Message)
    }

    @Test
    fun `suggested file names are safe and describe the key`() {
        assertEquals(
            "Alice_Example_private.asc",
            OpenedFiles.suggestedKeyFileName("Alice Example <alice@example.com>", isPrivate = true)
        )
        assertEquals(
            "bob_public.asc",
            OpenedFiles.suggestedKeyFileName("bob", isPrivate = false)
        )
        // Path separators and leading dots cannot leak into the proposed name.
        val hostile = OpenedFiles.suggestedKeyFileName("../../etc/passwd <x@y>", isPrivate = false)
        assertFalse(hostile.contains("/"))
        assertFalse(hostile.startsWith("."))
        assertTrue(hostile.endsWith(".asc"))
    }
}
