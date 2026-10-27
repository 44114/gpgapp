package com.gpgapp.intent

/** What the app decided to do with a file it was asked to open. */
sealed class OpenedFile {
    /** The file parsed as OpenPGP key material. */
    data class Key(
        val name: String,
        val data: ByteArray
    ) : OpenedFile()

    /** The file is not a key (ciphertext, a signed message, or arbitrary text). */
    data class Message(val name: String, val data: ByteArray) : OpenedFile()
}

/**
 * Classifies a file opened from another app and picks the screen it should land on.
 *
 * Kept free of Android types so the dispatch rules can be exercised by host-side unit tests;
 * the activity only supplies the bytes and the display name.
 */
object OpenedFiles {

    /** Larger inputs are refused rather than held in memory and handed to the UI. */
    const val MAX_BYTES = 4L * 1024 * 1024

    /** Largest message that is still safely rendered inside a text field. */
    private const val MAX_MESSAGE_BYTES = 256L * 1024

    /**
     * Returns null when [data] cannot be opened here.
     *
     * A key is identified by parsing it, not by its file name or MIME type: `.asc` is used for
     * keys, ciphertext and signatures alike, and file managers routinely report OpenPGP files
     * as `application/octet-stream`. Whatever does not parse as a key is treated as message
     * material, which is what the Decrypt and Verify screens accept.
     *
     * @param isKey reports whether the bytes hold OpenPGP key material, normally
     *   `PGPManager::containsKeyRing`.
     */
    fun classify(
        name: String,
        data: ByteArray,
        isKey: (ByteArray) -> Boolean
    ): OpenedFile? {
        if (data.isEmpty() || data.size > MAX_BYTES) return null

        if (runCatching { isKey(data) }.getOrDefault(false)) return OpenedFile.Key(name, data)

        if (data.size > MAX_MESSAGE_BYTES) return null
        // The Decrypt and Verify screens edit text, so a binary packet stream is refused
        // instead of being decoded into mojibake that could never decrypt.
        if (looksBinary(data)) return null
        return OpenedFile.Message(name, data)
    }

    /** A default filename for "save as", derived from the key's user ID. */
    fun suggestedKeyFileName(userId: String, isPrivate: Boolean): String {
        val safeUser = userId
            .substringBefore('<')
            .trim()
            .replace(Regex("[^A-Za-z0-9._-]+"), "_")
            .trim('_', '.')
            .ifBlank { "key" }
        return "$safeUser${if (isPrivate) "_private" else "_public"}.asc"
    }

    /**
     * OpenPGP data that is not armored is a packet stream of (mostly non-ASCII) bytes. U+FFFD
     * is counted because decoding replaces invalid sequences with it.
     */
    private fun looksBinary(data: ByteArray): Boolean {
        if (data.contains(0.toByte())) return true
        val text = data.toString(Charsets.UTF_8)
        val control = text.count { it.code < 0x20 && it != '\n' && it != '\r' && it != '\t' }
        val suspicious = text.count { it == '\uFFFD' } + control
        return suspicious > (text.length / 100) + 8
    }
}
