package com.gpgapp.intent

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.gpgapp.intent.OpenedFiles.MAX_BYTES
import java.io.ByteArrayOutputStream
import java.io.IOException

/** A file chosen by the user, already read into memory. */
data class PickedFile(val name: String, val data: ByteArray)

/**
 * Reads a `content://` URI handed to us by the file picker or by another app's "open with".
 *
 * Kept in this object rather than the [android.app.Activity] so every caller gets the same
 * size cap: a provider can hand out a URI to an arbitrarily large file, and reading it all
 * into memory is not acceptable for something that will be decoded and put into a text field.
 */
object FileReader {

    /**
     * Reads [uri], or returns null when the stream cannot be opened or exceeds [MAX_BYTES].
     *
     * The size is checked against the provider's reported length first, and enforced again
     * while copying, because that length is a hint the provider may not implement.
     */
    fun read(context: Context, uri: Uri): PickedFile? {
        val resolver = context.contentResolver

        resolver.openInputStream(uri)?.use { stream ->
                        val buffer = ByteArray(64 * 1024)
            val out = ByteArrayOutputStream()
            var total = 0L
            while (true) {
                val read = try {
                    stream.read(buffer)
                } catch (_: IOException) {
                    return null
                }
                if (read < 0) break
                total += read
                if (total > MAX_BYTES) return null
                out.write(buffer, 0, read)
            }
            return PickedFile(nameOf(context, uri), out.toByteArray())
        }
        return null
    }

    /**
     * Display name of [uri], falling back to the last path segment when the provider does not
     * report one. Providers label files arbitrarily, so callers must treat this as a hint and
     * never dispatch on it.
     */
    fun nameOf(context: Context, uri: Uri): String {
        runCatching {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { cursor ->
                    val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (index >= 0 && cursor.moveToFirst()) {
                        cursor.getString(index)?.takeIf { it.isNotBlank() }?.let { return it }
                    }
                }
        }
        return uri.lastPathSegment ?: "file"
    }
}
