package com.gpgapp.intent

import android.net.Uri
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** A file read from a `VIEW` intent, waiting to be routed into the app. */
class OpenedDocument(val uri: Uri, val file: PickedFile)

/**
 * Reads the file behind the launch intent's [uri] and hands it to [onOpened].
 *
 * The read happens off the main thread because a provider may stream from disk; the size cap
 * in [FileReader.read] keeps a large file from being loaded at all. Failure to read is
 * reported through [onFailed] so the user is told, rather than the app silently doing nothing.
 */
@Composable
fun OpenedDocumentEffect(
    uri: Uri?,
    onOpened: (PickedFile) -> Unit,
    onFailed: () -> Unit
) {
    if (uri == null) return

    val context = LocalContext.current
    val currentOnOpened by rememberUpdatedState(onOpened)
    val currentOnFailed by rememberUpdatedState(onFailed)

    LaunchedEffect(uri) {
        val picked = try {
            withContext(Dispatchers.IO) { FileReader.read(context, uri) }
        } catch (_: Exception) {
            null
        }
        if (picked != null) currentOnOpened(picked) else currentOnFailed()
    }
}
