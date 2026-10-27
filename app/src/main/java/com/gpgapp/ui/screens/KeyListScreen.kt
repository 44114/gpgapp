package com.gpgapp.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.gpgapp.R
import com.gpgapp.intent.FileReader
import com.gpgapp.model.KeyInfo
import com.gpgapp.model.PendingImport
import com.gpgapp.ui.components.EmptyState
import com.gpgapp.ui.components.GPGButton
import com.gpgapp.ui.components.GPGOutlinedButton
import com.gpgapp.ui.components.KeyChip
import com.gpgapp.ui.components.MonospaceTextField
import com.gpgapp.ui.components.SectionHeader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyListScreen(
    publicKeys: List<KeyInfo>,
    secretKeys: List<KeyInfo>,
    pendingImport: PendingImport?,
    onKeyClick: (KeyInfo) -> Unit,
    onDeleteKey: (Long) -> Unit,
    onExportPublic: (Long) -> Unit,
    onExportPrivate: (Long) -> Unit,
    onImportKey: (String) -> Unit,
    onFileSelected: (String, ByteArray) -> Unit,
    onConfirmImport: () -> Unit,
    onCancelImport: () -> Unit,
    onSaveKey: (KeyInfo) -> Unit,
    onBack: () -> Unit
) {
    var showImportDialog by remember { mutableStateOf(false) }
    var importText by remember { mutableStateOf("") }
    var keyToDelete by remember { mutableStateOf<KeyInfo?>(null) }

    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // Keys arrive as armored text or as a binary export (gpg --output), and providers disagree
    // about MIME types, so the picker accepts anything and the bytes are classified afterwards
    // (issue #2). The file is read here because the URI grant may not outlive this callback.
    val pickKeyFile = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val picked = withContext(Dispatchers.IO) {
                runCatching { FileReader.read(context, uri) }.getOrNull()
            }
            if (picked != null) {
                onFileSelected(picked.name, picked.data)
                showImportDialog = false
            }
        }
    }

    Column(
        modifier = Modifier.fillMaxSize()
    ) {
        TopAppBar(
            title = { Text(stringResource(R.string.key_management)) },
            navigationIcon = {
                IconButton(onClick = onBack) {
                    Icon(Icons.Default.ArrowBack, stringResource(R.string.back))
                }
            },
            actions = {
                IconButton(onClick = { pickKeyFile.launch(arrayOf("*/*")) }) {
                    Icon(
                        Icons.Default.FileUpload,
                        stringResource(R.string.import_key_from_file)
                    )
                }
                IconButton(onClick = { showImportDialog = true }) {
                    Icon(
                        Icons.Default.Description,
                        stringResource(R.string.import_key)
                    )
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(
                containerColor = MaterialTheme.colorScheme.surface
            )
        )

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            if (publicKeys.isEmpty() && secretKeys.isEmpty()) {
                item {
                    EmptyState(
                        icon = Icons.Default.VpnKey,
                        title = stringResource(R.string.no_keys_found),
                        subtitle = stringResource(R.string.no_keys_found_subtitle)
                    )
                }
            } else {
                if (secretKeys.isNotEmpty()) {
                    item { SectionHeader(stringResource(R.string.private_keys_count, secretKeys.size)) }
                    items(secretKeys) { key ->
                        KeyCard(
                            keyInfo = key,
                            onCardClick = { onKeyClick(key) },
                            onDelete = { keyToDelete = key },
                            onExport = { onExportPrivate(key.keyId) },
                            onSave = { onSaveKey(key) }
                        )
                    }
                }

                if (publicKeys.isNotEmpty()) {
                    item { Spacer(Modifier.height(8.dp)) }
                    item { SectionHeader(stringResource(R.string.public_keys_count, publicKeys.size)) }
                    items(publicKeys) { key ->
                        KeyCard(
                            keyInfo = key,
                            onCardClick = { onKeyClick(key) },
                            onDelete = { keyToDelete = key },
                            onExport = { onExportPublic(key.keyId) },
                            onSave = { onSaveKey(key) }
                        )
                    }
                }
            }

            item { Spacer(Modifier.height(80.dp)) }
        }
    }

    if (showImportDialog) {
        AlertDialog(
            onDismissRequest = { showImportDialog = false },
            title = { Text(stringResource(R.string.import_pgp_key)) },
            text = {
                Column {
                    Text(
                        stringResource(R.string.import_key_instructions),
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Spacer(Modifier.height(12.dp))
                    GPGOutlinedButton(
                        text = stringResource(R.string.choose_key_file),
                        onClick = { pickKeyFile.launch(arrayOf("*/*")) },
                        modifier = Modifier.fillMaxWidth(),
                        icon = Icons.Default.FileUpload
                    )
                    Spacer(Modifier.height(12.dp))
                    Text(
                        stringResource(R.string.import_key_or_paste),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(8.dp))
                    MonospaceTextField(
                        value = importText,
                        onValueChange = { importText = it },
                        label = stringResource(R.string.armored_key),
                        minLines = 6
                    )
                }
            },
            confirmButton = {
                GPGButton(
                    text = stringResource(R.string.action_import),
                    onClick = {
                        onImportKey(importText)
                        showImportDialog = false
                        importText = ""
                    },
                    enabled = importText.isNotBlank()
                )
            },
            dismissButton = {
                TextButton(onClick = { showImportDialog = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    // A file is never imported silently: it may hold a private key that replaces one already
    // on the device, and opening a file must not be able to do that unannounced (issue #3).
    pendingImport?.let { pending ->
        AlertDialog(
            onDismissRequest = onCancelImport,
            title = { Text(stringResource(R.string.import_key_confirm_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    pending.name?.let { name ->
                        Text(
                            stringResource(R.string.import_key_from_file_named, name),
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                    Text(
                        stringResource(R.string.import_key_confirm_note),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        stringResource(R.string.import_private_key_warning),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            },
            confirmButton = {
                GPGButton(
                    text = stringResource(R.string.action_import),
                    onClick = onConfirmImport
                )
            },
            dismissButton = {
                TextButton(onClick = onCancelImport) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    keyToDelete?.let { key ->
        AlertDialog(
            onDismissRequest = { keyToDelete = null },
            title = { Text(stringResource(R.string.delete_key)) },
            text = {
                Text(stringResource(R.string.delete_key_confirmation, key.userId))
            },
            confirmButton = {
                GPGButton(
                    text = stringResource(R.string.delete),
                    onClick = {
                        onDeleteKey(key.keyId)
                        keyToDelete = null
                    }
                )
            },
            dismissButton = {
                TextButton(onClick = { keyToDelete = null }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

@Composable
private fun KeyCard(
    keyInfo: KeyInfo,
    onCardClick: () -> Unit,
    onDelete: () -> Unit,
    onExport: () -> Unit,
    onSave: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onCardClick),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .then(
                            if (keyInfo.isPrivateKey) Modifier
                            else Modifier
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        if (keyInfo.isPrivateKey) Icons.Default.Key else Icons.Default.VpnKey,
                        contentDescription = null,
                        modifier = Modifier.size(24.dp),
                        tint = if (keyInfo.isPrivateKey)
                            Color(0xFFFF9800) else Color(0xFF2196F3)
                    )
                }
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = keyInfo.userId,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Spacer(Modifier.height(2.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        KeyChip(
                            text = keyInfo.algorithm,
                            color = if (keyInfo.isPrivateKey)
                                Color(0xFFFF9800) else Color(0xFF2196F3)
                        )
                        KeyChip(
                            text = stringResource(R.string.bit_size, keyInfo.keySize),
                            color = MaterialTheme.colorScheme.primary
                        )
                        if (keyInfo.isPrivateKey) {
                            KeyChip(
                                text = stringResource(R.string.key_private),
                                color = Color(0xFF4CAF50)
                            )
                        }
                    }
                }
                Column(horizontalAlignment = Alignment.End) {
                    IconButton(onClick = onExport) {
                        Icon(
                            Icons.Default.FileDownload,
                            stringResource(R.string.export),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                    IconButton(onClick = onSave) {
                        Icon(
                            Icons.Default.Save,
                            stringResource(R.string.save_to_file),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                    IconButton(onClick = onDelete) {
                        Icon(
                            Icons.Default.Delete,
                            stringResource(R.string.delete),
                            tint = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }
        }
    }
}
