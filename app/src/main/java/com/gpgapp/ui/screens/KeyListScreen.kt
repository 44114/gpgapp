package com.gpgapp.ui.screens

import androidx.compose.animation.animateContentSize
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
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Key
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.gpgapp.R
import com.gpgapp.model.KeyInfo
import com.gpgapp.ui.components.EmptyState
import com.gpgapp.ui.components.GPGButton
import com.gpgapp.ui.components.GPGOutlinedButton
import com.gpgapp.ui.components.KeyChip
import com.gpgapp.ui.components.MonospaceTextField
import com.gpgapp.ui.components.SectionHeader

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyListScreen(
    publicKeys: List<KeyInfo>,
    secretKeys: List<KeyInfo>,
    onKeyClick: (KeyInfo) -> Unit,
    onDeleteKey: (Long) -> Unit,
    onExportPublic: (Long) -> Unit,
    onExportPrivate: (Long) -> Unit,
    onImportKey: (String) -> Unit,
    onBack: () -> Unit
) {
    var showImportDialog by remember { mutableStateOf(false) }
    var importText by remember { mutableStateOf("") }
    var keyToDelete by remember { mutableStateOf<KeyInfo?>(null) }

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
                IconButton(onClick = { showImportDialog = true }) {
                    Icon(Icons.Default.FileUpload, stringResource(R.string.import_key))
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
                            onExport = { onExportPrivate(key.keyId) }
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
                            onExport = { onExportPublic(key.keyId) }
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
    onExport: () -> Unit
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
