package com.gpgapp.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.gpgapp.R
import com.gpgapp.model.KeyInfo
import com.gpgapp.ui.components.GPGButton
import com.gpgapp.ui.components.InfoCard
import com.gpgapp.ui.components.MonospaceTextField
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyDetailScreen(
    keyInfo: KeyInfo,
    exportedKey: String,
    onExport: () -> Unit,
    onBack: () -> Unit
) {
    val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.key_details)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, stringResource(R.string.back))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            InfoCard(
                title = keyInfo.userId,
                icon = if (keyInfo.isPrivateKey) Icons.Default.Key else Icons.Default.VpnKey,
                color = if (keyInfo.isPrivateKey)
                    MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondary,
                content = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        DetailRow(stringResource(R.string.key_id), keyInfo.keyIdHex)
                        DetailRow(stringResource(R.string.type), stringResource(R.string.key_type_format, keyInfo.algorithm, keyInfo.keySize))
                        DetailRow(
                            stringResource(R.string.created),
                            dateFormat.format(Date(keyInfo.creationDate))
                        )
                        DetailRow(stringResource(R.string.type), stringResource(if (keyInfo.isPrivateKey) R.string.private_key else R.string.public_key))
                    }
                }
            )

            InfoCard(
                title = stringResource(R.string.fingerprint),
                icon = Icons.Default.Fingerprint,
                color = MaterialTheme.colorScheme.tertiary,
                content = {
                    Text(
                        text = keyInfo.fingerprint,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            )

            if (exportedKey.isNotEmpty()) {
                InfoCard(
                    title = stringResource(if (keyInfo.isPrivateKey) R.string.private_key_armored else R.string.public_key_armored),
                    icon = Icons.Default.Lock,
                    color = MaterialTheme.colorScheme.primary,
                    content = {
                        MonospaceTextField(
                            value = exportedKey,
                            onValueChange = {},
                            label = "",
                            readOnly = true,
                            minLines = 8
                        )
                    }
                )
            }

            GPGButton(
                text = stringResource(if (exportedKey.isEmpty()) R.string.export_key else R.string.refresh_export),
                onClick = onExport,
                modifier = Modifier.fillMaxWidth(),
                icon = Icons.Default.ContentCopy
            )
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Medium
        )
    }
}
