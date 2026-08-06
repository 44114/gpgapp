package com.gpgapp.ui.screens

import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.gpgapp.R
import com.gpgapp.model.DecryptionParams
import com.gpgapp.model.KeyInfo
import com.gpgapp.model.OperationState
import com.gpgapp.ui.components.GPGButton
import com.gpgapp.ui.components.MonospaceTextField
import com.gpgapp.ui.components.PasswordField

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DecryptScreen(
    params: DecryptionParams,
    secretKeys: List<KeyInfo>,
    decryptedResult: String,
    operationState: OperationState,
    onUpdateParams: (DecryptionParams) -> Unit,
    onDecrypt: () -> Unit,
    onBack: () -> Unit
) {
    var showKeyDropdown by remember { mutableStateOf(false) }
    val selectedKey = secretKeys.find { it.keyId == params.selectedKeyId }
    val isLoading = operationState is OperationState.Loading

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.decrypt_message)) },
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
            Text(
                text = stringResource(R.string.select_private_key),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )

            OutlinedCard(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { showKeyDropdown = true }
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.Key,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = selectedKey?.userId ?: stringResource(R.string.select_a_private_key),
                            style = MaterialTheme.typography.bodyLarge,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        if (selectedKey != null) {
                            Text(
                                text = stringResource(R.string.key_type_format, selectedKey.algorithm, selectedKey.keySize),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    Icon(
                        Icons.Default.KeyboardArrowDown,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                DropdownMenu(
                    expanded = showKeyDropdown,
                    onDismissRequest = { showKeyDropdown = false }
                ) {
                    secretKeys.forEach { key ->
                        DropdownMenuItem(
                            text = {
                                Column {
                                    Text(key.userId, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    Text(
                                        stringResource(R.string.key_type_format, key.algorithm, key.keySize),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            },
                            onClick = {
                                onUpdateParams(params.copy(selectedKeyId = key.keyId))
                                showKeyDropdown = false
                            }
                        )
                    }
                }
            }

            PasswordField(
                value = params.passphrase,
                onValueChange = { onUpdateParams(params.copy(passphrase = it)) },
                label = stringResource(R.string.passphrase)
            )

            Text(
                text = stringResource(R.string.encrypted_message),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(top = 8.dp)
            )

            MonospaceTextField(
                value = params.input,
                onValueChange = { onUpdateParams(params.copy(input = it)) },
                label = stringResource(R.string.encrypted_ascii_armored),
                minLines = 8
            )

            GPGButton(
                text = stringResource(R.string.action_decrypt),
                onClick = onDecrypt,
                modifier = Modifier.fillMaxWidth(),
                icon = Icons.Default.LockOpen,
                isLoading = isLoading,
                enabled = params.input.isNotBlank() &&
                        params.selectedKeyId != null &&
                        params.passphrase.isNotBlank()
            )

            if (decryptedResult.isNotEmpty()) {
                Text(
                    text = stringResource(R.string.decrypted_result),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(top = 8.dp)
                )

                MonospaceTextField(
                    value = decryptedResult,
                    onValueChange = {},
                    label = stringResource(R.string.plain_text),
                    readOnly = true,
                    minLines = 6
                )
            }
        }
    }
}
