package com.gpgapp.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.gpgapp.R
import com.gpgapp.model.KeyInfo
import com.gpgapp.model.OperationState
import com.gpgapp.model.VerificationResult
import com.gpgapp.model.VerifyParams
import com.gpgapp.ui.components.GPGButton
import com.gpgapp.ui.components.MonospaceTextField

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerifyScreen(
    params: VerifyParams,
    publicKeys: List<KeyInfo>,
    verifyResult: VerificationResult?,
    operationState: OperationState,
    onUpdateParams: (VerifyParams) -> Unit,
    onVerify: () -> Unit,
    onBack: () -> Unit
) {
    var showKeyDropdown by remember { mutableStateOf(false) }
    val selectedKey = publicKeys.find { it.keyId == params.selectedKeyId }
    val isLoading = operationState is OperationState.Loading

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.verify_signature)) },
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
                text = stringResource(R.string.select_public_key),
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
                        Icons.Default.VpnKey,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = selectedKey?.userId ?: stringResource(R.string.select_a_public_key),
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
                    publicKeys.forEach { key ->
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

            Text(
                text = stringResource(R.string.message_to_verify),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(top = 8.dp)
            )

            MonospaceTextField(
                value = params.input,
                onValueChange = { onUpdateParams(params.copy(input = it)) },
                label = stringResource(R.string.signed_ascii_armored),
                minLines = 8
            )

            GPGButton(
                text = stringResource(R.string.action_verify),
                onClick = onVerify,
                modifier = Modifier.fillMaxWidth(),
                icon = Icons.Default.VerifiedUser,
                isLoading = isLoading,
                enabled = params.input.isNotBlank() && params.selectedKeyId != null
            )

            when (verifyResult) {
                is VerificationResult.Valid -> VerificationBanner(
                    icon = Icons.Default.CheckCircle,
                    text = stringResource(R.string.signature_valid),
                    color = Color(0xFF4CAF50)
                )
                is VerificationResult.Invalid -> VerificationBanner(
                    icon = Icons.Default.Error,
                    text = stringResource(R.string.signature_invalid),
                    color = MaterialTheme.colorScheme.error
                )
                is VerificationResult.Failed -> VerificationBanner(
                    icon = Icons.Default.Error,
                    text = verifyResult.message,
                    color = MaterialTheme.colorScheme.error
                )
                null -> Unit
            }
        }
    }
}

@Composable
private fun VerificationBanner(
    icon: ImageVector,
    text: String,
    color: Color
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.12f)),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(24.dp)
            )
            Spacer(Modifier.width(12.dp))
            Text(
                text = text,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = color
            )
        }
    }
}
