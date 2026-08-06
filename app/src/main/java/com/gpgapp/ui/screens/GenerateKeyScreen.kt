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
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.gpgapp.R
import com.gpgapp.model.KeyGenerationParams
import com.gpgapp.model.OperationState
import com.gpgapp.ui.components.GPGButton
import com.gpgapp.ui.components.GPGTextField
import com.gpgapp.ui.components.PasswordField

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GenerateKeyScreen(
    params: KeyGenerationParams,
    operationState: OperationState,
    onUpdateParams: (KeyGenerationParams) -> Unit,
    onGenerate: () -> Unit,
    onBack: () -> Unit
) {
    val keyAlgorithms = listOf("Ed25519", "RSA")
    val keySizes = listOf(2048, 3072, 4096)
    val isLoading = operationState is OperationState.Loading

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.generate_key_pair)) },
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
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Default.Info,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = stringResource(R.string.key_information),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    Spacer(Modifier.height(12.dp))
                    Text(
                        text = stringResource(R.string.key_information_description),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            GPGTextField(
                value = params.userId,
                onValueChange = { onUpdateParams(params.copy(userId = it)) },
                label = stringResource(R.string.user_id),
                placeholder = stringResource(R.string.user_id_placeholder),
                trailingIcon = Icons.Default.Person,
                onTrailingIconClick = null
            )

            PasswordField(
                value = params.passphrase,
                onValueChange = { onUpdateParams(params.copy(passphrase = it)) },
                label = stringResource(R.string.passphrase)
            )

            PasswordField(
                value = params.confirmPassphrase,
                onValueChange = { onUpdateParams(params.copy(confirmPassphrase = it)) },
                label = stringResource(R.string.confirm_passphrase)
            )

            Text(
                text = stringResource(R.string.key_algorithm),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(top = 8.dp)
            )

            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                keyAlgorithms.forEachIndexed { index, algorithm ->
                    SegmentedButton(
                        shape = SegmentedButtonDefaults.itemShape(
                            index = index,
                            count = keyAlgorithms.size
                        ),
                        onClick = { onUpdateParams(params.copy(keyAlgorithm = algorithm)) },
                        selected = params.keyAlgorithm == algorithm,
                        label = { Text(algorithm) }
                    )
                }
            }

            if (params.keyAlgorithm == "RSA") {
                Text(
                    text = stringResource(R.string.key_strength),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(top = 8.dp)
                )

                SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                    keySizes.forEachIndexed { index, size ->
                        SegmentedButton(
                            shape = SegmentedButtonDefaults.itemShape(
                                index = index,
                                count = keySizes.size
                            ),
                            onClick = { onUpdateParams(params.copy(keySize = size)) },
                            selected = params.keySize == size,
                            label = { Text("$size") }
                        )
                    }
                }
            } else {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer
                    )
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Lock,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSecondaryContainer,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = stringResource(R.string.ed25519_info),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSecondaryContainer
                        )
                    }
                }
            }

            Spacer(Modifier.height(8.dp))

            GPGButton(
                text = stringResource(R.string.generate_key_pair),
                onClick = onGenerate,
                modifier = Modifier.fillMaxWidth(),
                icon = Icons.Default.Fingerprint,
                isLoading = isLoading
            )

            Spacer(Modifier.height(32.dp))
        }
    }
}
