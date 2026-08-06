package com.gpgapp

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.gpgapp.model.SnackbarEvent
import com.gpgapp.navigation.Screen
import com.gpgapp.ui.screens.DecryptScreen
import com.gpgapp.ui.screens.EncryptScreen
import com.gpgapp.ui.screens.GenerateKeyScreen
import com.gpgapp.ui.screens.HomeScreen
import com.gpgapp.ui.screens.KeyDetailScreen
import com.gpgapp.ui.screens.KeyListScreen
import com.gpgapp.ui.theme.GPGAppTheme
import com.gpgapp.viewmodel.MainViewModel
import kotlinx.coroutines.flow.collectLatest

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            GPGAppTheme {
                GPGApp()
            }
        }
    }
}

@Composable
fun GPGApp() {
    val viewModel: MainViewModel = viewModel()
    val navController = rememberNavController()
    val snackbarHostState = remember { SnackbarHostState() }

    val operationState by viewModel.operationState.collectAsState()
    val publicKeys by viewModel.publicKeys.collectAsState()
    val secretKeys by viewModel.secretKeys.collectAsState()
    val generateParams by viewModel.generateParams.collectAsState()
    val encryptParams by viewModel.encryptParams.collectAsState()
    val decryptParams by viewModel.decryptParams.collectAsState()
    val encryptedResult by viewModel.encryptedResult.collectAsState()
    val decryptedResult by viewModel.decryptedResult.collectAsState()

    LaunchedEffect(Unit) {
        viewModel.snackbarEvent.collectLatest { event ->
            when (event) {
                is SnackbarEvent.Show -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Screen.Home.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Screen.Home.route) {
                HomeScreen(
                    onNavigateToGenerateKey = {
                        navController.navigate(Screen.GenerateKey.route)
                    },
                    onNavigateToKeyList = {
                        navController.navigate(Screen.KeyList.route)
                    },
                    onNavigateToEncrypt = {
                        navController.navigate(Screen.Encrypt.route)
                    },
                    onNavigateToDecrypt = {
                        navController.navigate(Screen.Decrypt.route)
                    },
                    publicKeyCount = publicKeys.size,
                    privateKeyCount = secretKeys.size
                )
            }

            composable(Screen.KeyList.route) {
                KeyListScreen(
                    publicKeys = publicKeys,
                    secretKeys = secretKeys,
                    onKeyClick = { keyInfo ->
                        navController.navigate(Screen.KeyDetail.createRoute(keyInfo.keyId))
                    },
                    onDeleteKey = { keyId -> viewModel.deleteKey(keyId) },
                    onExportPublic = { keyId -> viewModel.exportPublicKey(keyId) },
                    onExportPrivate = { keyId -> viewModel.exportPrivateKey(keyId) },
                    onImportKey = { armored -> viewModel.importKey(armored) },
                    onBack = { navController.popBackStack() }
                )
            }

            composable(
                route = Screen.KeyDetail.route,
                arguments = listOf(navArgument("keyId") { type = NavType.LongType })
            ) { backStackEntry ->
                val keyId = backStackEntry.arguments?.getLong("keyId") ?: return@composable
                val allKeys = publicKeys + secretKeys
                val keyInfo = allKeys.find { it.keyId == keyId }

                if (keyInfo != null) {
                    KeyDetailScreen(
                        keyInfo = keyInfo,
                        exportedKey = encryptedResult,
                        onExport = {
                            if (keyInfo.isPrivateKey) {
                                viewModel.exportPrivateKey(keyId)
                            } else {
                                viewModel.exportPublicKey(keyId)
                            }
                        },
                        onBack = { navController.popBackStack() }
                    )
                }
            }

            composable(Screen.GenerateKey.route) {
                GenerateKeyScreen(
                    params = generateParams,
                    operationState = operationState,
                    onUpdateParams = { viewModel.updateGenerateParams(it) },
                    onGenerate = { viewModel.generateKey() },
                    onBack = { navController.popBackStack() }
                )
            }

            composable(Screen.Encrypt.route) {
                EncryptScreen(
                    params = encryptParams,
                    publicKeys = publicKeys,
                    encryptedResult = encryptedResult,
                    operationState = operationState,
                    onUpdateParams = { viewModel.updateEncryptParams(it) },
                    onEncrypt = { viewModel.encrypt() },
                    onBack = { navController.popBackStack() }
                )
            }

            composable(Screen.Decrypt.route) {
                DecryptScreen(
                    params = decryptParams,
                    secretKeys = secretKeys,
                    decryptedResult = decryptedResult,
                    operationState = operationState,
                    onUpdateParams = { viewModel.updateDecryptParams(it) },
                    onDecrypt = { viewModel.decrypt() },
                    onBack = { navController.popBackStack() }
                )
            }
        }
    }
}
