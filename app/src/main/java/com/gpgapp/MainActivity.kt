package com.gpgapp

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.gpgapp.intent.OpenedFiles
import com.gpgapp.intent.OpenedDocumentEffect
import com.gpgapp.model.KeyInfo
import com.gpgapp.model.SnackbarEvent
import com.gpgapp.navigation.IncomingFileTarget
import com.gpgapp.navigation.Screen
import com.gpgapp.ui.screens.DecryptScreen
import com.gpgapp.ui.screens.EncryptScreen
import com.gpgapp.ui.screens.GenerateKeyScreen
import com.gpgapp.ui.screens.HomeScreen
import com.gpgapp.ui.screens.KeyDetailScreen
import com.gpgapp.ui.screens.KeyListScreen
import com.gpgapp.ui.screens.SignScreen
import com.gpgapp.ui.screens.VerifyScreen
import com.gpgapp.ui.theme.GPGAppTheme
import com.gpgapp.viewmodel.MainViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    /**
     * URI of the file this activity was asked to open, or null once it has been handled.
     *
     * Only a genuine first start consumes the launch intent. After process recreation the
     * intent is the one that was already handled, and re-reading it would reopen a dialog the
     * user had since closed.
     */
    private val incomingUri = mutableStateOf<Uri?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Keep key material, passphrases and decrypted text out of screenshots, screen
        // recordings and the recents thumbnail.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        if (savedInstanceState == null) {
            incomingUri.value = intent?.data
        }

        setContent {
            GPGAppTheme {
                val uri by incomingUri
                GPGApp(
                    openUri = uri,
                    onOpenHandled = { incomingUri.value = null }
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // singleTop delivery: the ViewModel survives, so the file is routed into the running
        // app rather than the app starting over.
        setIntent(intent)
        incomingUri.value = intent.data
    }
}

@Composable
fun GPGApp(
    openUri: Uri? = null,
    onOpenHandled: () -> Unit = {}
) {
    val viewModel: MainViewModel = viewModel()
    val navController = rememberNavController()
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    val operationState by viewModel.operationState.collectAsState()
    val publicKeys by viewModel.publicKeys.collectAsState()
    val secretKeys by viewModel.secretKeys.collectAsState()
    val generateParams by viewModel.generateParams.collectAsState()
    val encryptParams by viewModel.encryptParams.collectAsState()
    val decryptParams by viewModel.decryptParams.collectAsState()
    val signParams by viewModel.signParams.collectAsState()
    val verifyParams by viewModel.verifyParams.collectAsState()
    val encryptedResult by viewModel.encryptedResult.collectAsState()
    val decryptedResult by viewModel.decryptedResult.collectAsState()
    val signedResult by viewModel.signedResult.collectAsState()
    val verifyResult by viewModel.verifyResult.collectAsState()
    val exportedKey by viewModel.exportedKey.collectAsState()
    val pendingImport by viewModel.pendingImport.collectAsState()

    LaunchedEffect(Unit) {
        viewModel.snackbarEvent.collectLatest { event ->
            when (event) {
                is SnackbarEvent.Show -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    // A file the app was asked to open (issue #3). The URI grant only lasts while this intent
    // is alive, so the bytes are read first and dispatched from them; the extension is never
    // trusted, because `.asc` is used for keys, ciphertext and signatures alike.
    OpenedDocumentEffect(
        uri = openUri,
        onOpened = { picked ->
            onOpenHandled()
            when (viewModel.openIncomingFile(picked.name, picked.data)) {
                IncomingFileTarget.Keys -> navController.navigate(Screen.KeyList.route) {
                    launchSingleTop = true
                }
                IncomingFileTarget.Decrypt -> navController.navigate(Screen.Decrypt.route) {
                    launchSingleTop = true
                }
                null -> Unit
            }
        },
        onFailed = {
            onOpenHandled()
            scope.launch {
                snackbarHostState.showSnackbar(context.getString(R.string.error_file_unreadable))
            }
        }
    )

    // Key exports are encrypted material, so they are written through a file dialog rather
    // than a clipboard that other apps can read (issue #2). The destination is chosen by the
    // picker, so the pending export is captured when the dialog is launched, keyed by name,
    // instead of being re-read from state that may have changed since.
    var pendingExport by remember { mutableStateOf<Pair<String, String>?>(null) }

    val saveKeyLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("*/*")
    ) { target ->
        val (name, armored) = pendingExport ?: return@rememberLauncherForActivityResult
        pendingExport = null
        if (target == null) return@rememberLauncherForActivityResult
        scope.launch {
            val saved = withContext(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.openOutputStream(target)?.use { out ->
                        out.write(armored.toByteArray())
                    } ?: error("no stream")
                }.isSuccess
            }
            snackbarHostState.showSnackbar(
                context.getString(
                    if (saved) R.string.key_saved_success else R.string.error_failed_save_key,
                    name
                )
            )
        }
    }

    val saveKey: (KeyInfo) -> Unit = { keyInfo ->
        scope.launch {
            val armored = runCatching {
                viewModel.exportForSave(keyInfo.keyId, includePrivate = keyInfo.isPrivateKey)
            }.getOrNull()
            if (armored.isNullOrEmpty()) {
                snackbarHostState.showSnackbar(context.getString(R.string.error_failed_save_key, keyInfo.userId))
                return@launch
            }
            pendingExport = keyInfo.userId to armored
            saveKeyLauncher.launch(
                OpenedFiles.suggestedKeyFileName(keyInfo.userId, isPrivate = keyInfo.isPrivateKey)
            )
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
                    onNavigateToSign = {
                        navController.navigate(Screen.Sign.route)
                    },
                    onNavigateToVerify = {
                        navController.navigate(Screen.Verify.route)
                    },
                    publicKeyCount = publicKeys.size,
                    privateKeyCount = secretKeys.size
                )
            }

            composable(Screen.KeyList.route) {
                KeyListScreen(
                    publicKeys = publicKeys,
                    secretKeys = secretKeys,
                    pendingImport = pendingImport,
                    onKeyClick = { keyInfo ->
                        navController.navigate(Screen.KeyDetail.createRoute(keyInfo.keyId))
                    },
                    onDeleteKey = { keyId -> viewModel.deleteKey(keyId) },
                    onExportPublic = { keyId -> viewModel.exportPublicKey(keyId) },
                    onExportPrivate = { keyId -> viewModel.exportPrivateKey(keyId) },
                    onImportKey = { armored -> viewModel.importKey(armored) },
                    onFileSelected = { name, bytes -> viewModel.requestKeyImport(name, bytes) },
                    onConfirmImport = { viewModel.confirmPendingImport() },
                    onCancelImport = { viewModel.cancelPendingImport() },
                    onSaveKey = saveKey,
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
                        exportedKey = exportedKey,
                        onExport = {
                            if (keyInfo.isPrivateKey) {
                                viewModel.exportPrivateKey(keyId)
                            } else {
                                viewModel.exportPublicKey(keyId)
                            }
                        },
                        onSaveExport = { saveKey(keyInfo) },
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

            composable(Screen.Sign.route) {
                SignScreen(
                    params = signParams,
                    secretKeys = secretKeys,
                    signedResult = signedResult,
                    operationState = operationState,
                    onUpdateParams = { viewModel.updateSignParams(it) },
                    onSign = { viewModel.sign() },
                    onBack = { navController.popBackStack() }
                )
            }

            composable(Screen.Verify.route) {
                VerifyScreen(
                    params = verifyParams,
                    publicKeys = publicKeys,
                    verifyResult = verifyResult,
                    operationState = operationState,
                    onUpdateParams = { viewModel.updateVerifyParams(it) },
                    onVerify = { viewModel.verify() },
                    onBack = { navController.popBackStack() }
                )
            }
        }
    }
}
