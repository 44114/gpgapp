package com.gpgapp.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.gpgapp.R
import com.gpgapp.model.DecryptionParams
import com.gpgapp.model.EncryptionParams
import com.gpgapp.model.KeyGenerationParams
import com.gpgapp.model.KeyInfo
import com.gpgapp.model.OperationState
import com.gpgapp.model.SignParams
import com.gpgapp.model.SnackbarEvent
import com.gpgapp.model.VerificationResult
import com.gpgapp.model.VerifyParams
import com.gpgapp.service.PGPIntegrityException
import com.gpgapp.service.PGPManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val pgpManager = PGPManager(
        keysDir = File(application.filesDir, PGPManager.KEYS_DIR),
        unknownUserId = application.getString(R.string.unknown)
    )

    private val _publicKeys = MutableStateFlow<List<KeyInfo>>(emptyList())
    val publicKeys: StateFlow<List<KeyInfo>> = _publicKeys.asStateFlow()

    private val _secretKeys = MutableStateFlow<List<KeyInfo>>(emptyList())
    val secretKeys: StateFlow<List<KeyInfo>> = _secretKeys.asStateFlow()

    private val _operationState = MutableStateFlow<OperationState>(OperationState.Idle)
    val operationState: StateFlow<OperationState> = _operationState.asStateFlow()

    private val _snackbarEvent = MutableSharedFlow<SnackbarEvent>()
    val snackbarEvent: SharedFlow<SnackbarEvent> = _snackbarEvent.asSharedFlow()

    private val _generateParams = MutableStateFlow(KeyGenerationParams())
    val generateParams: StateFlow<KeyGenerationParams> = _generateParams.asStateFlow()

    private val _encryptParams = MutableStateFlow(EncryptionParams())
    val encryptParams: StateFlow<EncryptionParams> = _encryptParams.asStateFlow()

    private val _decryptParams = MutableStateFlow(DecryptionParams())
    val decryptParams: StateFlow<DecryptionParams> = _decryptParams.asStateFlow()

    private val _signParams = MutableStateFlow(SignParams())
    val signParams: StateFlow<SignParams> = _signParams.asStateFlow()

    private val _verifyParams = MutableStateFlow(VerifyParams())
    val verifyParams: StateFlow<VerifyParams> = _verifyParams.asStateFlow()

    private val _encryptedResult = MutableStateFlow("")
    val encryptedResult: StateFlow<String> = _encryptedResult.asStateFlow()

    private val _decryptedResult = MutableStateFlow("")
    val decryptedResult: StateFlow<String> = _decryptedResult.asStateFlow()

    private val _signedResult = MutableStateFlow("")
    val signedResult: StateFlow<String> = _signedResult.asStateFlow()

    private val _verifyResult = MutableStateFlow<VerificationResult?>(null)
    val verifyResult: StateFlow<VerificationResult?> = _verifyResult.asStateFlow()

    /**
     * Armored key produced by the most recent export. Kept apart from the encrypt result so
     * exporting a key cannot overwrite a ciphertext the user is still looking at.
     */
    private val _exportedKey = MutableStateFlow("")
    val exportedKey: StateFlow<String> = _exportedKey.asStateFlow()

    init {
        loadKeys()
    }

    fun loadKeys() {
        viewModelScope.launch {
            _operationState.value = OperationState.Loading
            try {
                val public = withContext(Dispatchers.IO) { pgpManager.loadKeys() }
                val secret = withContext(Dispatchers.IO) { pgpManager.loadSecretKeys() }
                _publicKeys.value = public
                _secretKeys.value = secret
                _operationState.value = OperationState.Idle
            } catch (e: Exception) {
                _operationState.value = OperationState.Error(e.message ?: getString(R.string.error_failed_load_keys))
            }
        }
    }

    private fun getString(id: Int): String = getApplication<Application>().getString(id)

    private suspend fun reportError(message: String) {
        _operationState.value = OperationState.Error(message)
        _snackbarEvent.emit(SnackbarEvent.Show(message))
    }

    private suspend fun reportSuccess(state: OperationState.Success, message: String) {
        _operationState.value = state
        _snackbarEvent.emit(SnackbarEvent.Show(message))
    }

    fun updateGenerateParams(params: KeyGenerationParams) {
        _generateParams.value = params
    }

    fun generateKey() {
        val params = _generateParams.value
        if (params.userId.isBlank()) {
            _operationState.value = OperationState.Error(getString(R.string.error_user_id_required))
            return
        }
        if (params.passphrase.isBlank()) {
            _operationState.value = OperationState.Error(getString(R.string.error_passphrase_required))
            return
        }
        if (params.passphrase != params.confirmPassphrase) {
            _operationState.value = OperationState.Error(getString(R.string.error_passphrases_mismatch))
            return
        }

        viewModelScope.launch {
            _operationState.value = OperationState.Loading
            try {
                withContext(Dispatchers.IO) {
                    pgpManager.generateKeyRing(
                        userId = params.userId,
                        passphrase = params.passphrase,
                        keyAlgorithm = params.keyAlgorithm,
                        keySize = params.keySize
                    )
                }
                loadKeys()
                _generateParams.value = KeyGenerationParams()
                reportSuccess(
                    OperationState.Success(getString(R.string.key_generated_success)),
                    getString(R.string.key_generated_success)
                )
            } catch (e: Exception) {
                reportError(e.message ?: getString(R.string.error_failed_generate_key))
            }
        }
    }

    fun deleteKey(keyId: Long) {
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { pgpManager.deleteKey(keyId) }
                _exportedKey.value = ""
                loadKeys()
                _snackbarEvent.emit(SnackbarEvent.Show(getString(R.string.key_deleted)))
            } catch (e: Exception) {
                _snackbarEvent.emit(SnackbarEvent.Show(e.message ?: getString(R.string.error_failed_delete_key)))
            }
        }
    }

    fun exportPublicKey(keyId: Long) {
        viewModelScope.launch {
            try {
                val armored = withContext(Dispatchers.IO) { pgpManager.exportPublicKey(keyId) }
                _exportedKey.value = armored
                _snackbarEvent.emit(SnackbarEvent.Show(getString(R.string.public_key_exported)))
            } catch (e: Exception) {
                _snackbarEvent.emit(SnackbarEvent.Show(e.message ?: getString(R.string.error_failed_export_key)))
            }
        }
    }

    fun exportPrivateKey(keyId: Long) {
        viewModelScope.launch {
            try {
                val armored = withContext(Dispatchers.IO) { pgpManager.exportPrivateKey(keyId) }
                _exportedKey.value = armored
                _snackbarEvent.emit(SnackbarEvent.Show(getString(R.string.private_key_exported)))
            } catch (e: Exception) {
                _snackbarEvent.emit(SnackbarEvent.Show(e.message ?: getString(R.string.error_failed_export_key)))
            }
        }
    }

    fun importKey(armoredKey: String) {
        viewModelScope.launch {
            _operationState.value = OperationState.Loading
            try {
                withContext(Dispatchers.IO) { pgpManager.importKey(armoredKey) }
                loadKeys()
                reportSuccess(
                    OperationState.Success(getString(R.string.key_imported_success)),
                    getString(R.string.key_imported_success)
                )
            } catch (e: Exception) {
                reportError(e.message ?: getString(R.string.error_failed_import_key))
            }
        }
    }

    fun updateEncryptParams(params: EncryptionParams) {
        _encryptParams.value = params
    }

    fun encrypt() {
        val params = _encryptParams.value
        if (params.input.isBlank()) {
            _operationState.value = OperationState.Error(getString(R.string.error_input_text_required))
            return
        }
        if (params.selectedKeyId == null) {
            _operationState.value = OperationState.Error(getString(R.string.error_select_public_key))
            return
        }

        viewModelScope.launch {
            _operationState.value = OperationState.Loading
            _encryptedResult.value = ""
            try {
                val result = withContext(Dispatchers.IO) {
                    pgpManager.encrypt(
                        data = params.input.toByteArray(),
                        keyId = params.selectedKeyId
                    )
                }
                _encryptedResult.value = String(result)
                reportSuccess(
                    OperationState.Success(getString(R.string.encrypted_success)),
                    getString(R.string.text_encrypted_success)
                )
            } catch (e: Exception) {
                reportError(e.message ?: getString(R.string.error_encryption_failed))
            }
        }
    }

    fun updateDecryptParams(params: DecryptionParams) {
        _decryptParams.value = params
    }

    fun decrypt() {
        val params = _decryptParams.value
        if (params.input.isBlank()) {
            _operationState.value = OperationState.Error(getString(R.string.error_input_text_required))
            return
        }
        if (params.selectedKeyId == null) {
            _operationState.value = OperationState.Error(getString(R.string.error_select_private_key))
            return
        }
        if (params.passphrase.isBlank()) {
            _operationState.value = OperationState.Error(getString(R.string.error_passphrase_required))
            return
        }

        viewModelScope.launch {
            _operationState.value = OperationState.Loading
            _decryptedResult.value = ""
            try {
                val result = withContext(Dispatchers.IO) {
                    pgpManager.decrypt(
                        encryptedData = params.input.trim().toByteArray(),
                        keyId = params.selectedKeyId,
                        passphrase = params.passphrase
                    )
                }
                _decryptedResult.value = String(result)
                reportSuccess(
                    OperationState.Success(getString(R.string.decrypted_success)),
                    getString(R.string.text_decrypted_success)
                )
            } catch (e: PGPIntegrityException) {
                // Never show plaintext that failed its integrity check.
                reportError(getString(R.string.error_integrity_check_failed))
            } catch (e: Exception) {
                reportError(e.message ?: getString(R.string.error_decryption_failed))
            }
        }
    }

    fun updateSignParams(params: SignParams) {
        _signParams.value = params
    }

    fun sign() {
        val params = _signParams.value
        if (params.input.isBlank()) {
            _operationState.value = OperationState.Error(getString(R.string.error_input_text_required))
            return
        }
        if (params.selectedKeyId == null) {
            _operationState.value = OperationState.Error(getString(R.string.error_select_private_key))
            return
        }
        if (params.passphrase.isBlank()) {
            _operationState.value = OperationState.Error(getString(R.string.error_passphrase_required))
            return
        }

        viewModelScope.launch {
            _operationState.value = OperationState.Loading
            _signedResult.value = ""
            try {
                val result = withContext(Dispatchers.IO) {
                    pgpManager.sign(
                        data = params.input.toByteArray(),
                        keyId = params.selectedKeyId,
                        passphrase = params.passphrase
                    )
                }
                _signedResult.value = String(result)
                reportSuccess(
                    OperationState.Success(getString(R.string.signed_success)),
                    getString(R.string.data_signed_success)
                )
            } catch (e: Exception) {
                reportError(e.message ?: getString(R.string.error_signing_failed))
            }
        }
    }

    fun updateVerifyParams(params: VerifyParams) {
        _verifyParams.value = params
        _verifyResult.value = null
    }

    fun verify() {
        val params = _verifyParams.value
        if (params.input.isBlank()) {
            _operationState.value = OperationState.Error(getString(R.string.error_input_text_required))
            return
        }
        if (params.selectedKeyId == null) {
            _operationState.value = OperationState.Error(getString(R.string.error_select_public_key))
            return
        }

        viewModelScope.launch {
            _operationState.value = OperationState.Loading
            _verifyResult.value = null
            try {
                val valid = withContext(Dispatchers.IO) {
                    pgpManager.verify(
                        data = params.input.trim().toByteArray(),
                        keyId = params.selectedKeyId
                    )
                }
                if (valid) {
                    _verifyResult.value = VerificationResult.Valid
                    reportSuccess(
                        OperationState.Success(getString(R.string.signature_valid)),
                        getString(R.string.signature_valid)
                    )
                } else {
                    _verifyResult.value = VerificationResult.Invalid
                    reportError(getString(R.string.signature_invalid))
                }
            } catch (e: Exception) {
                val message = e.message ?: getString(R.string.error_verification_failed)
                _verifyResult.value = VerificationResult.Failed(message)
                reportError(message)
            }
        }
    }

    fun clearResults() {
        _encryptedResult.value = ""
        _decryptedResult.value = ""
        _signedResult.value = ""
        _verifyResult.value = null
        _exportedKey.value = ""
    }

    fun clearOperationState() {
        _operationState.value = OperationState.Idle
    }
}
