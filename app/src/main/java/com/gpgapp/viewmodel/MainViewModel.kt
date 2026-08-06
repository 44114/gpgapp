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
import com.gpgapp.model.SnackbarEvent
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

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val pgpManager = PGPManager(application)

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

    private val _encryptedResult = MutableStateFlow("")
    val encryptedResult: StateFlow<String> = _encryptedResult.asStateFlow()

    private val _decryptedResult = MutableStateFlow("")
    val decryptedResult: StateFlow<String> = _decryptedResult.asStateFlow()

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
                _operationState.value = OperationState.Success(getString(R.string.key_generated_success))
                _snackbarEvent.emit(SnackbarEvent.Show(getString(R.string.key_generated_success)))
                _generateParams.value = KeyGenerationParams()
            } catch (e: Exception) {
                _operationState.value = OperationState.Error(e.message ?: getString(R.string.error_failed_generate_key))
                _snackbarEvent.emit(SnackbarEvent.Show(e.message ?: getString(R.string.error_failed_generate_key)))
            }
        }
    }

    fun deleteKey(keyId: Long) {
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { pgpManager.deleteKey(keyId) }
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
                _encryptedResult.value = armored
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
                _encryptedResult.value = armored
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
                _operationState.value = OperationState.Success(getString(R.string.key_imported_success))
                _snackbarEvent.emit(SnackbarEvent.Show(getString(R.string.key_imported_success)))
            } catch (e: Exception) {
                _operationState.value = OperationState.Error(e.message ?: getString(R.string.error_failed_import_key))
                _snackbarEvent.emit(SnackbarEvent.Show(e.message ?: getString(R.string.error_failed_import_key)))
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
            try {
                val result = withContext(Dispatchers.IO) {
                    pgpManager.encrypt(
                        data = params.input.toByteArray(),
                        keyId = params.selectedKeyId
                    )
                }
                _encryptedResult.value = String(result)
                _operationState.value = OperationState.Success(getString(R.string.encrypted_success))
                _snackbarEvent.emit(SnackbarEvent.Show(getString(R.string.text_encrypted_success)))
            } catch (e: Exception) {
                _operationState.value = OperationState.Error(e.message ?: getString(R.string.error_encryption_failed))
                _snackbarEvent.emit(SnackbarEvent.Show(e.message ?: getString(R.string.error_encryption_failed)))
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
            try {
                val result = withContext(Dispatchers.IO) {
                    pgpManager.decrypt(
                        encryptedData = params.input.toByteArray(),
                        keyId = params.selectedKeyId,
                        passphrase = params.passphrase
                    )
                }
                _decryptedResult.value = String(result)
                _operationState.value = OperationState.Success(getString(R.string.decrypted_success))
                _snackbarEvent.emit(SnackbarEvent.Show(getString(R.string.text_decrypted_success)))
            } catch (e: Exception) {
                _operationState.value = OperationState.Error(e.message ?: getString(R.string.error_decryption_failed))
                _snackbarEvent.emit(SnackbarEvent.Show(e.message ?: getString(R.string.error_decryption_failed)))
            }
        }
    }

    fun sign(keyId: Long, passphrase: String, data: String) {
        viewModelScope.launch {
            _operationState.value = OperationState.Loading
            try {
                val result = withContext(Dispatchers.IO) {
                    pgpManager.sign(
                        data = data.toByteArray(),
                        keyId = keyId,
                        passphrase = passphrase
                    )
                }
                _encryptedResult.value = String(result)
                _operationState.value = OperationState.Success(getString(R.string.signed_success))
                _snackbarEvent.emit(SnackbarEvent.Show(getString(R.string.data_signed_success)))
            } catch (e: Exception) {
                _operationState.value = OperationState.Error(e.message ?: getString(R.string.error_signing_failed))
                _snackbarEvent.emit(SnackbarEvent.Show(e.message ?: getString(R.string.error_signing_failed)))
            }
        }
    }

    fun clearResults() {
        _encryptedResult.value = ""
        _decryptedResult.value = ""
    }

    fun clearOperationState() {
        _operationState.value = OperationState.Idle
    }
}
