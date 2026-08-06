package com.gpgapp.model

data class KeyInfo(
    val keyId: Long,
    val keyIdHex: String,
    val userId: String,
    val algorithm: String,
    val keySize: Int,
    val creationDate: Long,
    val isPrivateKey: Boolean,
    val fingerprint: String
)

sealed class OperationState {
    data object Idle : OperationState()
    data object Loading : OperationState()
    data class Success(val message: String) : OperationState()
    data class Error(val message: String) : OperationState()
}

data class KeyGenerationParams(
    val userId: String = "",
    val passphrase: String = "",
    val confirmPassphrase: String = "",
    val keyAlgorithm: String = "Ed25519",
    val keySize: Int = 4096
)

data class EncryptionParams(
    val input: String = "",
    val selectedKeyId: Long? = null
)

data class DecryptionParams(
    val input: String = "",
    val selectedKeyId: Long? = null,
    val passphrase: String = ""
)

sealed class SnackbarEvent {
    data class Show(val message: String) : SnackbarEvent()
}
