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

data class SignParams(
    val input: String = "",
    val selectedKeyId: Long? = null,
    val passphrase: String = ""
)

data class VerifyParams(
    val input: String = "",
    val selectedKeyId: Long? = null
)

/** Outcome of verifying a signed message. */
sealed class VerificationResult {
    data object Valid : VerificationResult()
    data object Invalid : VerificationResult()
    data class Failed(val message: String) : VerificationResult()
}

sealed class SnackbarEvent {
    data class Show(val message: String) : SnackbarEvent()
}

/**
 * Key material read from a file and awaiting the user's confirmation.
 *
 * [name] is the file's display name, used only to frame the confirmation dialog. The bytes
 * are parsed once, when the import is confirmed, so a file that turns out not to be a key is
 * reported by that one import attempt.
 */
data class PendingImport(
    val name: String?,
    val data: ByteArray
) {
    // ByteArray needs identity-aware equality for the state flow to behave as a value object.
    override fun equals(other: Any?): Boolean =
        this === other || (other is PendingImport && name == other.name && data.contentEquals(other.data))

    override fun hashCode(): Int = name.hashCode() * 31 + data.contentHashCode()
}
