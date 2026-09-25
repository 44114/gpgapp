package com.gpgapp.service

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import com.gpgapp.model.KeyInfo
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPCompressedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import java.util.Date

/**
 * Thrown when an encrypted message fails its OpenPGP integrity protection, or carries none.
 *
 * Callers should translate this into a user-facing message rather than surfacing [message]
 * directly, because it marks a security-relevant outcome rather than a structural error.
 */
class PGPIntegrityException(message: String) : PGPException(message)

/**
 * On-device OpenPGP key store and crypto engine.
 *
 * Deliberately free of Android dependencies so the exact code the app ships can be exercised
 * by host-side unit tests (see `app/src/test`).
 */
class PGPManager(
    private val keysDir: File,
    private val unknownUserId: String = "Unknown"
) {

    companion object {
        const val KEYS_DIR = "pgp_keys"

        private const val SECRET_KEY_FILE = "secret_keys.asc"
        private const val PUBLIC_KEY_FILE = "public_keys.asc"

        /** Buffer used for the streaming (partial-length) packet form. */
        private const val STREAM_BUFFER_SIZE = 1 shl 16

        init {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private val storeDir: File
        get() = keysDir.also { it.mkdirs() }

    private val secretKeyFile: File
        get() = File(storeDir, SECRET_KEY_FILE)

    private val publicKeyFile: File
        get() = File(storeDir, PUBLIC_KEY_FILE)

    // ---------------------------------------------------------------- reading keys

    fun loadKeys(): List<KeyInfo> {
        val keys = mutableListOf<KeyInfo>()
        val seen = mutableSetOf<Long>()

        try {
            loadPublicKeyRingList().forEach { ring ->
                val pubKey = ring.publicKey
                if (seen.add(pubKey.keyID)) keys.add(describe(pubKey, isPrivateKey = false))
            }
        } catch (_: Exception) {
        }

        // A secret key ring carries its own public half. Surface it as a public key too, so a
        // private key that was imported on its own can immediately be used as a recipient.
        // (GnuPG behaves the same way, and `gpg --export` of an imported secret key works.)
        try {
            loadSecretKeyRingList().forEach { ring ->
                val pubKey = ring.publicKey
                if (seen.add(pubKey.keyID)) keys.add(describe(pubKey, isPrivateKey = false))
            }
        } catch (_: Exception) {
        }

        return keys
    }

    fun loadSecretKeys(): List<KeyInfo> {
        val keys = mutableListOf<KeyInfo>()
        try {
            loadSecretKeyRingList().forEach { ring ->
                keys.add(describe(ring.secretKey.publicKey, isPrivateKey = true))
            }
        } catch (_: Exception) {
        }
        return keys
    }

    private fun describe(pubKey: PGPPublicKey, isPrivateKey: Boolean) = KeyInfo(
        keyId = pubKey.keyID,
        keyIdHex = getKeyIdHex(pubKey.keyID),
        userId = getPrimaryUserId(pubKey),
        algorithm = getAlgorithmName(pubKey.algorithm),
        keySize = getKeySize(pubKey),
        creationDate = pubKey.creationTime.time,
        isPrivateKey = isPrivateKey,
        fingerprint = formatFingerprint(pubKey.fingerprint)
    )

    // ---------------------------------------------------------------- generating keys

    fun generateKeyRing(
        userId: String,
        passphrase: String,
        keyAlgorithm: String = "RSA",
        keySize: Int = 4096
    ) {
        when (keyAlgorithm) {
            "Ed25519" -> generateEd25519KeyRing(userId, passphrase)
            else -> generateRSAKeyRing(userId, passphrase, keySize)
        }
    }

    private fun generateRSAKeyRing(userId: String, passphrase: String, keySize: Int) {
        val kpg = KeyPairGenerator.getInstance("RSA", "BC")
        kpg.initialize(keySize, SecureRandom())
        val masterKp = kpg.generateKeyPair()
        val subKp = kpg.generateKeyPair()

        val masterPgpKeyPair = JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, masterKp, Date())
        val subPgpKeyPair = JcaPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, subKp, Date())

        val keyRingGen = createKeyRingGenerator(
            userId = userId,
            passphrase = passphrase,
            masterPgpKeyPair = masterPgpKeyPair,
            signerBuilder = JcaPGPContentSignerBuilder(
                PGPPublicKey.RSA_GENERAL, HashAlgorithmTags.SHA512
            ).setProvider("BC").setSecureRandom(SecureRandom()),
            subPgpKeyPair = subPgpKeyPair,
            subKeyFlags = KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE
        )

        upsertSecretKeyRing(keyRingGen.generateSecretKeyRing())
        upsertPublicKeyRing(keyRingGen.generatePublicKeyRing())
    }

    private fun generateEd25519KeyRing(userId: String, passphrase: String) {
        val masterKpg = KeyPairGenerator.getInstance("Ed25519", "BC")
        val masterKp = masterKpg.generateKeyPair()

        val subKpg = KeyPairGenerator.getInstance("X25519", "BC")
        val subKp = subKpg.generateKeyPair()

        val masterPgpKeyPair = JcaPGPKeyPair(PGPPublicKey.EDDSA, masterKp, Date())
        val subPgpKeyPair = JcaPGPKeyPair(PGPPublicKey.ECDH, subKp, Date())

        val keyRingGen = createKeyRingGenerator(
            userId = userId,
            passphrase = passphrase,
            masterPgpKeyPair = masterPgpKeyPair,
            signerBuilder = JcaPGPContentSignerBuilder(
                PGPPublicKey.EDDSA, HashAlgorithmTags.SHA512
            ).setProvider("BC").setSecureRandom(SecureRandom()),
            subPgpKeyPair = subPgpKeyPair,
            subKeyFlags = KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE
        )

        upsertSecretKeyRing(keyRingGen.generateSecretKeyRing())
        upsertPublicKeyRing(keyRingGen.generatePublicKeyRing())
    }

    private fun createKeyRingGenerator(
        userId: String,
        passphrase: String,
        masterPgpKeyPair: PGPKeyPair,
        signerBuilder: JcaPGPContentSignerBuilder,
        subPgpKeyPair: PGPKeyPair,
        subKeyFlags: Int
    ): PGPKeyRingGenerator {
        val sha1Calc = JcaPGPDigestCalculatorProviderBuilder().build()[HashAlgorithmTags.SHA1]

        val keyEncryptor = JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
            .setProvider("BC")
            .setSecureRandom(SecureRandom())
            .build(passphrase.toCharArray())

        val keyRingGen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            masterPgpKeyPair,
            userId,
            sha1Calc,
            buildMasterHashedSubpackets(),
            PGPSignatureSubpacketGenerator().generate(),
            signerBuilder,
            keyEncryptor
        )

        keyRingGen.addSubKey(
            subPgpKeyPair,
            buildSubHashedSubpackets(subKeyFlags),
            PGPSignatureSubpacketGenerator().generate()
        )

        return keyRingGen
    }

    private fun buildMasterHashedSubpackets(): PGPSignatureSubpacketVector {
        return PGPSignatureSubpacketGenerator().apply {
            setPreferredSymmetricAlgorithms(
                false,
                intArrayOf(
                    SymmetricKeyAlgorithmTags.AES_256,
                    SymmetricKeyAlgorithmTags.AES_192,
                    SymmetricKeyAlgorithmTags.AES_128
                )
            )
            setPreferredHashAlgorithms(
                false,
                intArrayOf(
                    HashAlgorithmTags.SHA512,
                    HashAlgorithmTags.SHA384,
                    HashAlgorithmTags.SHA256
                )
            )
            setPreferredCompressionAlgorithms(
                false,
                intArrayOf(
                    CompressionAlgorithmTags.ZLIB,
                    CompressionAlgorithmTags.BZIP2,
                    CompressionAlgorithmTags.ZIP
                )
            )
            setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
        }.generate()
    }

    private fun buildSubHashedSubpackets(keyFlags: Int): PGPSignatureSubpacketVector {
        return PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, keyFlags)
        }.generate()
    }

    // ---------------------------------------------------------------- key management

    fun deleteKey(keyId: Long) {
        saveSecretKeyRings(loadSecretKeyRingList().filterNot { ringContainsKey(it, keyId) })
        savePublicKeyRings(loadPublicKeyRingList().filterNot { ringContainsKey(it, keyId) })
    }

    fun importKey(armoredKey: String) {
        val input = PGPUtil.getDecoderStream(ByteArrayInputStream(armoredKey.toByteArray()))
        val factory = JcaPGPObjectFactory(input)

        var obj = factory.nextObject()
        var imported = false

        while (obj != null) {
            when (obj) {
                is PGPSecretKeyRing -> {
                    upsertSecretKeyRing(obj)
                    // Keep the public half as well, otherwise the imported private key could
                    // never be selected as an encryption recipient.
                    upsertPublicKeyRing(toPublicKeyRing(obj))
                    imported = true
                }
                is PGPPublicKeyRing -> {
                    upsertPublicKeyRing(obj)
                    imported = true
                }
            }
            obj = factory.nextObject()
        }

        if (!imported) {
            throw PGPException("No valid PGP key found in the input")
        }
    }

    fun exportPublicKey(keyId: Long): String {
        val ring = findPublicKeyRing(keyId)
            ?: throw PGPException("Public key not found")
        return armor { ring.encode(it) }
    }

    fun exportPrivateKey(keyId: Long): String {
        val ring = findSecretKeyRing(keyId)
            ?: throw PGPException("Private key not found")
        return armor { ring.encode(it) }
    }

    private inline fun armor(encode: (ArmoredOutputStream) -> Unit): String {
        val out = ByteArrayOutputStream()
        val armoredOut = ArmoredOutputStream(out)
        encode(armoredOut)
        armoredOut.close()
        return String(out.toByteArray())
    }

    // ---------------------------------------------------------------- encryption

    fun encrypt(data: ByteArray, keyId: Long): ByteArray {
        val ring = findPublicKeyRing(keyId)
            ?: throw PGPException("Public key not found for key ID ${getKeyIdHex(keyId)}")
        return encrypt(data, ring)
    }

    fun encrypt(data: ByteArray, publicKeyRing: PGPPublicKeyRing): ByteArray {
        return encryptTo(data, selectEncryptionKey(publicKeyRing))
    }

    fun encryptTo(data: ByteArray, encryptionKey: PGPPublicKey): ByteArray {
        val out = ByteArrayOutputStream()
        val armoredOut = ArmoredOutputStream(out)

        val encryptor = JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
            .setWithIntegrityPacket(true)
            .setSecureRandom(SecureRandom())
            .setProvider("BC")

        val encGen = PGPEncryptedDataGenerator(encryptor)
        encGen.addMethod(JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BC"))

        // Must use the streaming form. Passing a plain byte count here declares one encrypted
        // packet of at least that size regardless of the real message length, which produces
        // malformed framing (GnuPG: "decryption failed: Invalid packet") and can trigger
        // premature end-of-stream handling on the receiving side.
        val encryptedOut = encGen.open(armoredOut, ByteArray(STREAM_BUFFER_SIZE))

        val compGen = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZLIB)
        val compressedOut = compGen.open(encryptedOut)

        val literalGen = PGPLiteralDataGenerator()
        val literalOut = literalGen.open(
            compressedOut,
            PGPLiteralData.BINARY,
            "_CONSOLE",
            data.size.toLong(),
            Date()
        )

        literalOut.write(data)
        literalOut.close()
        compressedOut.close()
        encryptedOut.close()
        armoredOut.close()

        return out.toByteArray()
    }

    fun decrypt(encryptedData: ByteArray, keyId: Long, passphrase: String): ByteArray {
        val secretRing = findSecretKeyRing(keyId)
            ?: throw PGPException("Secret key not found for key ID ${getKeyIdHex(keyId)}")

        val factory = JcaPGPObjectFactory(
            PGPUtil.getDecoderStream(ByteArrayInputStream(encryptedData))
        )

        val encryptedDataList = factory.nextObject() as? PGPEncryptedDataList
            ?: throw PGPException("Expected encrypted data list")

        val pbe = findMatchingEncryptedData(encryptedDataList, secretRing)
            ?: throw PGPException("No matching encrypted data found")

        val decryptKey = secretKeyFor(secretRing, pbe.keyID)
            ?: throw PGPException("Secret key not found for key ID ${getKeyIdHex(pbe.keyID)}")

        val privateKey = decryptKey.extractPrivateKey(
            JcePBESecretKeyDecryptorBuilder()
                .setProvider("BC")
                .build(passphrase.toCharArray())
        )

        val clearData = pbe.getDataStream(
            JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider("BC")
                .build(privateKey)
        )

        // The encrypted stream has to be consumed to the very end before the integrity
        // protection can be evaluated, so the plaintext is collected first and only returned
        // once the check below has passed.
        val plaintext = readLiteralData(JcaPGPObjectFactory(clearData))
        clearData.drainToEnd()

        if (!pbe.isIntegrityProtected) {
            throw PGPIntegrityException(
                "Message is not integrity protected (no MDC), so modification cannot be detected"
            )
        }
        if (!pbe.verify()) {
            throw PGPIntegrityException(
                "Integrity check failed: the message was modified or corrupted"
            )
        }

        return plaintext
    }

    // ---------------------------------------------------------------- signing

    fun sign(data: ByteArray, keyId: Long, passphrase: String): ByteArray {
        val secretRing = findSecretKeyRing(keyId)
            ?: throw PGPException("Secret key not found for key ID ${getKeyIdHex(keyId)}")

        val signingKey = secretRing.secretKey
        val privateKey = signingKey.extractPrivateKey(
            JcePBESecretKeyDecryptorBuilder()
                .setProvider("BC")
                .build(passphrase.toCharArray())
        )
        val pubKey = signingKey.publicKey

        val out = ByteArrayOutputStream()
        val armoredOut = ArmoredOutputStream(out)

        val signatureGenerator = PGPSignatureGenerator(
            JcaPGPContentSignerBuilder(pubKey.algorithm, HashAlgorithmTags.SHA512)
                .setProvider("BC")
        )
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey)

        val onePassSig = signatureGenerator.generateOnePassVersion(false)
        onePassSig.encode(armoredOut)

        val literalGen = PGPLiteralDataGenerator()
        val literalOut = literalGen.open(
            armoredOut,
            PGPLiteralData.BINARY,
            "_CONSOLE",
            data.size.toLong(),
            Date()
        )

        literalOut.write(data)
        signatureGenerator.update(data)
        literalOut.close()

        signatureGenerator.generate().encode(armoredOut)
        armoredOut.close()

        return out.toByteArray()
    }

    fun verify(data: ByteArray, keyId: Long): Boolean {
        val pubKeyRing = findPublicKeyRing(keyId)
            ?: throw PGPException("Public key not found for key ID ${getKeyIdHex(keyId)}")

        var factory = JcaPGPObjectFactory(
            PGPUtil.getDecoderStream(ByteArrayInputStream(data))
        )

        var obj = factory.nextObject()

        // Signed data is usually wrapped in a compression packet.
        if (obj is PGPCompressedData) {
            factory = JcaPGPObjectFactory(obj.dataStream)
            obj = factory.nextObject()
        }

        val onePassSigList = obj as? PGPOnePassSignatureList
            ?: throw PGPException("Expected one pass signature list")

        val onePassSig = onePassSigList[0]
        // getPublicKey() searches the primary key and every subkey, so signatures made by a
        // signing subkey resolve here as well.
        val pubKey = pubKeyRing.getPublicKey(onePassSig.keyID)
            ?: throw PGPException("Public key not found for signature")

        val literalData = factory.nextObject() as? PGPLiteralData
            ?: throw PGPException("Expected literal data")

        onePassSig.init(JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKey)

        val literalStream = literalData.inputStream
        val buffer = ByteArray(STREAM_BUFFER_SIZE)
        var len: Int
        while (literalStream.read(buffer).also { len = it } >= 0) {
            if (len > 0) onePassSig.update(buffer, 0, len)
        }

        val signatureList = factory.nextObject() as? PGPSignatureList
            ?: throw PGPException("Expected signature list")

        return onePassSig.verify(signatureList[0])
    }

    // ---------------------------------------------------------------- key selection

    /**
     * Picks the key a message should be encrypted to, mirroring what GnuPG does.
     *
     * Encryption-capable subkeys are preferred over the primary key: an OpenPGP primary key is
     * normally certify/sign-only, and a dedicated encryption subkey is what peers expect to
     * address. Returns the primary key only when the ring has no usable subkey at all.
     */
    private fun selectEncryptionKey(ring: PGPPublicKeyRing): PGPPublicKey {
        val primary = ring.publicKey
        val usable = ring.publicKeys.asSequence().filter { isUsable(it) }.toList()

        val flagged = usable.filter { hasEncryptionFlags(it) }
        val pool = flagged.ifEmpty { usable.filter { isEncryptionAlgorithm(it) } }

        if (pool.isEmpty()) {
            throw PGPException(
                "Key ${getKeyIdHex(primary.keyID)} has no encryption-capable key"
            )
        }

        return pool.firstOrNull { it.keyID != primary.keyID } ?: pool.first()
    }

    private fun isUsable(key: PGPPublicKey): Boolean {
        if (key.isRevoked) return false
        val validSeconds = key.validSeconds
        if (validSeconds > 0 &&
            key.creationTime.time + validSeconds * 1000L < System.currentTimeMillis()
        ) {
            return false
        }
        return true
    }

    private fun hasEncryptionFlags(key: PGPPublicKey): Boolean {
        val sigs = key.keySignatures
        while (sigs.hasNext()) {
            val flags = sigs.next().hashedSubPackets?.keyFlags ?: continue
            if (flags and (KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE) != 0) return true
        }
        return false
    }

    private fun isEncryptionAlgorithm(key: PGPPublicKey): Boolean = when (key.algorithm) {
        PGPPublicKey.RSA_ENCRYPT,
        PGPPublicKey.RSA_GENERAL,
        PGPPublicKey.ECDH,
        PGPPublicKey.ELGAMAL_ENCRYPT,
        PGPPublicKey.ELGAMAL_GENERAL -> true
        else -> false
    }

    /**
     * Finds the secret key with [keyId] anywhere in [ring].
     *
     * This deliberately walks `getSecretKeys()`, which yields the primary key *and* every
     * subkey. A generated ring keeps its encryption-capable key in a subkey, and
     * `getExtraPublicKeys()` does not expose the subkeys of a parsed secret ring, so matching
     * on that iterator makes ciphertext addressed to the encryption subkey — including the
     * app's own output — fail with "No matching encrypted data found".
     */
    private fun secretKeyFor(ring: PGPSecretKeyRing, keyId: Long): PGPSecretKey? {
        val iter = ring.secretKeys
        while (iter.hasNext()) {
            val key = iter.next()
            if (key.publicKey.keyID == keyId) return key
        }
        return null
    }

    private fun findMatchingEncryptedData(
        dataList: PGPEncryptedDataList,
        secretRing: PGPSecretKeyRing
    ): PGPPublicKeyEncryptedData? {
        val iter = dataList.encryptedDataObjects
        while (iter.hasNext()) {
            val obj = iter.next()
            if (obj is PGPPublicKeyEncryptedData && secretKeyFor(secretRing, obj.keyID) != null) {
                return obj
            }
        }
        return null
    }

    private fun ringContainsKey(ring: PGPPublicKeyRing, keyId: Long): Boolean {
        val iter = ring.publicKeys
        while (iter.hasNext()) {
            if (iter.next().keyID == keyId) return true
        }
        return false
    }

    private fun ringContainsKey(ring: PGPSecretKeyRing, keyId: Long): Boolean {
        return secretKeyFor(ring, keyId) != null
    }

    /**
     * Builds the public key ring matching a secret key ring, binding signatures included.
     *
     * The [PGPPublicKey] objects held by a parsed secret ring already carry their user-ID
     * certifications and subkey binding signatures, and `encode()` writes them, so handing the
     * same objects to the ring constructor yields a complete public ring.
     * (`PGPPublicKeyRing.insertPublicKey` cannot be used to start a ring: it dereferences the
     * ring it is given.)
     */
    private fun toPublicKeyRing(secretRing: PGPSecretKeyRing): PGPPublicKeyRing {
        val keys = mutableListOf<PGPPublicKey>()
        val iter = secretRing.secretKeys
        while (iter.hasNext()) {
            keys.add(iter.next().publicKey)
        }
        if (keys.isEmpty()) throw PGPException("Secret key ring contains no keys")
        return PGPPublicKeyRing(keys)
    }

    private fun findPublicKeyRing(keyId: Long): PGPPublicKeyRing? {
        loadPublicKeyRingList().firstOrNull { ringContainsKey(it, keyId) }?.let { return it }
        // Fall back to the public half of a stored secret ring.
        return loadSecretKeyRingList()
            .firstOrNull { ringContainsKey(it, keyId) }
            ?.let { toPublicKeyRing(it) }
    }

    private fun findSecretKeyRing(keyId: Long): PGPSecretKeyRing? {
        return loadSecretKeyRingList().firstOrNull { ringContainsKey(it, keyId) }
    }

    // ---------------------------------------------------------------- packet helpers

    private fun readLiteralData(factory: JcaPGPObjectFactory): ByteArray {
        var obj = factory.nextObject()

        if (obj is PGPCompressedData) {
            obj = JcaPGPObjectFactory(obj.dataStream).nextObject()
        }

        if (obj is PGPLiteralData) {
            val output = ByteArrayOutputStream()
            obj.inputStream.copyTo(output)
            return output.toByteArray()
        }

        throw PGPException("Unexpected data format")
    }

    /** Reads [this] to end of stream, discarding the bytes. */
    private fun InputStream.drainToEnd() {
        val buffer = ByteArray(STREAM_BUFFER_SIZE)
        while (read(buffer) >= 0) {
            // discard: this only exists to let the MDC trailer be processed
        }
    }

    // ---------------------------------------------------------------- storage

    private fun loadPublicKeyRingList(): List<PGPPublicKeyRing> {
        return readRings(publicKeyFile) { it is PGPPublicKeyRing }
            .filterIsInstance<PGPPublicKeyRing>()
    }

    private fun loadSecretKeyRingList(): List<PGPSecretKeyRing> {
        return readRings(secretKeyFile) { it is PGPSecretKeyRing }
            .filterIsInstance<PGPSecretKeyRing>()
    }

    private fun readRings(file: File, accept: (Any) -> Boolean): List<Any> {
        if (!file.exists() || file.length() == 0L) return emptyList()

        val rings = mutableListOf<Any>()
        val input = PGPUtil.getDecoderStream(FileInputStream(file))
        try {
            val factory = JcaPGPObjectFactory(input)
            var obj = factory.nextObject()
            while (obj != null) {
                if (accept(obj)) rings.add(obj)
                obj = factory.nextObject()
            }
        } finally {
            input.close()
        }
        return rings
    }

    private fun savePublicKeyRings(rings: List<PGPPublicKeyRing>) {
        if (rings.isEmpty()) {
            publicKeyFile.delete()
            return
        }
        val armoredOut = ArmoredOutputStream(FileOutputStream(publicKeyFile))
        rings.forEach { it.encode(armoredOut) }
        armoredOut.close()
    }

    private fun saveSecretKeyRings(rings: List<PGPSecretKeyRing>) {
        if (rings.isEmpty()) {
            secretKeyFile.delete()
            return
        }
        val armoredOut = ArmoredOutputStream(FileOutputStream(secretKeyFile))
        rings.forEach { it.encode(armoredOut) }
        armoredOut.close()
    }

    private fun upsertPublicKeyRing(ring: PGPPublicKeyRing) {
        val rings = loadPublicKeyRingList().toMutableList()
        val index = rings.indexOfFirst { it.publicKey.keyID == ring.publicKey.keyID }
        if (index >= 0) rings[index] = ring else rings.add(ring)
        savePublicKeyRings(rings)
    }

    private fun upsertSecretKeyRing(ring: PGPSecretKeyRing) {
        val rings = loadSecretKeyRingList().toMutableList()
        val index = rings.indexOfFirst { it.secretKey.keyID == ring.secretKey.keyID }
        if (index >= 0) rings[index] = ring else rings.add(ring)
        saveSecretKeyRings(rings)
    }

    // ---------------------------------------------------------------- formatting

    private fun getPrimaryUserId(pubKey: PGPPublicKey): String {
        val iter = pubKey.userIDs
        return if (iter.hasNext()) iter.next() as String else unknownUserId
    }

    private fun getKeyIdHex(keyId: Long): String {
        return String.format("%016X", keyId)
    }

    private fun getAlgorithmName(algorithm: Int): String {
        return when (algorithm) {
            PGPPublicKey.RSA_GENERAL -> "RSA"
            PGPPublicKey.RSA_ENCRYPT -> "RSA"
            PGPPublicKey.RSA_SIGN -> "RSA"
            PGPPublicKey.EDDSA -> "EdDSA"
            PGPPublicKey.ECDSA -> "ECDSA"
            PGPPublicKey.ECDH -> "ECDH"
            PGPPublicKey.DSA -> "DSA"
            PGPPublicKey.ELGAMAL_ENCRYPT -> "ElGamal"
            PGPPublicKey.ELGAMAL_GENERAL -> "ElGamal"
            else -> "Unknown"
        }
    }

    private fun getKeySize(pubKey: PGPPublicKey): Int {
        return when (pubKey.algorithm) {
            PGPPublicKey.EDDSA -> 256
            PGPPublicKey.ECDH -> 256
            else -> pubKey.bitStrength
        }
    }

    private fun formatFingerprint(bytes: ByteArray): String {
        return bytes.joinToString(":") { String.format("%02X", it.toInt() and 0xFF) }
    }
}
