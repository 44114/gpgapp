package com.gpgapp.service

import android.content.Context
import com.gpgapp.R
import com.gpgapp.model.KeyInfo
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPLiteralData
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
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRingCollection
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
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import java.util.Date

class PGPManager(private val context: Context) {

    companion object {
        private const val KEYS_DIR = "pgp_keys"

        init {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private val keysDir: File
        get() = File(context.filesDir, KEYS_DIR).also { it.mkdirs() }

    private val secretKeyFile: File
        get() = File(keysDir, "secret_keys.asc")

    private val publicKeyFile: File
        get() = File(keysDir, "public_keys.asc")

    fun loadKeys(): List<KeyInfo> {
        val keys = mutableListOf<KeyInfo>()
        try {
            val publicRings = loadPublicKeyRings()
            val iter = publicRings.keyRings
            while (iter.hasNext()) {
                val ring = iter.next()
                val pubKey = ring.publicKey
                val userId = getPrimaryUserId(pubKey)
                keys.add(
                    KeyInfo(
                        keyId = pubKey.keyID,
                        keyIdHex = getKeyIdHex(pubKey.keyID),
                        userId = userId,
                        algorithm = getAlgorithmName(pubKey.algorithm),
                        keySize = getKeySize(pubKey),
                        creationDate = pubKey.creationTime.time,
                        isPrivateKey = false,
                        fingerprint = formatFingerprint(pubKey.fingerprint)
                    )
                )
            }
        } catch (_: Exception) {
        }
        return keys
    }

    fun loadSecretKeys(): List<KeyInfo> {
        val keys = mutableListOf<KeyInfo>()
        try {
            val secretRings = loadSecretKeyRings()
            val iter = secretRings.keyRings
            while (iter.hasNext()) {
                val ring = iter.next()
                val secKey = ring.secretKey
                val pubKey = secKey.publicKey
                val userId = getPrimaryUserId(pubKey)
                keys.add(
                    KeyInfo(
                        keyId = pubKey.keyID,
                        keyIdHex = getKeyIdHex(pubKey.keyID),
                        userId = userId,
                        algorithm = getAlgorithmName(pubKey.algorithm),
                        keySize = getKeySize(pubKey),
                        creationDate = pubKey.creationTime.time,
                        isPrivateKey = true,
                        fingerprint = formatFingerprint(pubKey.fingerprint)
                    )
                )
            }
        } catch (_: Exception) {
        }
        return keys
    }

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

        val secretRing = keyRingGen.generateSecretKeyRing()
        val publicRing = keyRingGen.generatePublicKeyRing()

        appendSecretKeyRing(secretRing)
        appendPublicKeyRing(publicRing)
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

        val secretRing = keyRingGen.generateSecretKeyRing()
        val publicRing = keyRingGen.generatePublicKeyRing()

        appendSecretKeyRing(secretRing)
        appendPublicKeyRing(publicRing)
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

    fun deleteKey(keyId: Long) {
        val secretRings = loadSecretKeyRingList().toMutableList()
        secretRings.removeAll { it.secretKey.keyID == keyId }
        saveSecretKeyRings(secretRings)

        val publicRings = loadPublicKeyRingList().toMutableList()
        publicRings.removeAll { it.publicKey.keyID == keyId }
        savePublicKeyRings(publicRings)
    }

    fun exportPublicKey(keyId: Long): String {
        val rings = loadPublicKeyRingList()
        val ring = rings.find { it.publicKey.keyID == keyId }
            ?: throw PGPException("Public key not found")
        val out = ByteArrayOutputStream()
        val armoredOut = ArmoredOutputStream(out)
        ring.encode(armoredOut)
        armoredOut.close()
        return String(out.toByteArray())
    }

    fun exportPrivateKey(keyId: Long): String {
        val rings = loadSecretKeyRingList()
        val ring = rings.find { it.secretKey.keyID == keyId }
            ?: throw PGPException("Private key not found")
        val out = ByteArrayOutputStream()
        val armoredOut = ArmoredOutputStream(out)
        ring.encode(armoredOut)
        armoredOut.close()
        return String(out.toByteArray())
    }

    fun importKey(armoredKey: String) {
        val input = PGPUtil.getDecoderStream(ByteArrayInputStream(armoredKey.toByteArray()))
        val factory = JcaPGPObjectFactory(input)

        var obj = factory.nextObject()
        var imported = false

        while (obj != null) {
            when (obj) {
                is PGPSecretKeyRing -> {
                    appendSecretKeyRing(obj)
                    imported = true
                }
                is PGPPublicKeyRing -> {
                    appendPublicKeyRing(obj)
                    imported = true
                }
            }
            obj = factory.nextObject()
        }

        if (!imported) {
            throw PGPException("No valid PGP key found in the input")
        }
    }

    fun encrypt(data: ByteArray, publicKeyRing: PGPPublicKeyRing): ByteArray {
        val encKey = getEncryptionKey(publicKeyRing, publicKeyRing.publicKey.keyID)
        val out = ByteArrayOutputStream()
        val armoredOut = ArmoredOutputStream(out)

        val encryptor = JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
            .setWithIntegrityPacket(true)
            .setSecureRandom(SecureRandom())
            .setProvider("BC")

        val encGen = org.bouncycastle.openpgp.PGPEncryptedDataGenerator(encryptor)
        encGen.addMethod(JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"))

        val encryptedOut = encGen.open(armoredOut, data.size.coerceAtLeast(4096).toLong())

        val compGen = org.bouncycastle.openpgp.PGPCompressedDataGenerator(
            CompressionAlgorithmTags.ZLIB
        )
        val compressedOut = compGen.open(encryptedOut)

        val literalGen = org.bouncycastle.openpgp.PGPLiteralDataGenerator()
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

    fun encrypt(data: ByteArray, keyId: Long): ByteArray {
        val publicRings = loadPublicKeyRingList()
        val ring = publicRings.find { it.publicKey.keyID == keyId }
            ?: publicRings.firstOrNull { ring ->
                ring.publicKeys.asSequence().any { it.keyID == keyId }
            }
            ?: throw PGPException("Public key not found")
        return encrypt(data, ring)
    }

    fun decrypt(encryptedData: ByteArray, keyId: Long, passphrase: String): ByteArray {
        val secretRings = loadSecretKeyRingList()
        val secretRing = secretRings.find { it.secretKey.keyID == keyId }
            ?: secretRings.firstOrNull { ring ->
                ring.secretKeys.asSequence().any { it.keyID == keyId }
            }
            ?: throw PGPException("Secret key not found")

        val input = PGPUtil.getDecoderStream(ByteArrayInputStream(encryptedData))
        val factory = JcaPGPObjectFactory(input)

        val encryptedDataList = factory.nextObject() as? PGPEncryptedDataList
            ?: throw PGPException("Expected encrypted data list")

        val pbe = findMatchingEncryptedData(encryptedDataList, secretRing)
            ?: throw PGPException("No matching encrypted data found")

        val decryptKey = findSecretKey(secretRing, pbe.keyID)
        val decryptor = JcePBESecretKeyDecryptorBuilder()
            .setProvider("BC")
            .build(passphrase.toCharArray())
        val privateKey = decryptKey.extractPrivateKey(decryptor)
        val decryptorFactory = JcePublicKeyDataDecryptorFactoryBuilder()
            .setProvider("BC")
            .build(privateKey)

        val clearData = pbe.getDataStream(decryptorFactory)

        val clearFactory = JcaPGPObjectFactory(clearData)
        var obj = clearFactory.nextObject()

        if (obj is PGPCompressedData) {
            val compFactory = JcaPGPObjectFactory(obj.dataStream)
            obj = compFactory.nextObject()
        }

        if (obj is PGPLiteralData) {
            val output = ByteArrayOutputStream()
            obj.inputStream.copyTo(output)
            return output.toByteArray()
        }

        throw PGPException("Unexpected data format")
    }

    fun sign(data: ByteArray, keyId: Long, passphrase: String): ByteArray {
        val secretRings = loadSecretKeyRingList()
        val secretRing = secretRings.find { it.secretKey.keyID == keyId }
            ?: throw PGPException("Secret key not found")

        val privateKey = secretRing.secretKey.extractPrivateKey(
            JcePBESecretKeyDecryptorBuilder()
                .setProvider("BC")
                .build(passphrase.toCharArray())
        )
        val pubKey = secretRing.secretKey.publicKey

        val out = ByteArrayOutputStream()
        val armoredOut = ArmoredOutputStream(out)

        val signatureGenerator = PGPSignatureGenerator(
            JcaPGPContentSignerBuilder(pubKey.algorithm, HashAlgorithmTags.SHA512)
                .setProvider("BC")
        )
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey)

        val onePassSig = signatureGenerator.generateOnePassVersion(false)
        onePassSig.encode(armoredOut)

        val literalGen = org.bouncycastle.openpgp.PGPLiteralDataGenerator()
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
        val publicRings = loadPublicKeyRingList()
        val pubKeyRing = publicRings.find { it.publicKey.keyID == keyId }
            ?: throw PGPException("Public key not found")

        val input = PGPUtil.getDecoderStream(ByteArrayInputStream(data))
        val factory = JcaPGPObjectFactory(input)

        val onePassSigList = factory.nextObject() as? PGPOnePassSignatureList
            ?: throw PGPException("Expected one pass signature list")

        val onePassSig = onePassSigList[0]
        val pubKey = pubKeyRing.getPublicKey(onePassSig.keyID)
            ?: throw PGPException("Public key not found for signature")

        val literalData = factory.nextObject() as? PGPLiteralData
            ?: throw PGPException("Expected literal data")

        onePassSig.init(JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKey)

        val literalStream = literalData.inputStream
        val buffer = ByteArray(8192)
        var len: Int
        while (literalStream.read(buffer).also { len = it } >= 0) {
            onePassSig.update(buffer, 0, len)
        }

        val signatureList = factory.nextObject() as? PGPSignatureList
            ?: throw PGPException("Expected signature list")

        return onePassSig.verify(signatureList[0])
    }

    fun getPublicKeyRing(keyId: Long): PGPPublicKeyRing? {
        return loadPublicKeyRingList().find { it.publicKey.keyID == keyId }
    }

    fun getSecretKeyRing(keyId: Long): PGPSecretKeyRing? {
        return loadSecretKeyRingList().find { it.secretKey.keyID == keyId }
    }

    private fun findMatchingEncryptedData(
        dataList: PGPEncryptedDataList,
        secretRing: PGPSecretKeyRing
    ): PGPPublicKeyEncryptedData? {
        val iter = dataList.encryptedDataObjects
        while (iter.hasNext()) {
            val obj = iter.next()
            if (obj is PGPPublicKeyEncryptedData) {
                val secKey = secretRing.secretKey
                if (obj.keyID == secKey.keyID || hasSubkey(secretRing, obj.keyID)) {
                    return obj
                }
            }
        }
        return null
    }

    private fun hasSubkey(secretRing: PGPSecretKeyRing, keyId: Long): Boolean {
        val iter = secretRing.extraPublicKeys
        while (iter.hasNext()) {
            if (iter.next().keyID == keyId) return true
        }
        return false
    }

    private fun findSecretKey(secretRing: PGPSecretKeyRing, keyId: Long): PGPSecretKey {
        if (secretRing.secretKey.keyID == keyId) {
            return secretRing.secretKey
        }
        val iter = secretRing.secretKeys
        while (iter.hasNext()) {
            val key = iter.next()
            if (key.keyID == keyId) return key
        }
        return secretRing.secretKey
    }

    private fun getEncryptionKey(ring: PGPPublicKeyRing, preferredKeyId: Long): PGPPublicKey {
        var iter = ring.publicKeys
        while (iter.hasNext()) {
            val key = iter.next()
            if (key.keyID == preferredKeyId && isEncryptionKey(key)) {
                return key
            }
        }
        iter = ring.publicKeys
        while (iter.hasNext()) {
            val key = iter.next()
            if (isEncryptionKey(key)) {
                return key
            }
        }
        return ring.publicKey
    }

    private fun isEncryptionKey(key: PGPPublicKey): Boolean {
        val sigIter = key.keySignatures
        while (sigIter.hasNext()) {
            val sig = sigIter.next()
            val flags = sig.hashedSubPackets?.keyFlags
            if (flags != null && flags and KeyFlags.ENCRYPT_COMMS != 0 ||
                flags != null && flags and KeyFlags.ENCRYPT_STORAGE != 0
            ) {
                return true
            }
        }
        return when (key.algorithm) {
            PGPPublicKey.RSA_ENCRYPT,
            PGPPublicKey.RSA_GENERAL,
            PGPPublicKey.ECDH,
            PGPPublicKey.ELGAMAL_ENCRYPT -> true
            else -> false
        }
    }

    private fun loadPublicKeyRings(): JcaPGPPublicKeyRingCollection {
        return if (publicKeyFile.exists()) {
            JcaPGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(FileInputStream(publicKeyFile))
            )
        } else {
            JcaPGPPublicKeyRingCollection(mutableListOf<PGPPublicKeyRing>())
        }
    }

    private fun loadSecretKeyRings(): JcaPGPSecretKeyRingCollection {
        return if (secretKeyFile.exists()) {
            JcaPGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(FileInputStream(secretKeyFile))
            )
        } else {
            JcaPGPSecretKeyRingCollection(mutableListOf<PGPSecretKeyRing>())
        }
    }

    private fun loadPublicKeyRingList(): List<PGPPublicKeyRing> {
        return if (publicKeyFile.exists()) {
            val rings = mutableListOf<PGPPublicKeyRing>()
            val input = PGPUtil.getDecoderStream(FileInputStream(publicKeyFile))
            val factory = JcaPGPObjectFactory(input)
            var obj = factory.nextObject()
            while (obj != null) {
                if (obj is PGPPublicKeyRing) rings.add(obj)
                obj = factory.nextObject()
            }
            input.close()
            rings
        } else emptyList()
    }

    private fun loadSecretKeyRingList(): List<PGPSecretKeyRing> {
        return if (secretKeyFile.exists()) {
            val rings = mutableListOf<PGPSecretKeyRing>()
            val input = PGPUtil.getDecoderStream(FileInputStream(secretKeyFile))
            val factory = JcaPGPObjectFactory(input)
            var obj = factory.nextObject()
            while (obj != null) {
                if (obj is PGPSecretKeyRing) rings.add(obj)
                obj = factory.nextObject()
            }
            input.close()
            rings
        } else emptyList()
    }

    private fun savePublicKeyRings(rings: List<PGPPublicKeyRing>) {
        val armoredOut = ArmoredOutputStream(FileOutputStream(publicKeyFile))
        rings.forEach { it.encode(armoredOut) }
        armoredOut.close()
    }

    private fun saveSecretKeyRings(rings: List<PGPSecretKeyRing>) {
        val armoredOut = ArmoredOutputStream(FileOutputStream(secretKeyFile))
        rings.forEach { it.encode(armoredOut) }
        armoredOut.close()
    }

    private fun appendPublicKeyRing(ring: PGPPublicKeyRing) {
        val rings = loadPublicKeyRingList().toMutableList()
        rings.add(ring)
        savePublicKeyRings(rings)
    }

    private fun appendSecretKeyRing(ring: PGPSecretKeyRing) {
        val rings = loadSecretKeyRingList().toMutableList()
        rings.add(ring)
        saveSecretKeyRings(rings)
    }

    private fun getPrimaryUserId(pubKey: PGPPublicKey): String {
        val iter = pubKey.userIDs
        return if (iter.hasNext()) iter.next() as String else context.getString(R.string.unknown)
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
        return bytes.joinToString(":") { String.format("%02X", it) }
    }

    fun getPublicKeyRingCount(): Int {
        return loadPublicKeyRingList().size
    }
}
