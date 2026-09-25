package com.gpgapp.service

import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Host-side tests for the OpenPGP layer.
 *
 * These exercise the exact [PGPManager] the app ships, on the JVM. The interop tests at the
 * bottom shell out to the system `gpg` binary and act as an independent oracle: a real GnuPG
 * implementation has to be able to read what this app produces, and the app has to be able to
 * read what GnuPG produces, in both cases using the encryption subkey.
 */
class PGPManagerTest {

    private val passphrase = "correct horse battery staple"
    private val userId = "Test User <test@example.com>"

    private lateinit var keysDir: File
    private lateinit var manager: PGPManager

    @Before
    fun setUp() {
        keysDir = tempDir("pgp-test")
        manager = PGPManager(keysDir, "Unknown")
    }

    // ------------------------------------------------------------ key selection

    @Test
    fun `ed25519 ciphertext is addressed to the encryption subkey`() {
        manager.generateKeyRing(userId, passphrase, "Ed25519")

        val ring = exportedPublicRing(manager.exportPublicKey(primaryKeyId()))
        val subkeyId = encryptionSubkeyId(ring)

        assertNotEquals("subkey must differ from the primary key", ring.publicKey.keyID, subkeyId)
        assertEquals(
            "ciphertext must be encrypted to the encryption subkey, not the primary key",
            subkeyId,
            recipientKeyIdOf(manager.encrypt("hello".toByteArray(), primaryKeyId()))
        )
    }

    @Test
    fun `rsa ciphertext is addressed to the encryption subkey`() {
        manager.generateKeyRing(userId, passphrase, "RSA", 2048)

        val ring = exportedPublicRing(manager.exportPublicKey(primaryKeyId()))
        val subkeyId = encryptionSubkeyId(ring)

        assertNotEquals(ring.publicKey.keyID, subkeyId)
        assertEquals(
            subkeyId,
            recipientKeyIdOf(manager.encrypt("hello".toByteArray(), primaryKeyId()))
        )
    }

    // ------------------------------------------------------------ round trips

    @Test
    fun `ed25519 message can be decrypted by its own key`() {
        manager.generateKeyRing(userId, passphrase, "Ed25519")
        val keyId = primaryKeyId()

        val message = "Short synthetic message"
        val ciphertext = manager.encrypt(message.toByteArray(), keyId)

        assertEquals(
            message,
            String(manager.decrypt(ciphertext, keyId, passphrase))
        )
    }

    @Test
    fun `rsa message can be decrypted by its own key`() {
        manager.generateKeyRing(userId, passphrase, "RSA", 2048)
        val keyId = primaryKeyId()

        val message = "Short synthetic message"
        val ciphertext = manager.encrypt(message.toByteArray(), keyId)

        assertEquals(message, String(manager.decrypt(ciphertext, keyId, passphrase)))
    }

    /**
     * Reproduces the reviewer's interop failure in the other direction: ciphertext addressed
     * directly to the encryption subkey (which is what GnuPG produces) must decrypt.
     */
    @Test
    fun `ciphertext addressed to the encryption subkey can be decrypted`() {
        manager.generateKeyRing(userId, passphrase, "Ed25519")
        val keyId = primaryKeyId()

        val ring = exportedPublicRing(manager.exportPublicKey(keyId))
        val subkey: PGPPublicKey = ring.publicKeys.asSequence()
            .first { it.keyID == encryptionSubkeyId(ring) }

        val message = "Addressed straight to the ECDH subkey"
        val ciphertext = manager.encryptTo(message.toByteArray(), subkey)

        assertEquals(message, String(manager.decrypt(ciphertext, keyId, passphrase)))
    }

    // ------------------------------------------------------------ integrity

    @Test
    fun `modified ciphertext is rejected`() {
        manager.generateKeyRing(userId, passphrase, "Ed25519")
        val keyId = primaryKeyId()

        val message = "Integrity protected message"
        val binary = binaryCiphertext(manager.encrypt(message.toByteArray(), keyId))

        // Flip a bit inside the trailing MDC region, exactly as the reviewer did.
        val tampered = binary.copyOf()
        val index = tampered.size - 5
        tampered[index] = (tampered[index].toInt() xor 0x01).toByte()

        val failure = runCatching { manager.decrypt(tampered, keyId, passphrase) }.exceptionOrNull()

        assertNotNull("modified ciphertext must not decrypt", failure)
        assertTrue(
            "expected an integrity failure, got $failure",
            failure is PGPIntegrityException
        )
        assertNotEquals(message, runCatching {
            String(manager.decrypt(tampered, keyId, passphrase))
        }.getOrDefault(""))
    }

    @Test
    fun `intact ciphertext still decrypts`() {
        manager.generateKeyRing(userId, passphrase, "Ed25519")
        val keyId = primaryKeyId()

        val message = "Untouched message"
        val binary = binaryCiphertext(manager.encrypt(message.toByteArray(), keyId))

        assertEquals(message, String(manager.decrypt(binary, keyId, passphrase)))
    }

    // ------------------------------------------------------------ packet framing

    /**
     * Regression test for `encGen.open(out, data.size.coerceAtLeast(4096))`, which declared an
     * encrypted packet at least 4096 bytes long regardless of the message and produced
     * malformed framing. A correctly framed short message is far smaller than that.
     */
    @Test
    fun `short message does not produce an oversized encrypted packet`() {
        manager.generateKeyRing(userId, passphrase, "Ed25519")
        val keyId = primaryKeyId()

        val binary = binaryCiphertext(manager.encrypt("Hello, OpenPGP!".toByteArray(), keyId))

        assertTrue(
            "a 15-byte message framed correctly must stay well below 4096 bytes, was ${binary.size}",
            binary.size < 2048
        )
    }

    // ------------------------------------------------------------ signing

    @Test
    fun `signed message verifies and tampering is detected`() {
        manager.generateKeyRing(userId, passphrase, "Ed25519")
        val keyId = primaryKeyId()

        val message = "Sign me"
        val signed = manager.sign(message.toByteArray(), keyId, passphrase)
        assertTrue("a freshly signed message must verify", manager.verify(signed, keyId))

        // Tamper with the signed content. The armored form is base64, so the change has to be
        // applied to the decoded packet stream rather than to the armored text.
        val binary = PGPUtil.getDecoderStream(ByteArrayInputStream(signed)).readBytes()
        val offset = indexOf(binary, message.toByteArray())
        assertTrue("signed content must appear in the packet stream", offset >= 0)

        binary[offset] = (binary[offset].toInt() xor 0x01).toByte()
        assertFalse("tampered content must not verify", manager.verify(binary, keyId))
    }

    // ------------------------------------------------------------ storage

    @Test
    fun `importing a private key also exposes its public half`() {
        manager.generateKeyRing(userId, passphrase, "Ed25519")
        val keyId = primaryKeyId()
        val privateKey = manager.exportPrivateKey(keyId)

        // A fresh store that only ever sees the private key.
        val other = PGPManager(tempDir("pgp-test-import"), "Unknown")
        other.importKey(privateKey)

        assertTrue(
            "imported private key must be listed",
            other.loadSecretKeys().any { it.keyId == keyId }
        )
        assertTrue(
            "imported private key must also be usable as an encryption recipient",
            other.loadKeys().any { it.keyId == keyId }
        )
    }

    // ------------------------------------------------------------ GnuPG oracle

    @Test
    fun `gnupg can decrypt app ciphertext and app can decrypt gnupg ciphertext`() {
        assumeTrue("gpg not installed, skipping oracle test", gpgAvailable())

        manager.generateKeyRing(userId, passphrase, "Ed25519")
        val keyId = primaryKeyId()

        val gpgHome = tempDir("gnupg")
        gpgHome.setReadable(true, true)
        gpgHome.setExecutable(true, true)

        // Hand both halves of the app-generated key to GnuPG.
        assertTrue(
            "gpg must import the app public key",
            gpg(gpgHome, "--import", input = manager.exportPublicKey(keyId)).first == 0
        )
        assertTrue(
            "gpg must import the app private key",
            gpg(gpgHome, "--import", input = manager.exportPrivateKey(keyId)).first == 0
        )
        unlockAgent(gpgHome)

        // Direction 1: GnuPG encrypts to the app's key, the app decrypts.
        val fromGpg = "Message encrypted by GnuPG"
        val (encryptCode, encryptOut) = gpg(
            gpgHome,
            "--encrypt", "--armor", "--trust-model", "always",
            "--recipient", userId,
            input = fromGpg
        )
        assertEquals("gpg --encrypt failed: $encryptOut", 0, encryptCode)
        assertEquals(
            "app must decrypt ciphertext produced by GnuPG",
            fromGpg,
            String(manager.decrypt(encryptOut.toByteArray(), keyId, passphrase))
        )

        // Direction 2: the app encrypts, GnuPG decrypts. A malformed packet makes GnuPG exit
        // with status 2 and report "decryption failed: Invalid packet".
        val toGpg = "Message encrypted by the app"
        val appCiphertext = manager.encrypt(toGpg.toByteArray(), keyId)
        val armored = String(appCiphertext)

        // Deterministic framing check, needing no secret key: the encrypted packet must declare
        // a length close to the real content. The old code declared at least 4096 bytes for
        // every message regardless of size.
        val (_, packets) = gpg(gpgHome, "--list-packets", input = armored)
        assertTrue(
            "app ciphertext must carry an integrity-protected (MDC) packet: $packets",
            packets.contains("mdc_method")
        )
        val declaredLength = Regex("tag=18[^\\n]*?plen=(\\d+)")
            .find(packets)?.groupValues?.get(1)?.toInt()
        assertNotNull("could not read the encrypted packet length from: $packets", declaredLength)
        assertTrue(
            "encrypted packet must be framed to the real content length, declared=$declaredLength",
            declaredLength!! < 1024
        )

        val (decryptCode, decryptOut) = gpgDecrypt(gpgHome, armored)
        assertEquals(
            "GnuPG must decrypt app ciphertext cleanly, got: $decryptOut",
            0,
            decryptCode
        )
        assertTrue(
            "GnuPG must recover the exact plaintext, got: $decryptOut",
            decryptOut.contains(toGpg)
        )
        assertFalse(
            "GnuPG must not warn about a key that is not marked for encryption: $decryptOut",
            decryptOut.contains("not marked for encryption")
        )
    }

    /**
     * A private key imported on its own must yield a public half GnuPG accepts. This exercises
     * the secret-ring to public-ring conversion, including the subkey binding signature that
     * makes the encryption subkey usable at all.
     */
    @Test
    fun `gnupg can encrypt to the public half derived from an imported private key`() {
        assumeTrue("gpg not installed, skipping oracle test", gpgAvailable())

        manager.generateKeyRing(userId, passphrase, "Ed25519")
        val keyId = primaryKeyId()

        val store = PGPManager(tempDir("pgp-test-derived"), "Unknown")
        store.importKey(manager.exportPrivateKey(keyId))

        val gpgHome = tempDir("gnupg-derived")
        gpgHome.setReadable(true, true)
        gpgHome.setExecutable(true, true)

        val (importCode, importOut) = gpg(
            gpgHome,
            "--import",
            input = store.exportPublicKey(keyId)
        )
        assertEquals("gpg must import the derived public key: $importOut", 0, importCode)
        assertFalse(
            "GnuPG must not report a missing subkey binding signature: $importOut",
            importOut.contains("no binding signature")
        )

        val message = "Encrypted to a derived public key"
        val (encryptCode, ciphertext) = gpg(
            gpgHome,
            "--encrypt", "--armor", "--trust-model", "always", "--recipient", userId,
            input = message
        )
        assertEquals("gpg --encrypt failed: $ciphertext", 0, encryptCode)

        assertEquals(
            message,
            String(store.decrypt(ciphertext.toByteArray(), keyId, passphrase))
        )
    }

    /**
     * Signing interoperability in both directions. Sign/Verify are user-facing screens, so the
     * signed messages have to be readable by other OpenPGP implementations and vice versa.
     */
    @Test
    fun `gnupg verifies app signatures and app verifies gnupg signatures`() {
        assumeTrue("gpg not installed, skipping oracle test", gpgAvailable())

        manager.generateKeyRing(userId, passphrase, "Ed25519")
        val keyId = primaryKeyId()

        val gpgHome = tempDir("gnupg-sign")
        gpgHome.setReadable(true, true)
        gpgHome.setExecutable(true, true)

        assertEquals(
            0,
            gpg(gpgHome, "--import", input = manager.exportPublicKey(keyId)).first
        )
        assertEquals(
            0,
            gpg(gpgHome, "--import", input = manager.exportPrivateKey(keyId)).first
        )
        unlockAgent(gpgHome)

        // Direction 1: the app signs, GnuPG verifies.
        val signedByApp = "Signed by the app"
        val signed = manager.sign(signedByApp.toByteArray(), keyId, passphrase)
        val (verifyCode, verifyOut) = gpg(gpgHome, "--decrypt", input = String(signed))
        assertEquals("GnuPG must accept the app signature: $verifyOut", 0, verifyCode)
        assertTrue("GnuPG must report a good signature: $verifyOut", verifyOut.contains("Good signature"))
        assertTrue("GnuPG must recover the message: $verifyOut", verifyOut.contains(signedByApp))

        // Direction 2: GnuPG signs (compressing by default), the app verifies. This also
        // exercises the compression unwrapping in verify().
        val signedByGpg = "Signed by GnuPG"
        val (signCode, gpgSigned, signErr) = gpgBinary(
            gpgHome,
            "--sign", "--pinentry-mode", "loopback", "--passphrase", passphrase,
            "--local-user", userId,
            input = signedByGpg
        )
        assertEquals("gpg --sign failed: $signErr", 0, signCode)
        assertTrue(
            "app must verify a compressed signature produced by GnuPG",
            manager.verify(gpgSigned, keyId)
        )

        // The same message must not verify against an unrelated key.
        manager.generateKeyRing("Other User <other@example.com>", passphrase, "Ed25519")
        val otherKeyId = manager.loadSecretKeys().first { it.userId.startsWith("Other") }.keyId
        val wrongKey = runCatching { manager.verify(gpgSigned, otherKeyId) }
        assertTrue(
            "an unrelated key must not verify this signature",
            wrongKey.isFailure || wrongKey.getOrNull() == false
        )
    }

    // ------------------------------------------------------------ helpers

    private fun tempDir(prefix: String): File {
        val dir = File.createTempFile(prefix, "")
        dir.delete()
        dir.mkdirs()
        return dir
    }

    private companion object {
        /** Attempts allowed for gpg-agent startup races in the interoperability tests. */
        const val AGENT_ATTEMPTS = 3
    }

    private fun primaryKeyId(): Long = manager.loadSecretKeys().first().keyId

    private fun exportedPublicRing(armored: String): PGPPublicKeyRing =
        JcaPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(armored.toByteArray())))
            .nextObject() as PGPPublicKeyRing

    private fun encryptionSubkeyId(ring: PGPPublicKeyRing): Long =
        ring.publicKeys.asSequence().first { it.keyID != ring.publicKey.keyID }.keyID

    private fun recipientKeyIdOf(armoredCiphertext: ByteArray): Long {
        val list = JcaPGPObjectFactory(
            PGPUtil.getDecoderStream(ByteArrayInputStream(armoredCiphertext))
        ).nextObject() as PGPEncryptedDataList
        return (list.encryptedDataObjects.next() as PGPPublicKeyEncryptedData).keyID
    }

    private fun binaryCiphertext(armored: ByteArray): ByteArray =
        PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).readBytes()

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }

    private fun gpgAvailable(): Boolean = try {
        val process = ProcessBuilder("gpg", "--version").start()
        process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0
    } catch (_: Exception) {
        false
    }

    /**
     * GnuPG performs private-key operations through gpg-agent. With `--pinentry-mode loopback`
     * the supplied passphrase can be dropped while the agent is still starting, which surfaces
     * as a spurious "Bad passphrase" and makes any assertion that unlocks the key flaky on a
     * headless machine.
     *
     * [unlockAgent] retries a throwaway signing operation until the agent is genuinely up and
     * the passphrase cached; [gpgDecrypt] retries the real operation with a fresh agent in
     * between. Both are retries around gpg-agent startup only — never around the property under
     * test, which is the packet framing and key selection.
     */
    private fun unlockAgent(home: File) {
        val probe = File(home, "warmup.txt").apply { writeText("warmup") }
        repeat(AGENT_ATTEMPTS) { attempt ->
            val (code, _) = gpg(
                home,
                "--pinentry-mode", "loopback", "--passphrase", passphrase,
                "--local-user", userId,
                "--output", "/dev/null", "--sign", probe.absolutePath
            )
            if (code == 0) return
            restartAgent(home, attempt)
        }
        fail("gpg-agent could not unlock the key for signing after $AGENT_ATTEMPTS attempts")
    }

    private fun gpgDecrypt(home: File, ciphertext: String): Pair<Int, String> {
        var last: Pair<Int, String> = 0 to ""
        repeat(AGENT_ATTEMPTS) { attempt ->
            last = gpg(
                home,
                "--decrypt", "--pinentry-mode", "loopback", "--passphrase", passphrase,
                input = ciphertext
            )
            if (last.first == 0) return last
            restartAgent(home, attempt)
        }
        return last
    }

    private fun restartAgent(home: File, attempt: Int) {
        try {
            ProcessBuilder("gpgconf", "--homedir", home.absolutePath, "--kill", "gpg-agent")
                .redirectErrorStream(true)
                .start()
                .waitFor(10, TimeUnit.SECONDS)
        } catch (_: Exception) {
            // gpgconf may be unavailable; the retry on its own still helps.
        }
        Thread.sleep(250L * (attempt + 1))
    }

    /** Runs gpg, feeding [input] on stdin, and returns (exitCode, combinedOutput). */
    private fun gpg(home: File, vararg args: String, input: String = ""): Pair<Int, String> {
        val process = gpgProcess(home, args, redirectError = true).start()

        process.outputStream.use { it.write(input.toByteArray()) }
        val output = process.inputStream.readBytes().decodeToString()
        process.waitFor(60, TimeUnit.SECONDS)
        return process.exitValue() to output
    }

    /** Runs gpg keeping stdout (which may be binary) apart from stderr. */
    private fun gpgBinary(
        home: File,
        vararg args: String,
        input: String = ""
    ): Triple<Int, ByteArray, String> {
        val process = gpgProcess(home, args, redirectError = false).start()

        process.outputStream.use { it.write(input.toByteArray()) }
        val stdout = process.inputStream.readBytes()
        val stderr = process.errorStream.readBytes().decodeToString()
        process.waitFor(60, TimeUnit.SECONDS)
        return Triple(process.exitValue(), stdout, stderr)
    }

    /**
     * GnuPG translates its diagnostics, so the assertions below only hold with a fixed locale;
     * without this, checks for English phrases would silently pass on a localized system.
     */
    private fun gpgProcess(
        home: File,
        args: Array<out String>,
        redirectError: Boolean
    ): ProcessBuilder {
        val command = mutableListOf("gpg", "--homedir", home.absolutePath, "--batch", "--no-tty")
        command.addAll(args)
        return ProcessBuilder(command).redirectErrorStream(redirectError).apply {
            environment()["LC_ALL"] = "C"
            environment()["LANG"] = "C"
        }
    }
}
