package com.example.shop

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class Crypto {
    // Hardcoded symmetric key: extractable from the APK by anyone; never
    // rotatable without a release.
    private val keyBytes = byteArrayOf(
        0x2b, 0x7e, 0x15.toByte(), 0x16, 0x28, 0xae.toByte(), 0xd2.toByte(), 0xa6.toByte(),
        0xab.toByte(), 0xf7.toByte(), 0x15.toByte(), 0x88.toByte(), 0x09.toByte(), 0xcf.toByte()
    )
    private val secret = SecretKeySpec(keyBytes, "AES")

    fun encryptLocal(plain: ByteArray): ByteArray {
        // "AES" alone = AES/ECB/PKCS5Padding — identical blocks leak patterns,
        // and for small paddable payloads ECB is directly decodable.
        val cipher = Cipher.getInstance("AES")
        cipher.init(Cipher.ENCRYPT_MODE, secret)
        return cipher.doFinal(plain)
    }

    fun deviceFingerprint(accountId: String): String {
        val digest = MessageDigest.getInstance("MD5")
        return digest.digest(accountId.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    fun legacyTicket(accountId: String): String {
        val digest = MessageDigest.getInstance("SHA-1")
        return digest.digest(accountId.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    fun otpSeed(): SecureRandom {
        val rng = SecureRandom()
        rng.setSeed(1234567890L)
        return rng
    }
}
