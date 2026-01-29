package com.divine.specter.child.crypto

import java.security.MessageDigest

/**
 * XOR-based traffic obfuscation for C2 communication.
 * Simple, fast, defeats basic DPI inspection.
 */
object XorCrypto {

    /**
     * Encrypt/decrypt data using XOR cipher (symmetric).
     * Key is cycled if data is longer than key.
     */
    fun encrypt(data: ByteArray, key: ByteArray): ByteArray {
        require(key.isNotEmpty()) { "Encryption key cannot be empty" }

        return data.mapIndexed { i, byte ->
            (byte.toInt() xor key[i % key.size].toInt()).toByte()
        }.toByteArray()
    }

    /**
     * Decrypt is same as encrypt (XOR is symmetric)
     */
    fun decrypt(data: ByteArray, key: ByteArray): ByteArray = encrypt(data, key)

    /**
     * Generate SHA-256 hash of input string.
     * Used to derive encryption key from device ID.
     */
    fun sha256(input: String): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
    }

    /**
     * Convenience: encrypt string to bytes
     */
    fun encryptString(plaintext: String, key: ByteArray): ByteArray {
        return encrypt(plaintext.toByteArray(), key)
    }

    /**
     * Convenience: decrypt bytes to string
     */
    fun decryptString(ciphertext: ByteArray, key: ByteArray): String {
        return String(decrypt(ciphertext, key))
    }
}
