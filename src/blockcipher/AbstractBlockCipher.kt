package blockcipher

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

abstract class AbstractBlockCipher(private val key: SecretKeySpec) : BlockCipherable {
    private val cipher: Cipher = Cipher.getInstance("AES/ECB/NoPadding")
    protected var lastBlock: ByteArray? = null

    companion object {
        val AES_KEY_SIZE = intArrayOf(16, 24, 32)
        const val BLOCK_SIZE = 16
        const val NONCE_SIZE = 4
        const val IV_SIZE = 8
        const val COUNTER_SIZE = 4
    }

    fun blockCipherEncrypt(data: ByteArray): ByteArray? {
        cipher.init(Cipher.ENCRYPT_MODE, this.key)
        return cipher.doFinal(data)
    }

    fun blockCipherDecrypt(data: ByteArray): ByteArray? {
        cipher.init(Cipher.DECRYPT_MODE, this.key)
        return cipher.doFinal(data)
    }

    fun paddingData(data: ByteArray): ByteArray {
        var copyData = data.clone()
        var delta = BLOCK_SIZE - data.size
        delta = if (delta == 0) BLOCK_SIZE else delta
        var paddingBytes = ByteArray(0)
        for (i in 0..<delta) {
            paddingBytes += delta.toByte()
        }
        copyData += paddingBytes

        return copyData
    }

    override fun encrypt(
        data: ByteArray,
        iv: ByteArray?,
    ): ByteArray {
        this.lastBlock = iv
        var ciphertext = ByteArray(0)
        val s = BLOCK_SIZE
        var i = 0
        while (i + s < data.size) {
            val start = i
            val end = i + s - 1
            val newBlock = processBlockEncrypt(data.sliceArray(start..end), false, "PKCS7")
            if (newBlock != null) {
                ciphertext += newBlock
            }
            i += s
        }
        val newBlock = processBlockEncrypt(data.sliceArray(i..<data.size), true, "PKCS7")
        if (newBlock != null) {
            ciphertext += newBlock
        }
        ciphertext = if (iv != null) iv + ciphertext else ciphertext
        return ciphertext
    }

    override fun decrypt(
        data: ByteArray,
        iv: ByteArray?,
    ): ByteArray {
        this.lastBlock = iv
        var plaintext = ByteArray(0)
        val s = BLOCK_SIZE
        var i = 0
        while (i + s < data.size) {
            val start = i
            val end = i + s - 1
            val newBlock = processBlockDecrypt(data.sliceArray(start..end), false, "PKCS7")
            if (newBlock != null) {
                plaintext += newBlock
            }
            i += s
        }
        if (i < data.size) {
            val newBlock = processBlockDecrypt(data.sliceArray(i..<data.size), true, "PKCS7")
            if (newBlock != null) {
                plaintext += newBlock
            }
        }

        if (plaintext[plaintext.size - 1] == plaintext[plaintext.size - 2]) {
            val pad = plaintext[plaintext.size - 1]
            val paddingSlice = plaintext.sliceArray(plaintext.size - pad..<plaintext.size)
            if (paddingSlice.isNotEmpty() && paddingSlice[0] == pad) {
                plaintext = plaintext.sliceArray(0..<(plaintext.size - pad))
            }
        }

        return plaintext
    }
}
