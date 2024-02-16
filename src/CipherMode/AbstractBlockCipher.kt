package CipherMode

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

abstract class AbstractBlockCipher(private val key: SecretKeySpec) : BlockCipherable {
    private val cipher: Cipher = Cipher.getInstance("AES/ECB/NoPadding")
    protected var lastBlock: ByteArray? = null

    companion object {
        const val AES_KEY_SIZE = 32
        const val BLOCK_SIZE = 16
    }

    fun blockCipherEncrypt(data: ByteArray): ByteArray? {
        cipher.init(Cipher.ENCRYPT_MODE, this.key)
        return cipher.doFinal(data)
    }

    fun blockCipherDecrypt(data: ByteArray): ByteArray? {
        cipher.init(Cipher.DECRYPT_MODE, this.key)
        return cipher.doFinal(data)
    }
}
