package CipherMode

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

abstract class AbstractBlockCipher(private val key: SecretKeySpec, private val iv: ByteArray): BlockCipherable {
    private val cipher: Cipher = Cipher.getInstance("AES/ECB/NoPadding")
    protected var lastBlock: ByteArray? = null

    fun blockCipherEncrypt(data: ByteArray): ByteArray? {
        cipher.init(Cipher.ENCRYPT_MODE, this.key)
        return cipher.doFinal(data)
    }

    fun blockCipherDecrypt(data: ByteArray): ByteArray? {
        cipher.init(Cipher.DECRYPT_MODE, this.key)
        return cipher.doFinal(data)
    }

    override fun encrypt(data: ByteArray, iv: ByteArray?): ByteArray? {

    }

    override fun decrypt(data: ByteArray, iv: ByteArray?): ByteArray? {
        TODO("Not yet implemented")
    }
}