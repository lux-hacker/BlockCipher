package blockcipher

import blockcipherexception.NotExistModeException
import blockcipherexception.SmallKeySizeException
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

class BlockCipher() {
    private lateinit var key: SecretKeySpec
    private lateinit var mode: AbstractBlockCipher

    fun setKey(key: ByteArray) {
        if (key.size !in AbstractBlockCipher.AES_KEY_SIZE) {
            throw SmallKeySizeException("Invalid key size, expecting ${AbstractBlockCipher.AES_KEY_SIZE}")
        }
        this.key = SecretKeySpec(key, "AES")
    }

    fun setMode(mode: String) {
        when (mode) {
            "ECB" -> this.mode = ECBBlockCipher(this.key)
            "CBC" -> this.mode = CBCBlockCipher(this.key)
            "CFB" -> this.mode = CFBBlockCipher(this.key)
            "OFB" -> this.mode = OFBBlockCipher(this.key)
            "CTR" -> this.mode = CTRBlockCipher(this.key)
            else -> throw NotExistModeException("This mode is not supported")
        }
    }

    private fun generateIV(size: Int): ByteArray {
        val secureRandom = SecureRandom.getInstanceStrong()
        val iv = ByteArray(size)
        secureRandom.nextBytes(iv)
        return iv
    }

    fun encrypt(
        data: ByteArray,
        iv: ByteArray?,
    ): ByteArray {
        if (iv == null) {
            var newIv: ByteArray
            if (this.mode !is CTRBlockCipher) {
                newIv = generateIV(AbstractBlockCipher.BLOCK_SIZE)
            } else {
                newIv = generateIV(AbstractBlockCipher.NONCE_SIZE)
                for (i in 0..<(AbstractBlockCipher.BLOCK_SIZE - AbstractBlockCipher.NONCE_SIZE)) {
                    newIv += 0
                }
            }
            return this.mode.encrypt(data, newIv)
        }
        return this.mode.encrypt(data, iv)
    }

    fun decrypt(
        data: ByteArray,
        iv: ByteArray?,
    ): ByteArray {
        if (this.mode !is ECBBlockCipher) {
            val newIv = data.sliceArray(0..<AbstractBlockCipher.BLOCK_SIZE)
            val realData = data.sliceArray(AbstractBlockCipher.BLOCK_SIZE..<data.size)
            return this.mode.decrypt(realData, newIv)
        }
        return this.mode.decrypt(data, iv)
    }
}
