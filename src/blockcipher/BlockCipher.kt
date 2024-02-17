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
//            "CFB" -> this.mode = CipherMode.CFB
//            "OFB" -> this.mode = CipherMode.OFB
//            "CTR" -> this.mode = CipherMode.CTR
            else -> throw NotExistModeException("This mode is not supported")
        }
    }

    private fun generateIV(): ByteArray {
        val secureRandom = SecureRandom.getInstanceStrong()
        val iv = ByteArray(AbstractBlockCipher.BLOCK_SIZE)
        secureRandom.nextBytes(iv)
        return iv
    }

    fun encrypt(
        data: ByteArray,
        iv: ByteArray?,
    ): ByteArray {
        if (iv == null) {
            val newIv = generateIV()
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
