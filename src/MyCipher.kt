import blockcipherexception.NotExistModeException
import blockcipherexception.SmallKeySizeException
import ciphermode.AbstractBlockCipher
import ciphermode.ECBBlockCipher
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

class MyCipher() {
    private lateinit var key: SecretKeySpec
    private lateinit var mode: AbstractBlockCipher
    private lateinit var iv: ByteArray

    fun setKey(key: ByteArray) {
        if (key.size != AbstractBlockCipher.AES_KEY_SIZE) {
            throw SmallKeySizeException("Invalid key size, expecting ${AbstractBlockCipher.AES_KEY_SIZE}")
        }
        this.key = SecretKeySpec(key, "AES")
    }

    fun setMode(mode: String) {
        when (mode) {
            "ECB" -> this.mode = ECBBlockCipher(this.key)
//            "CBC" -> this.mode = CBCBlockCipher(this.key)
//            "CFB" -> this.mode = CipherMode.CFB
//            "OFB" -> this.mode = CipherMode.OFB
//            "CTR" -> this.mode = CipherMode.CTR
            else -> throw NotExistModeException("This mode is not supported")
        }
    }

    private fun generateIV() {
        val secureRandom = SecureRandom.getInstanceStrong()
        this.iv = ByteArray(AbstractBlockCipher.BLOCK_SIZE)
        secureRandom.nextBytes(iv)
    }

    fun encrypt(data: ByteArray): ByteArray {
        generateIV()
        return this.mode.encrypt(data, this.iv)
    }

    fun decrypt(data: ByteArray): ByteArray {
        generateIV()
        return this.mode.decrypt(data, this.iv)
    }
}
