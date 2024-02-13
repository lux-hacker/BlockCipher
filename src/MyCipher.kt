import CipherMode.AbstractBlockCipher
import CipherMode.CBCBlockCipher
import CipherMode.CipherMode
import CipherMode.ECBBlockCipher
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

class MyCipher() {
    private lateinit var key: SecretKeySpec
    private lateinit var mode: AbstractBlockCipher
    private lateinit var iv: ByteArray

    fun setKey(key: ByteArray){
        this.key = SecretKeySpec(key, "AES")
    }

    fun setMode(mode: String){
        when(mode) {
            "ECB" -> this.mode = ECBBlockCipher(this.key, this.iv)
            "CBC" -> this.mode = CBCBlockCipher(this.key, this.iv)
//            "CFB" -> this.mode = CipherMode.CFB
//            "OFB" -> this.mode = CipherMode.OFB
//            "CTR" -> this.mode = CipherMode.CTR
            else -> throw NotExistModeException("This mode is not supported")
        }
    }

    private fun generateIV(){
        val secureRandom = SecureRandom.getInstanceStrong()
        this.iv = ByteArray(this.key.encoded.size)
        secureRandom.nextBytes(iv)
    }
}