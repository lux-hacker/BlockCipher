import CipherMode.CipherMode
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

class MyCipher() {
    private lateinit var key: SecretKeySpec
    private lateinit var mode: CipherMode
    private lateinit var iv: ByteArray
    private var blockSize: Int = 0

    fun setKey(key: ByteArray){
        this.key = SecretKeySpec(key, "AES")
        this.blockSize = key.size
    }

    fun setMode(mode: String){
        when(mode) {
            "ECB" -> this.mode = CipherMode.ECB
            "CBC" -> this.mode = CipherMode.CBC
            "CFB" -> this.mode = CipherMode.CFB
            "OFB" -> this.mode = CipherMode.OFB
            "CTR" -> this.mode = CipherMode.CTR
            else -> throw NotExistModeException("This mode is not supported")
        }
    }

    private fun generateIV(){
        val secureRandom = SecureRandom.getInstanceStrong()
        this.iv = ByteArray(this.blockSize)
        secureRandom.nextBytes(iv)
    }
}