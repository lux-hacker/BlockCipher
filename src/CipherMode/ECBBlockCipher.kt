package CipherMode

import javax.crypto.spec.SecretKeySpec

class ECBBlockCipher(private val key: SecretKeySpec, private val iv: ByteArray): AbstractBlockCipher(key, iv) {
    override fun processBlockEncrypt(data: ByteArray, isFinalBlock: Boolean, padding: String): ByteArray? {
        if (isFinalBlock){
            val delta = key.encoded.size - data.size
            val paddingBytes = ByteArray(delta)
            for (i in 0..delta) {
                paddingBytes.plus(delta.toByte())
            }
            data.plus(paddingBytes)
        }
        this.lastBlock = blockCipherEncrypt(data)
        return this.lastBlock
    }

    override fun processBlockDecrypt(data: ByteArray, isFinalBlock: Boolean, padding: String): ByteArray? {
        if (isFinalBlock){
            val delta = key.encoded.size - data.size
            val paddingBytes = ByteArray(delta)
            for (i in 0..delta) {
                paddingBytes.plus(delta.toByte())
            }
            data.plus(paddingBytes)
        }
        this.lastBlock = blockCipherEncrypt(data)
        return this.lastBlock
    }
}