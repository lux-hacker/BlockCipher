package blockcipher

import units.xor
import javax.crypto.spec.SecretKeySpec

class CFBBlockCipher(key: SecretKeySpec) : AbstractBlockCipher(key) {
    override fun processBlockEncrypt(
        data: ByteArray,
        isFinalBlock: Boolean,
        padding: String,
    ): ByteArray {
        if (!isFinalBlock) {
            val gamma = blockCipherEncrypt(lastBlock!!)
            val newBlock = gamma!! xor data
            lastBlock = newBlock
            return newBlock
        } else if (padding == "PKCS7") {
            val copyData = paddingData(data)
            val gamma = blockCipherEncrypt(lastBlock!!)
            val newBlock = gamma!! xor copyData
            lastBlock = null
            return newBlock
        } else {
            val gamma = blockCipherEncrypt(lastBlock!!)
            val newBlock = gamma!! xor data
            lastBlock = null
            return newBlock
        }
    }

    override fun processBlockDecrypt(
        data: ByteArray,
        isFinalBlock: Boolean,
        padding: String,
    ): ByteArray {
        if (!isFinalBlock) {
            val gamma = blockCipherEncrypt(lastBlock!!)
            val newBlock = gamma!! xor data
            lastBlock = data
            return newBlock
        } else {
            val gamma = blockCipherEncrypt(lastBlock!!)
            val newBlock = gamma!! xor data
            lastBlock = null
            return newBlock
        }
    }
}
