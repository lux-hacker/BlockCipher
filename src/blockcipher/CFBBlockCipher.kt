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
            if (copyData.size == BLOCK_SIZE * 2)
                {
                    val gamma1 = blockCipherEncrypt(lastBlock!!)
                    val newBlock1 = gamma1!! xor copyData.sliceArray(0..<BLOCK_SIZE)
                    val gamma2 = blockCipherEncrypt(newBlock1)
                    val newBlock2 = gamma2!! xor copyData.sliceArray(BLOCK_SIZE..<2 * BLOCK_SIZE)
                    lastBlock = null
                    return newBlock1 + newBlock2
                } else {
                val gamma = blockCipherEncrypt(lastBlock!!)
                val newBlock = gamma!! xor copyData
                lastBlock = null
                return newBlock
            }
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
