package blockcipher

import javax.crypto.spec.SecretKeySpec

class ECBBlockCipher(key: SecretKeySpec) : AbstractBlockCipher(key) {
    override fun processBlockEncrypt(
        data: ByteArray,
        isFinalBlock: Boolean,
        padding: String,
    ): ByteArray? {
        var copyData: ByteArray = data
        if (isFinalBlock) {
            copyData = paddingData(data)
        }
        if (copyData.size != 2 * BLOCK_SIZE) {
            val cipherBlock = blockCipherEncrypt(copyData)
            lastBlock = if (isFinalBlock) null else cipherBlock
            return cipherBlock
        }
        val cipherBlock1 = blockCipherEncrypt(copyData.sliceArray(0..<BLOCK_SIZE))
        val cipherBlock2 = blockCipherEncrypt(copyData.sliceArray(BLOCK_SIZE..<2 * BLOCK_SIZE))
        lastBlock = null
        return cipherBlock1!! + cipherBlock2!!
    }

    override fun processBlockDecrypt(
        data: ByteArray,
        isFinalBlock: Boolean,
        padding: String,
    ): ByteArray? {
        val plainBlock = blockCipherDecrypt(data)
        lastBlock = if (isFinalBlock) null else plainBlock
        return plainBlock
    }
}
