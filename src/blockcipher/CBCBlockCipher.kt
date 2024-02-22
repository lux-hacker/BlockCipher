package blockcipher

import units.xor
import javax.crypto.spec.SecretKeySpec

class CBCBlockCipher(key: SecretKeySpec) : AbstractBlockCipher(key) {
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
            copyData = copyData xor this.lastBlock!!

            val cipherBlock = blockCipherEncrypt(copyData)
            lastBlock = if (isFinalBlock) null else cipherBlock
            return cipherBlock
        }
        val copyData1 = copyData.sliceArray(0..<BLOCK_SIZE) xor this.lastBlock!!
        val cipherBlock1 = blockCipherEncrypt(copyData1)
        val copyData2 = copyData.sliceArray(BLOCK_SIZE..<2 * BLOCK_SIZE) xor cipherBlock1!!
        val cipherBlock2 = blockCipherEncrypt(copyData2)
        lastBlock = null
        return cipherBlock1!! + cipherBlock2!!
    }

    override fun processBlockDecrypt(
        data: ByteArray,
        isFinalBlock: Boolean,
        padding: String,
    ): ByteArray {
        var plaintext = blockCipherDecrypt(data)

        plaintext = plaintext!! xor this.lastBlock!!

        this.lastBlock = if (isFinalBlock) null else data
        return plaintext
    }
}
