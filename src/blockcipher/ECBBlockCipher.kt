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
        val cipherBlock = blockCipherEncrypt(copyData)
        lastBlock = if (isFinalBlock) null else cipherBlock
        return cipherBlock
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
