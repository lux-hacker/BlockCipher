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
        this.lastBlock = blockCipherEncrypt(copyData)
        return this.lastBlock
    }

    override fun processBlockDecrypt(
        data: ByteArray,
        isFinalBlock: Boolean,
        padding: String,
    ): ByteArray? {
        this.lastBlock = blockCipherDecrypt(data)
        return this.lastBlock
    }
}
