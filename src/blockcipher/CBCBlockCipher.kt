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

        copyData = copyData xor this.lastBlock!!

        val cipherBlock = blockCipherEncrypt(copyData)
        lastBlock = if (isFinalBlock) null else cipherBlock
        return cipherBlock
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
