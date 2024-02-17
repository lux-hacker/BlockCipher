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

        this.lastBlock = blockCipherEncrypt(copyData)
        return this.lastBlock
    }

    override fun processBlockDecrypt(
        data: ByteArray,
        isFinalBlock: Boolean,
        padding: String,
    ): ByteArray {
        var plaintext = blockCipherDecrypt(data)

        plaintext = plaintext!! xor this.lastBlock!!

        this.lastBlock = data
        return plaintext
    }

    override fun encrypt(
        data: ByteArray,
        iv: ByteArray?,
    ): ByteArray {
        var ciphertext = super.encrypt(data, iv)
        ciphertext = iv!! + ciphertext
        return ciphertext
    }
}
