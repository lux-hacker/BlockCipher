package blockcipher

import javax.crypto.spec.SecretKeySpec

class ECBBlockCipher(private val key: SecretKeySpec) : AbstractBlockCipher(key) {
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

    override fun encrypt(
        data: ByteArray,
        iv: ByteArray?,
    ): ByteArray {
        var ciphertext = ByteArray(0)
        val s = BLOCK_SIZE
        var i = 0
        while (i + s < data.size) {
            val start = i
            val end = i + s - 1
            val newBlock = processBlockEncrypt(data.sliceArray(start..end), false, "PSC7")
            if (newBlock != null) {
                ciphertext += newBlock
            }
            i += s
        }
        val newBlock = processBlockEncrypt(data.sliceArray(i..<data.size), true, "PSC7")
        if (newBlock != null) {
            ciphertext += newBlock
        }

        return ciphertext
    }

    override fun decrypt(
        data: ByteArray,
        iv: ByteArray?,
    ): ByteArray {
        var plaintext = ByteArray(0)
        val s = BLOCK_SIZE
        var i = 0
        while (i + s < data.size) {
            val start = i
            val end = i + s - 1
            val newBlock = processBlockDecrypt(data.sliceArray(start..end), false, "PSC7")
            if (newBlock != null) {
                plaintext += newBlock
            }
            i += s
        }
        val newBlock = processBlockDecrypt(data.sliceArray(i..<data.size), true, "PSC7")
        if (newBlock != null) {
            plaintext += newBlock
        }

        val pad = plaintext[plaintext.size - 1]
        if (pad.toInt() < plaintext.size) {
            val paddingSlice = plaintext.sliceArray(plaintext.size - pad..<plaintext.size)
            if (paddingSlice[0] == pad) {
                plaintext = plaintext.sliceArray(0..<(plaintext.size - pad))
            }
        }

        return plaintext
    }
}
