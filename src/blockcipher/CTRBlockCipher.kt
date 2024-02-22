package blockcipher

import units.decodeHex
import units.xor
import javax.crypto.spec.SecretKeySpec

class CTRBlockCipher(key: SecretKeySpec) : AbstractBlockCipher(key) {
    @OptIn(ExperimentalStdlibApi::class)
    private fun incNonce() {
        val nonce = lastBlock!!.sliceArray(0..<NONCE_SIZE + IV_SIZE)
        var counter = lastBlock!!.sliceArray(NONCE_SIZE + IV_SIZE..<BLOCK_SIZE)
        val intCounter = counter.toHexString().toUInt(16) + 1u
        var hexCounter = intCounter.toHexString()
        if (hexCounter.length < BLOCK_SIZE - NONCE_SIZE - IV_SIZE) {
            val c = (BLOCK_SIZE - NONCE_SIZE - IV_SIZE) - hexCounter.length
            for (i in 0..<c) {
                hexCounter = "0$hexCounter"
            }
        }
        counter = hexCounter.decodeHex()
        lastBlock = nonce + counter
    }

    override fun processBlockEncrypt(
        data: ByteArray,
        isFinalBlock: Boolean,
        padding: String,
    ): ByteArray {
        var gamma = blockCipherEncrypt(lastBlock!!)
        var copyData = data
        if (isFinalBlock) {
            if (padding == "PKCS7") {
                copyData = paddingData(data)
            }
            lastBlock = null
        }
        if (copyData.size == 2 * BLOCK_SIZE)
            {
                val cipherBlock1 = gamma!! xor copyData.sliceArray(0..<BLOCK_SIZE)
                incNonce()
                gamma = blockCipherEncrypt(lastBlock!!)
                val cipherBlock2 = gamma!! xor copyData.sliceArray(BLOCK_SIZE..<2 * BLOCK_SIZE)
                return cipherBlock1 + cipherBlock2
            }
        val cipherBlock = gamma!! xor copyData
        if (!isFinalBlock) incNonce()
        return cipherBlock
    }

    override fun processBlockDecrypt(
        data: ByteArray,
        isFinalBlock: Boolean,
        padding: String,
    ): ByteArray {
        val gamma = blockCipherEncrypt(lastBlock!!)
        if (isFinalBlock) {
            lastBlock = null
        }
        val cipherBlock = gamma!! xor data
        if (!isFinalBlock) incNonce()
        return cipherBlock
    }
}
