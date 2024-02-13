package CipherMode

import javax.crypto.spec.SecretKeySpec

class ECBBlockCipher(private val key: SecretKeySpec, private val iv: ByteArray): AbstractBlockCipher(key, iv) {
    override fun processBlockEncrypt(data: ByteArray, isFinalBlock: Boolean, padding: String): ByteArray? {
        if (isFinalBlock){
            val delta = key.encoded.size - data.size
            val paddingBytes = ByteArray(delta)
            for (i in 0..delta) {
                paddingBytes.plus(delta.toByte())
            }
            data.plus(paddingBytes)
        }
        this.lastBlock = blockCipherEncrypt(data)
        return this.lastBlock
    }

    override fun processBlockDecrypt(data: ByteArray, isFinalBlock: Boolean, padding: String): ByteArray? {
        if (isFinalBlock){
            val delta = key.encoded.size - data.size
            val paddingBytes = ByteArray(delta)
            for (i in 0..delta) {
                paddingBytes.plus(delta.toByte())
            }
            data.plus(paddingBytes)
        }
        this.lastBlock = blockCipherEncrypt(data)
        return this.lastBlock
    }

    override fun encrypt(data: ByteArray, iv: ByteArray?): ByteArray {
        val ciphertext: ByteArray = ByteArray(0)
        val s = this.key.encoded.size
        for(i in 0..(data.size - s) step s){
            var newBlock = processBlockEncrypt(data.sliceArray(i..(i+s)), false, "PSC7")
            if (newBlock != null) {
                ciphertext.plus(newBlock)
            }
        }
        var newBlock = processBlockEncrypt(data.sliceArray((data.size - s)..data.size), true, "PSC7")
        if (newBlock != null) {
            ciphertext.plus(newBlock)
        }

        return ciphertext
    }

    override fun decrypt(data: ByteArray, iv: ByteArray?): ByteArray {
        val ciphertext: ByteArray = ByteArray(0)
        val s = this.key.encoded.size
        for(i in 0..(data.size - s) step s){
            var newBlock = processBlockDecrypt(data.sliceArray(i..(i+s)), false, "PSC7")
            if (newBlock != null) {
                ciphertext.plus(newBlock)
            }
        }
        var newBlock = processBlockDecrypt(data.sliceArray((data.size - s)..data.size), true, "PSC7")
        if (newBlock != null) {
            ciphertext.plus(newBlock)
        }

        return ciphertext
    }
}