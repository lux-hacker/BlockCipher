package ciphermode

interface BlockCipherable {
    fun processBlockEncrypt(
        data: ByteArray,
        isFinalBlock: Boolean,
        padding: String,
    ): ByteArray?

    fun encrypt(
        data: ByteArray,
        iv: ByteArray? = null,
    ): ByteArray

    fun processBlockDecrypt(
        data: ByteArray,
        isFinalBlock: Boolean,
        padding: String,
    ): ByteArray?

    fun decrypt(
        data: ByteArray,
        iv: ByteArray? = null,
    ): ByteArray
}
