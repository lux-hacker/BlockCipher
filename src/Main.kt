import blockcipher.BlockCipher

@OptIn(ExperimentalStdlibApi::class)
fun main() {
    println("Enter plain text: ")
    val plaintext = readln()
    println("Enter key: ")
    val key = readln()

    val myCipher = BlockCipher()

    myCipher.setKey(key.toByteArray())
    myCipher.setMode("CFB")

    val myCiphertext = myCipher.encrypt(plaintext.toByteArray(), null)
    println("Ciphertext: " + myCiphertext.toHexString())

    val plaintext2 = myCipher.decrypt(myCiphertext, null)
    println("Plaintext : " + plaintext2.toString(Charsets.UTF_8))
}
