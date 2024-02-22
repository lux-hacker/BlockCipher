import blockcipher.BlockCipher
import units.decodeHex

@OptIn(ExperimentalStdlibApi::class)
fun main() {
//    println("Enter plain text: ")
//    val plaintext = readln()
    println("Enter key: ")
    val key = readln()
//
    val myCipher = BlockCipher()
//
    myCipher.setKey(key.decodeHex())
    myCipher.setMode("CTR")
//
//    val myCiphertext = myCipher.encrypt(plaintext.toByteArray(), null)
//    println("Ciphertext: " + myCiphertext.toHexString())
//
//    val plaintext2 = myCipher.decrypt(myCiphertext, null)
//    println("Plaintext : " + plaintext2.toString(Charsets.UTF_8))

    println("Enter ciphertext:")
    val ciphertext = readln().decodeHex()
    val plaintext = myCipher.decrypt(ciphertext, null).toString(Charsets.US_ASCII)
    println("Plaintext : $plaintext")
}
