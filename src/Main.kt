import blockcipher.BlockCipher
import units.decodeHex

@OptIn(ExperimentalStdlibApi::class)
fun main() {
//    println("Enter plain text: ")
//    val plaintext = readln()
//    println("Enter key: ")
//    val key = readln()

//    val myCipher = BlockCipher()
//    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
//    val secretKey = SecretKeySpec(key.toByteArray(), "AES")
//    cipher.init(Cipher.ENCRYPT_MODE, secretKey)

//    myCipher.setKey(key.toByteArray())
//    myCipher.setMode("ECB")

//    val myCiphertext = myCipher.encrypt(plaintext.toByteArray(), null)
//    val ciphertext = cipher.doFinal(plaintext.toByteArray())
//    println("my Ciphertext: " + myCiphertext.toHexString())
//    println("   Ciphertext: " + ciphertext.toHexString())

//    val plaintext2 = myCipher.decrypt(myCiphertext, null)
//    println("Plaintext : " + plaintext2.toString(Charsets.UTF_8))
    println("Enter ciphertext: ")
    val ciphertext = readln()
    val byte_ciphertext = ciphertext.decodeHex()
    println("Enter key: ")
    val key = readln()
    val cipher = BlockCipher()

    cipher.setKey(key.decodeHex())
    cipher.setMode("CBC")
// qwertyuiopasdfghjklzxcvbnmqwerty
    val plaintext2 = cipher.decrypt(byte_ciphertext, null)
    println("Plaintext : " + plaintext2.toString(Charsets.US_ASCII))
}
