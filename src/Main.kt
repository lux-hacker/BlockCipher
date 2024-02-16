@OptIn(ExperimentalStdlibApi::class)
fun main() {
    println("Enter plain text: ")
    val plaintext = readln()
//    val plaintext = "Hello world! Hello world! Hello world! Hello world! Hello world! Hello world! Hello world! Hello world!".toByteArray()
    println("Enter key: ")
    val key = readln()
//    val key = "ICIS{secret_key_for_our_text111}".toByteArray()

    val cipher = MyCipher()

    cipher.setKey(key.toByteArray())
    cipher.setMode("ECB")

    val ciphertext = cipher.encrypt(plaintext.toByteArray())
    println("Ciphertext: " + ciphertext.toHexString())

    val plaintext2 = cipher.decrypt(ciphertext)
    println("Plaintext : " + plaintext2.toString(Charsets.UTF_8))
}
