package units

import kotlin.experimental.xor

infix fun ByteArray.xor(x: ByteArray): ByteArray {
    for (i in x.indices) {
        this[i] = this[i] xor x[i]
    }
    return this
}

fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }

    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}
