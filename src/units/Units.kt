package units

import kotlin.experimental.xor
import kotlin.math.min

infix fun ByteArray.xor(x: ByteArray): ByteArray {
    val answer = ByteArray(min(this.size, x.size))
    for (i in 0..<min(this.size, x.size)) {
        answer[i] = this[i] xor x[i]
    }
    return answer
}

fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }

    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}
