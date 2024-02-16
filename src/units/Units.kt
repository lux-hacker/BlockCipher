package units

infix fun Byte.xor(x: Byte): Byte {
    val a = this.toInt()
    val b = x.toInt()
    val c = (a + b) % 2
    return c.toByte()
}
