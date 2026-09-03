class Client(private val base: String) {
    fun url(path: String) = base + "/" + path
}
