package fixture

class Screen {
    fun titleResource(): Int {
        return R.string.screen_title
    }

    fun renderCount(items: List<Int>): Int {
        var total = 0
        for (item in items) {
            total += item
        }
        return total
    }
}
