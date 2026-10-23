package com.example

class Smelly {
    fun swallow(block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
        }
    }

    fun timeoutMs(): Long = 4242L
}
