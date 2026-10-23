package com.example

import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val web = WebView(this)
        web.settings.setJavaScriptEnabled(true)
        web.addJavascriptInterface(Bridge(), "bridge")
        web.loadUrl("http://example.com/start")
    }
}

class Bridge
