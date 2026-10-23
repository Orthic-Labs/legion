plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "com.example.app"
    compileSdk = 35
    flavorDimensions += "device"
    productFlavors {
        create("phone") { dimension = "device" }
        create("tablet") { dimension = "device" }
    }
}
