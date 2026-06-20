plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.deskaccess.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.deskaccess.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = project.findProperty("appVersion")?.toString() ?: "0.1.0"
    }
}
