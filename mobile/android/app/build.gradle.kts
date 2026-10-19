plugins {
    id("com.android.application")
}

android {
    namespace = "com.karmanya03.cinder"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.karmanya03.cinder"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }

    // The source logo is the repository asset of record. Its historical .png
    // name contains JPEG bytes; keeping the copy task here avoids a second
    // hand-edited icon that could drift from the desktop branding.
    tasks.register<Copy>("syncCinderLogo") {
        from("../../assets/Cinder-Logo.png")
        into("src/main/res/drawable")
        rename { "cinder_logo.jpg" }
    }
    tasks.named("preBuild") { dependsOn("syncCinderLogo") }
}
