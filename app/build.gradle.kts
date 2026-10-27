plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.gpgapp"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.gpgapp"
        minSdk = 26
        targetSdk = 34
        versionCode = 200
        versionName = "2.0.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    dependenciesInfo {
        // Disable dependency metadata in APK Signing Block.
        // F-Droid scanner rejects extra signing blocks, so this must be off.
        includeInApk = false
    }

    packaging {
        resources {
            // The Bouncy Castle jars are multi-release: bcprov, bcpg and bcutil each ship an
            // OSGI manifest under META-INF/versions/9, which collides at packaging time.
            // Android runs the base classes, so the whole versioned tree is dead weight.
            excludes += "META-INF/versions/**"
            excludes += "META-INF/LICENSE*"
            excludes += "META-INF/NOTICE*"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    kotlinOptions {
        jvmTarget = "21"
    }

    buildFeatures {
        compose = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.8"
    }
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    // Compose BOM
    val composeBom = platform("androidx.compose:compose-bom:2024.02.00")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.7.0")
    implementation("androidx.activity:activity-compose:1.8.2")

    // Compose UI
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // Navigation
    implementation("androidx.navigation:navigation-compose:2.7.7")

    // Bouncy Castle for PGP.
    // 1.77 is affected by CVE-2026-3505 / GHSA-cj8j-37rh-8475 (unbounded OpenPGP AEAD
    // chunk size, fixed upstream in 1.84). Keep this at 1.84 or newer.
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    implementation("org.bouncycastle:bcpg-jdk18on:1.86")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")

    debugImplementation("androidx.compose.ui:ui-tooling")

    // Host-side unit tests for the OpenPGP layer (run with ./gradlew :app:testDebugUnitTest)
    testImplementation("junit:junit:4.13.2")
}
