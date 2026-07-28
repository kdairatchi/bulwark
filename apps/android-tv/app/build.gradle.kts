import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.bulwark.tv"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.bulwark.tv"
        minSdk = 26
        targetSdk = 34
        // CI can override via BULWARK_TV_VERSION_CODE / BULWARK_TV_VERSION_NAME
        versionCode = System.getenv("BULWARK_TV_VERSION_CODE")?.toIntOrNull() ?: 1
        versionName = System.getenv("BULWARK_TV_VERSION_NAME")?.takeIf { it.isNotBlank() } ?: "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Optional release signing — only applied when keystore.properties (or
    // BULWARK_TV_STORE_* env vars) is present. Without secrets, release builds
    // remain unsigned so CI / local debug keeps working.
    val keystorePropsFile = rootProject.file("keystore.properties")
    val keystoreProps = Properties()
    if (keystorePropsFile.exists()) {
        keystoreProps.load(FileInputStream(keystorePropsFile))
    }
    fun prop(name: String, env: String): String? =
        keystoreProps.getProperty(name)?.takeIf { it.isNotBlank() && it != "CHANGE_ME" }
            ?: System.getenv(env)?.takeIf { it.isNotBlank() }

    val storeFilePath = prop("storeFile", "BULWARK_TV_STORE_FILE")
    val storePassword = prop("storePassword", "BULWARK_TV_STORE_PASSWORD")
    val keyAlias = prop("keyAlias", "BULWARK_TV_KEY_ALIAS")
    val keyPassword = prop("keyPassword", "BULWARK_TV_KEY_PASSWORD")
    val hasReleaseSigning = listOf(storeFilePath, storePassword, keyAlias, keyPassword).all { it != null }

    if (hasReleaseSigning) {
        signingConfigs {
            create("release") {
                val store = file(storeFilePath!!)
                storeFile = if (store.isAbsolute) store else rootProject.file(storeFilePath)
                this.storePassword = storePassword
                this.keyAlias = keyAlias
                this.keyPassword = keyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    kotlinOptions {
        jvmTarget = "21"
        freeCompilerArgs += listOf(
            "-opt-in=androidx.tv.material3.ExperimentalTvMaterial3Api",
        )
    }
    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
            excludes += "META-INF/LICENSE*"
            excludes += "META-INF/NOTICE*"
        }
    }
}

dependencies {
    implementation(project(":core"))

    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.3")
    implementation("androidx.tv:tv-foundation:1.0.0-alpha10")
    implementation("androidx.tv:tv-material:1.0.0-alpha10")
    implementation("androidx.work:work-runtime-ktx:2.9.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
