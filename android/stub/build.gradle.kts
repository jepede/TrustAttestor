plugins {
    id("com.android.library")
}

fun requiredGradleProperty(name: String): String =
    providers.gradleProperty(name).orNull
        ?: throw GradleException("Missing required Gradle property: $name")

val pinnedCompileSdk = requiredGradleProperty("trustAttestor.android.compileSdk").toInt()
val pinnedMinSdk = requiredGradleProperty("trustAttestor.android.minSdk").toInt()

android {
    namespace = "io.github.a13e300.stub"
    compileSdk = pinnedCompileSdk

    defaultConfig {
        minSdk = pinnedMinSdk

        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}
