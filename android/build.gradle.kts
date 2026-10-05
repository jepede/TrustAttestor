plugins {
    id("com.android.application") version "8.7.2" apply false
    id("com.android.library") version "8.7.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.lsposed.lsplugin.apksign") version "1.4" apply false
}

val androidSourceCompatibility by extra(JavaVersion.VERSION_17)
val androidTargetCompatibility by extra(JavaVersion.VERSION_17)

val configuredBuildRoot = providers.gradleProperty("trustAttestorBuildRoot").orNull
    ?: System.getenv("TRUST_ATTESTOR_BUILD_ROOT")
    ?: projectDir.parentFile.parentFile
        .resolve("${projectDir.parentFile.name}-build")
        .absolutePath
val externalBuildRoot = file(configuredBuildRoot).canonicalFile
check(!externalBuildRoot.toPath().startsWith(projectDir.parentFile.canonicalFile.toPath())) {
    "trustAttestorBuildRoot must be outside the repository: $externalBuildRoot"
}

// AGP modules otherwise default to <module>/build. Set every module before
// Android/Kotlin tasks are realized so generated sources, DEX, mappings and
// APKs all share the external build root.
allprojects {
    val moduleName = if (path == ":") "root" else path.substring(1).replace(':', '/')
    layout.buildDirectory.set(externalBuildRoot.resolve("android/$moduleName"))
}

subprojects {
    plugins.withType(JavaPlugin::class.java) {
        extensions.configure(JavaPluginExtension::class.java) {
            sourceCompatibility = androidSourceCompatibility
            targetCompatibility = androidTargetCompatibility
        }
    }
}
