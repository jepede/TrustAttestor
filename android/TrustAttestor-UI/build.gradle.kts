plugins {
    id("com.android.application") version "8.7.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
}

val configuredBuildRoot = providers.gradleProperty("trustAttestorBuildRoot").orNull
    ?: System.getenv("TRUST_ATTESTOR_BUILD_ROOT")
    ?: projectDir.parentFile.parentFile.parentFile
        .resolve("TrustAttestor-build/ui")
        .absolutePath
val externalBuildRoot = file(configuredBuildRoot).canonicalFile
val repositoryRoot = if (projectDir.parentFile.name == "android") {
    projectDir.parentFile.parentFile.canonicalFile
} else {
    projectDir.canonicalFile
}
check(!externalBuildRoot.toPath().startsWith(repositoryRoot.toPath())) {
    "trustAttestorBuildRoot must be outside the repository: $externalBuildRoot"
}

allprojects {
    val moduleName = if (path == ":") "root" else path.substring(1).replace(':', '/')
    layout.buildDirectory.set(externalBuildRoot.resolve("$moduleName"))
}
