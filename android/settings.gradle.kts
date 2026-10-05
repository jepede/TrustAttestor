pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath("net.fornwall:jelf:0.9.0")
    }
}

rootProject.name = "TrustAttestor"
include(":app", ":dex")
include(":stub")

// Keep Gradle's project cache outside the checkout. The wrapper supplies
// TRUST_ATTESTOR_BUILD_ROOT, while the sibling fallback also protects direct
// Gradle invocations from recreating android/.gradle.
val configuredBuildRoot = providers.gradleProperty("trustAttestorBuildRoot").orNull
    ?: System.getenv("TRUST_ATTESTOR_BUILD_ROOT")
    ?: rootDir.parentFile.parentFile
        .resolve("${rootDir.parentFile.name}-build")
        .absolutePath
val externalBuildRoot = file(configuredBuildRoot).canonicalFile
val repositoryRoot = rootDir.parentFile.canonicalFile
check(!externalBuildRoot.toPath().startsWith(repositoryRoot.toPath())) {
    "trustAttestorBuildRoot must be outside the repository: $externalBuildRoot"
}
gradle.startParameter.projectCacheDir = externalBuildRoot.resolve("gradle-project")

if (gradle.startParameter.projectProperties["kotlin.project.persistent.dir"] == null) {
    val properties = gradle.startParameter.projectProperties.toMutableMap()
    properties["kotlin.project.persistent.dir"] =
        externalBuildRoot.resolve("kotlin-project").absolutePath
    gradle.startParameter.projectProperties = properties
}
