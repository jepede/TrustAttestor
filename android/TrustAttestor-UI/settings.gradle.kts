pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "TrustAttestor-UI"
include(":app")

val configuredBuildRoot = providers.gradleProperty("trustAttestorBuildRoot").orNull
    ?: System.getenv("TRUST_ATTESTOR_BUILD_ROOT")
    ?: rootDir.parentFile.parentFile.parentFile
        .resolve("TrustAttestor-build/ui")
        .absolutePath
val externalBuildRoot = file(configuredBuildRoot).canonicalFile
val repositoryRoot = if (rootDir.parentFile.name == "android") {
    rootDir.parentFile.parentFile.canonicalFile
} else {
    rootDir.canonicalFile
}
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
