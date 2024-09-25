import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
}

kotlin {
    apply(from = rootProject.file("gradle/compile-native-multiplatform.gradle"))

    sourceSets {
        all {
            dependencies {
                api("org.jetbrains.kotlinx:kotlinx-serialization-core:${extra.get("serialization")}")
                api("org.jetbrains.kotlinx:kotlinx-serialization-protobuf:${extra.get("serialization")}")
            }
        }
    }

    targets.configureEach {
        if (this !is KotlinNativeTarget) return@configureEach

        binaries {
            executable {
                entryPoint("me.him188.maven.central.publish.generator.main")
            }
        }
    }
}