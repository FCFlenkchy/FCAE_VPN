// Pass-through module that exposes the CI-built Psiphon AAR
// (core/psiphon build -> android/psiphon/libs/ca.psiphon.aar) as a module
// dependency for :app.
//
// This module must NOT apply com.android.library: AGP refuses to build a
// library AAR that has a direct local .aar file dependency (the old
// `:psiphon` library module died at :psiphon:bundleReleaseAar with
// "Direct local .aar file dependencies are not supported when building an
// AAR"). Instead the aar is declared as this project's only artifact, so
// `implementation(project(":psiphon"))` resolves it as a plain file
// artifact: classes, jni (libgojni.so), manifest and assets merge into
// the app exactly as a files(...) dependency would, but through proper
// project wiring (build order, task graph, IDE model).
configurations.maybeCreate("default")
artifacts.add("default", file("libs/ca.psiphon.aar"))
