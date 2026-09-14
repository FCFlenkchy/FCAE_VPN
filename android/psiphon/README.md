# Android Psiphon (official AAR)

This is the Android Psiphon integration point. It is **not** part of the
Gradle graph (`settings.gradle.kts` does not `include(":psiphon")`) and
is **not compiled**.

## Why an AAR

Psiphon's Android library is `MobileLibrary/psi`, distributed as
`ca.psiphon.aar` / Maven `ca.psiphon:psiphontunnel`. That is a gomobile
binding with `Start` / `Stop` / `BindToDevice`.

What does **not** work:

- `ClientLibrary` — no `BindToDevice`, sockets get captured by our TUN.
- Linking `psi` into tun2socks' Go c-shared (`libfcae_go_bridge.so`).
- Loading a second Go runtime next to tun2socks — SIGSEGV at `dlopen`.

## Re-enable later

1. `include(":psiphon")` in `android/settings.gradle.kts`
2. `implementation(project(":psiphon"))` in the app module
3. Uncomment the Maven/AAR line in `build.gradle.kts`
4. Keep `fcae-bridge-psiphon/enabled` off for the Android cargo build
