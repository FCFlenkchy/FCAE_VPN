# Psiphon Android library

`:app` consumes `:psiphon`, a pass-through artifact for
`android/psiphon/libs/ca.psiphon.aar`. The Android CI jobs build this file
from the pinned `core/psiphon` submodule, using that revision's Dockerfile,
vendored gomobile, Go and NDK. They verify all four ABI libraries have 16 KB
ELF LOAD alignment and upload the AAR as a separate artifact.

For local APK builds, first download the matching CI AAR to the path above,
or follow `core/psiphon/MobileLibrary/Android/README.md` to build that pinned
source and copy its `ca.psiphon.aar` here. No Maven prebuilt fallback is used.

Psiphon runs as a bound-only service in `:psiphon`, separate from the
application's tun2socks Go runtime. `ProxyNotification` owns the startup/proxy
notification and hands it to `FCAEVpnService` in TUN mode. Psiphon's service
never calls Android notification or foreground-service APIs. Owner teardown
releases the binding; native stop runs off the main thread.
