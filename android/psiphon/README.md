# Psiphon Android library

`:app` consumes `:psiphon`, a pass-through artifact for
`android/psiphon/libs/ca.psiphon.aar`. The Android CI jobs build this file
from the pinned `core/psiphon` submodule, using that revision's Dockerfile,
vendored gomobile, Go and NDK. They verify all four ABI libraries have 16 KB
ELF LOAD alignment. The AAR is consumed locally by the Android app build;
it is not uploaded as a workflow artifact or a standalone release asset.

CI mounts both the submodule source and its resolved Git metadata directory
(read-only) into Docker. Explicit `GIT_DIR` and `GIT_WORK_TREE` let upstream's
`make.bash` read its build revision without following the submodule's `.git`
pointer outside the source mount. The checkout and container HEAD must match
FCAE's `HEAD:core/psiphon` gitlink; no separate upstream checkout or branch-tip
update is used.

For local APK builds, follow `core/psiphon/MobileLibrary/Android/README.md`
to build the pinned source and copy its `ca.psiphon.aar` to the path above.
No Maven prebuilt fallback is used.

Psiphon runs as a bound-only service in `:psiphon`, separate from the
application's tun2socks Go runtime. `ProxyNotification` owns the startup/proxy
notification and hands it to `FCAEVpnService` in TUN mode. Psiphon's service
never calls Android notification or foreground-service APIs. Owner teardown
releases the binding; native stop runs off the main thread.
