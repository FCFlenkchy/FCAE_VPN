# Psiphon Go shim (desktop)

C-ABI wrapper around `MobileLibrary/psi`. Built as its **own** Go module so
it does not share a runtime with tun2socks.

| Platform | How Psiphon runs |
| --- | --- |
| Android | Official `.aar` (`android/psiphon`). **Not this directory.** |
| Desktop | This module, `-buildmode=c-archive` with `force_shared`, only when `fcae-bridge-psiphon/enabled` is on. |

Do not compile psi into `libfcae_go_bridge.so`. Two Go runtimes in one
Android process crash at `dlopen`. `ClientLibrary` has no `BindToDevice`
and cannot work on Android.

The `enabled` feature is off. Nothing here is built.
