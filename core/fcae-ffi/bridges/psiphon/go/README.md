# Psiphon Go shim (desktop)

C-ABI wrapper around `MobileLibrary/psi`. Built as its **own** Go module so
it does not share a runtime with tun2socks.

| Platform | How Psiphon runs |
| --- | --- |
| Android | Official `.aar` (`android/psiphon`). **Not this directory.** |
| Desktop | This module, `-buildmode=c-shared` (`force_shared`) as `libfcae_psiphon`, when `psiphon-live` is on. |

Do not compile psi into `libfcae_go_bridge.so`. Two Go runtimes in one
Android process crash at `dlopen`. Two static Go archives in one desktop
binary fail the link. `ClientLibrary` has no `BindToDevice` and cannot
work on Android.
