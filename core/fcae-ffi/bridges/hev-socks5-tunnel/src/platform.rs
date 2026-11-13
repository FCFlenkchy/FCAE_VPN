//! Windows Wintun staging for the HEV engine (the engine LoadLibraryExW's
//! "wintun.dll" from the application directory or System32). The admin/root
//! probe lives in [`fcae_runtime::privilege`]; the DLL loader itself lives in
//! [`fcae_runtime::windows_dll`].

fcae_runtime::wintun_bytes!(pub "FCAE_HEV_WINTUN_DLL");
