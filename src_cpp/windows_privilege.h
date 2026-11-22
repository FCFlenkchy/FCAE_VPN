#pragma once
#if defined(_WIN32)
#include <windows.h>

// Check the process token, not an impersonation token on a library worker.
// Enabled Administrators membership also covers non-split tokens (UAC off).
inline bool fcae_windows_process_admin(HANDLE process) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation = {};
    DWORD size = 0;
    const bool elevated = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)
        && elevation.TokenIsElevated != 0;
    bool member = false;
    if (!elevated) {
        CloseHandle(token); token = nullptr;
        if (!OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &token)) return false;
        HANDLE impersonation = nullptr;
        if (DuplicateToken(token, SecurityIdentification, &impersonation)) {
            SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
            PSID administrators = nullptr;
            if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                    DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators)) {
                BOOL enabled = FALSE;
                member = CheckTokenMembership(impersonation, administrators, &enabled) && enabled;
                FreeSid(administrators);
            }
            CloseHandle(impersonation);
        }
    }
    CloseHandle(token);
    return elevated || member;
}
#endif
