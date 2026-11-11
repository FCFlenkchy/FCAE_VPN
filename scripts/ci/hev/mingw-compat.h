#ifndef FCAE_HEV_MINGW_COMPAT_H
#define FCAE_HEV_MINGW_COMPAT_H

#ifndef __ASSEMBLER__
/* HEV's Windows header supplies an MSVC mode_t when _MODE_T_DEFINED is
 * absent. MinGW uses a different guard and already supplies mode_t. */
#include <sys/types.h>
#ifndef _MODE_T_DEFINED
#define _MODE_T_DEFINED 1
#endif

/* The pinned task-system assembly restores these slots directly. */
#include <stddef.h>
#include <setjmp.h>
/* HEV calls the MSVC one-argument form. MinGW's MSVCRT declaration takes
 * an additional frame argument. HEV restores the buffer itself, without
 * invoking CRT unwinding, so save a non-unwinding frame. */
#ifdef _setjmp
#error FCAE's HEV bridge expects MinGW's MSVCRT _setjmp declaration
#endif
#define _setjmp(buf) (_setjmp)((buf), NULL)
#if !defined(__x86_64__) || !defined(_WIN32)
#error FCAE's Windows HEV archives require the x86_64 Windows ABI
#endif
#define FCAE_JB_OFFSET(field, expected) \
    _Static_assert(offsetof(_JUMP_BUFFER, field) == (expected), "unexpected jump buffer: " #field)
_Static_assert(sizeof(jmp_buf) >= 256, "jump buffer too small");
_Static_assert(_Alignof(jmp_buf) >= 16, "jump buffer is not 16-byte aligned");
FCAE_JB_OFFSET(Rbx, 8);
FCAE_JB_OFFSET(Rsp, 16);
FCAE_JB_OFFSET(Rbp, 24);
FCAE_JB_OFFSET(Rsi, 32);
FCAE_JB_OFFSET(Rdi, 40);
FCAE_JB_OFFSET(R12, 48);
FCAE_JB_OFFSET(R13, 56);
FCAE_JB_OFFSET(R14, 64);
FCAE_JB_OFFSET(R15, 72);
FCAE_JB_OFFSET(Rip, 80);
FCAE_JB_OFFSET(MxCsr, 88);
FCAE_JB_OFFSET(FpCsr, 92);
FCAE_JB_OFFSET(Xmm6, 96);
FCAE_JB_OFFSET(Xmm15, 240);
#undef FCAE_JB_OFFSET
#endif
#endif
