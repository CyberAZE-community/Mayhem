#ifndef RESOLVE_H
#define RESOLVE_H

#include <windows.h>
#include <winternl.h>

#define HASH_SEED	7 // jenkins seed

DWORD   HashStringA(PCHAR str);
HMODULE ResolveModuleH(DWORD hash);
FARPROC ResolveFuncH(HMODULE hMod, DWORD hash);

#endif
