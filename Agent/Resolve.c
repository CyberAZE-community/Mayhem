#include "Resolve.h"
#include <ctype.h>

// jenkins 
DWORD HashStringA(PCHAR str) {
	DWORD h = 0;
	while (*str) {
		h += (UCHAR)*str++;
		h += h << HASH_SEED;
		h ^= h >> 6;
	}
	h += h << 3;
	h ^= h >> 11;
	h += h << 15;
	return h;
}


HMODULE ResolveModuleH(DWORD hash) {

#ifdef _WIN64
	PPEB peb = (PPEB)__readgsqword(0x60);
#else
	PPEB peb = (PPEB)__readfsdword(0x30);
#endif

	PPEB_LDR_DATA ldr = peb->Ldr;
	PLDR_DATA_TABLE_ENTRY dte = (PLDR_DATA_TABLE_ENTRY)(ldr->InMemoryOrderModuleList.Flink);

	while (dte) {
		if (dte->FullDllName.Length == 0 || dte->FullDllName.Length >= MAX_PATH)
			break;

		CHAR buf[MAX_PATH];
		int j = 0;
		while (dte->FullDllName.Buffer[j]) {
			buf[j] = (CHAR)toupper(dte->FullDllName.Buffer[j]);
			j++;
		}
		buf[j] = 0;

		if (HashStringA(buf) == hash)
			return (HMODULE)dte->Reserved2[0]; // dllBase

		dte = *(PLDR_DATA_TABLE_ENTRY*)(dte);
	}
	return NULL;
}


FARPROC ResolveFuncH(HMODULE hMod, DWORD hash) {
	PBYTE base = (PBYTE)hMod;
	if (!base) return NULL;

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

	// walk walk walk walk export table
	DWORD exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + exportRva);

	PDWORD names    = (PDWORD)(base + exp->AddressOfNames);
	PDWORD funcs    = (PDWORD)(base + exp->AddressOfFunctions);
	PWORD  ordinals = (PWORD)(base + exp->AddressOfNameOrdinals);

	for (DWORD i = 0; i < exp->NumberOfFunctions; i++) {
		char *fname = (char*)(base + names[i]);
		if (HashStringA(fname) == hash)
			return (FARPROC)(base + funcs[ordinals[i]]);
	}
	return NULL;
}
