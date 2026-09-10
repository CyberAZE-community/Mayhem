#include "Resolve.h"
#include <ctype.h>
#include <string.h>

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
	PLDR_DATA_TABLE_ENTRY e = (PLDR_DATA_TABLE_ENTRY)ldr->InMemoryOrderModuleList.Flink;

	while (e) {
		if (e->FullDllName.Length == 0 || e->FullDllName.Length >= MAX_PATH)
			break;

		CHAR buf[MAX_PATH];
		int i = 0;
		while (e->FullDllName.Buffer[i]) {
			buf[i] = (CHAR)toupper(e->FullDllName.Buffer[i]);
			i++;
		}
		buf[i] = 0;

		if (HashStringA(buf) == hash)
			return (HMODULE)e->Reserved2[0];
		e = *(PLDR_DATA_TABLE_ENTRY*)e;
	}
	return NULL;
}

static HMODULE ResolveModuleName(const char *dll) {
	char want[64];
	int n = 0;
	while (dll[n] && n < 63) { want[n] = (char)toupper((unsigned char)dll[n]); n++; }
	want[n] = 0;

#ifdef _WIN64
	PPEB peb = (PPEB)__readgsqword(0x60);
#else
	PPEB peb = (PPEB)__readfsdword(0x30);
#endif
	PPEB_LDR_DATA ldr = peb->Ldr;
	PLDR_DATA_TABLE_ENTRY e = (PLDR_DATA_TABLE_ENTRY)ldr->InMemoryOrderModuleList.Flink;

	while (e) {
		if (e->FullDllName.Length == 0 || e->FullDllName.Length >= MAX_PATH)
			break;

		char buf[MAX_PATH];
		int i = 0;
		while (e->FullDllName.Buffer[i] && i < MAX_PATH - 1) {
			buf[i] = (char)toupper(e->FullDllName.Buffer[i]);
			i++;
		}
		buf[i] = 0;

		int len = (int)strlen(buf);
		if (len >= n && strcmp(buf + len - n, want) == 0)
			return (HMODULE)e->Reserved2[0];

		e = *(PLDR_DATA_TABLE_ENTRY*)e;
	}
	return NULL;
}

static PBYTE FindExportName(HMODULE mod, const char *name) {
	PBYTE base = (PBYTE)mod;
	if (!base)
		return NULL;

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
	DWORD dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + dir);

	PDWORD names = (PDWORD)(base + exp->AddressOfNames);
	PDWORD funcs = (PDWORD)(base + exp->AddressOfFunctions);
	PWORD  ords = (PWORD)(base + exp->AddressOfNameOrdinals);

	for (DWORD i = 0; i < exp->NumberOfNames; i++)
		if (strcmp((PCHAR)(base + names[i]), name) == 0)
			return base + funcs[ords[i]];

	return NULL;
}

FARPROC ResolveFuncH(HMODULE hMod, DWORD hash) {
	PBYTE base = (PBYTE)hMod;
	if (!base) return NULL;

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

	DWORD dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD sz = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + dir);

	PDWORD names = (PDWORD)(base + exp->AddressOfNames);
	PDWORD funcs = (PDWORD)(base + exp->AddressOfFunctions);
	PWORD  ords = (PWORD)(base + exp->AddressOfNameOrdinals);

	for (DWORD i = 0; i < exp->NumberOfNames; i++) {
		if (HashStringA((PCHAR)(base + names[i])) != hash)
			continue;

		DWORD rva = funcs[ords[i]];

		if (rva >= dir && rva < dir + sz) {
			PCHAR fwd = (PCHAR)(base + rva);
			PCHAR dot = strchr(fwd, '.');
			if (!dot)
				return NULL;

			CHAR dll[64];
			int n = (int)(dot - fwd);
			if (n > 55) n = 55;
			memcpy(dll, fwd, n);
			dll[n] = 0;
			strcat(dll, ".dll");

			HMODULE t = ResolveModuleName(dll);
			return t ? (FARPROC)FindExportName(t, dot + 1) : NULL;
		}
		return (FARPROC)(base + rva);
	}
	return NULL;
}
