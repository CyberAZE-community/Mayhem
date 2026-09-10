#include "Syscall.h"
#include "Resolve.h"
#include "Hashes.h"
#include <string.h>
#include <stdlib.h>

#define MAX_STUBS 0x600

typedef struct _SYSSTUB {
	char  name[64];
	PBYTE addr;
	DWORD ssn;
	BOOL  ok;
} SYSSTUB;

static SYSSTUB stubs[MAX_STUBS];
static int     nStubs = 0;
static PBYTE   g_gadget = NULL;

static BOOL ReadSsn(PBYTE p, PDWORD ssn) {
	if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
		*ssn = *(DWORD*)(p + 4);
		return TRUE;
	}
	return FALSE;
}

static int CmpAddr(const void *a, const void *b) {
	PBYTE x = ((SYSSTUB*)a)->addr;
	PBYTE y = ((SYSSTUB*)b)->addr;
	return (x < y) ? -1 : (x > y);
}

static void LoadStubs(HMODULE ntdll) {
	PBYTE base = (PBYTE)ntdll;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

	DWORD dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + dir);

	PDWORD names = (PDWORD)(base + exp->AddressOfNames);
	PDWORD funcs = (PDWORD)(base + exp->AddressOfFunctions);
	PWORD  ords = (PWORD)(base + exp->AddressOfNameOrdinals);

	for (DWORD i = 0; i < exp->NumberOfNames && nStubs < MAX_STUBS; i++) {
		PCHAR nm = (PCHAR)(base + names[i]);
		if (nm[0] != 'Z' || nm[1] != 'w')
			continue;

		PBYTE fn = base + funcs[ords[i]];
		strncpy(stubs[nStubs].name, nm, 63);
		stubs[nStubs].addr = fn;
		stubs[nStubs].ok = ReadSsn(fn, &stubs[nStubs].ssn);
		nStubs++;
	}

	qsort(stubs, nStubs, sizeof(SYSSTUB), CmpAddr);

	for (int i = 0; i < nStubs; i++) {
		if (stubs[i].ok)
			continue;
		for (int j = i - 1; j >= 0; j--) {
			if (stubs[j].ok) { stubs[i].ssn = stubs[j].ssn + (i - j); stubs[i].ok = TRUE; break; }
		}
		if (!stubs[i].ok) {
			for (int j = i + 1; j < nStubs; j++) {
				if (stubs[j].ok) { stubs[i].ssn = stubs[j].ssn - (j - i); stubs[i].ok = TRUE; break; }
			}
		}
	}
}

static PBYTE FindGadget(HMODULE ntdll) {
	PBYTE base = (PBYTE)ntdll;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
		if (memcmp(sec->Name, ".text", 5) != 0)
			continue;

		PBYTE p = base + sec->VirtualAddress;
		PBYTE end = p + sec->Misc.VirtualSize;

		for (; p + 3 <= end; p++)
			if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3)
				return p;
	}
	return NULL;
}

BOOL InitSyscalls(VOID) {
	HMODULE ntdll = ResolveModuleH(H_NTDLL);
	if (!ntdll)
		return FALSE;

	LoadStubs(ntdll);
	g_gadget = FindGadget(ntdll);

	return (nStubs > 0 && g_gadget != NULL);
}

DWORD GetSsn(const char *name) {
	char want[64];

	if (name[0] == 'N' && name[1] == 't') {
		want[0] = 'Z';
		want[1] = 'w';
		strncpy(want + 2, name + 2, 61);
	} else {
		strncpy(want, name, 63);
	}
	want[63] = 0;

	for (int i = 0; i < nStubs; i++)
		if (strcmp(stubs[i].name, want) == 0)
			return stubs[i].ssn;

	return 0xFFFFFFFF;
}

PVOID SyscallStub(DWORD ssn) {
	typedef LPVOID (WINAPI* fn_Alloc)(LPVOID, SIZE_T, DWORD, DWORD);

	HMODULE k32 = ResolveModuleH(H_KERNEL32);
	fn_Alloc pAlloc = (fn_Alloc)ResolveFuncH(k32, H_VirtualAlloc);
	if (!pAlloc || !g_gadget || ssn == 0xFFFFFFFF)
		return NULL;

	PBYTE s = (PBYTE)pAlloc(NULL, 0x40, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!s)
		return NULL;

	int i = 0;
	s[i++] = 0x4C; s[i++] = 0x8B; s[i++] = 0xD1;
	s[i++] = 0xB8;
	*(DWORD*)(s + i) = ssn; i += 4;
	s[i++] = 0xFF; s[i++] = 0x25;
	*(DWORD*)(s + i) = 0; i += 4;
	*(PVOID*)(s + i) = g_gadget; i += 8;

	return s;
}
