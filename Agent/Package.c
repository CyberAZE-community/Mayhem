#include "Package.h"
#include "Transport.h"

extern UINT32 g_AgentID;

VOID Int32ToBuffer(PUCHAR buf, UINT32 val){
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8 ) & 0xFF;
    buf[3] = (val      ) & 0xFF;
}

VOID PackageAddInt32(PPACKAGE Package, UINT32 data){
    Package->Buffer = LocalReAlloc(Package->Buffer, Package->Length + 4, LMEM_MOVEABLE);
    Int32ToBuffer(Package->Buffer + Package->Length, data);
    Package->Length += 4;
}

VOID PackageAddBytes(PPACKAGE Package, PUCHAR Data, SIZE_T Size){
    PackageAddInt32(Package, Size);
    Package->Buffer = LocalReAlloc(Package->Buffer, Package->Length + Size, LMEM_MOVEABLE | LMEM_ZEROINIT);
    memcpy(Package->Buffer + Package->Length, Data, Size);
    Package->Length += Size;
}

PPACKAGE PackageCreate(UINT32 CommandID){
    PPACKAGE pkg     = LocalAlloc(LPTR, sizeof(PACKAGE));
    pkg->Buffer      = LocalAlloc(LPTR, sizeof(BYTE));
    pkg->Length      = 0;
    pkg->CommandID   = CommandID;

    PackageAddInt32(pkg, 0);              // size placeholder
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

    Int32ToBuffer(Package->Buffer, Package->Length - 4); // write actual size into first 4 bytes

    BOOL ok = TransportSend(Package->Buffer, Package->Length, Response, Size);
    PackageDestroy(Package);
    return ok;
}
