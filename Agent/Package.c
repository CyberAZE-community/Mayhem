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
    if (!Package || !Package->Valid)
        return;

    PVOID buf = LocalReAlloc(Package->Buffer, Package->Length + 4, LMEM_MOVEABLE);
    if (!buf){
        Package->Valid = FALSE;
        return;
    }

    Package->Buffer = buf;
    Int32ToBuffer(Package->Buffer + Package->Length, data);
    Package->Length += 4;
}

VOID PackageAddBytes(PPACKAGE Package, PUCHAR Data, SIZE_T Size){
    if (!Package || !Package->Valid)
        return;

    if (Size > 0xFFFFFFFF || (!Data && Size)){
        Package->Valid = FALSE;
        return;
    }

    PackageAddInt32(Package, (UINT32)Size);
    if (!Package->Valid)
        return;

    PVOID buf = LocalReAlloc(Package->Buffer, Package->Length + Size, LMEM_MOVEABLE | LMEM_ZEROINIT);
    if (!buf){
        Package->Valid = FALSE;
        return;
    }

    Package->Buffer = buf;
    memcpy(Package->Buffer + Package->Length, Data, Size);
    Package->Length += (UINT32)Size;
}

PPACKAGE PackageCreate(UINT32 CommandID){
    PPACKAGE pkg = LocalAlloc(LPTR, sizeof(PACKAGE));
    if (!pkg)
        return NULL;

    pkg->Buffer = LocalAlloc(LPTR, sizeof(BYTE));
    if (!pkg->Buffer){
        LocalFree(pkg);
        return NULL;
    }

    pkg->Length    = 0;
    pkg->CommandID = CommandID;
    pkg->Valid     = TRUE;

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

    if (!Package->Valid || Package->Length < 4){
        PackageDestroy(Package);
        return FALSE;
    }

    Int32ToBuffer(Package->Buffer, Package->Length - 4);

    BOOL ok = TransportSend(Package->Buffer, Package->Length, Response, Size);
    PackageDestroy(Package);
    return ok;
}
