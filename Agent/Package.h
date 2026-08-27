#ifndef PACKAGE_H
#define PACKAGE_H

#include <windows.h>

#define MAYO_MAGIC  0x6D61796F

typedef struct _PACKAGE {
    PUCHAR  Buffer;
    UINT32  Length;
    UINT32  Size;
    UINT32  CommandID;
    BOOL    Encrypt;
} PACKAGE, *PPACKAGE;

PPACKAGE PackageCreate(UINT32 CommandID);
VOID     PackageAddInt32(PPACKAGE Package, UINT32 Value);
VOID     PackageAddBytes(PPACKAGE Package, PUCHAR Data, SIZE_T Size);
BOOL     PackageTransmit(PPACKAGE Package, PVOID* Response, PSIZE_T Size);
VOID     PackageDestroy(PPACKAGE Package);

#endif
