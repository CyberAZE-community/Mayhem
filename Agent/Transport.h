#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <windows.h>

typedef struct _TRANSPORT_CFG {
    LPWSTR  UserAgent;
    LPWSTR  Host;
    DWORD   Port;
    BOOL    Secure;
} TRANSPORT_CFG, *PTRANSPORT_CFG;

BOOL TransportSend(LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize);

#endif
