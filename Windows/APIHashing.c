#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

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

BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2)
{
	WCHAR lStr1[MAX_PATH], lStr2[MAX_PATH];
	int len1 = lstrlenW(Str1), len2 = lstrlenW(Str2);
	int i;

	// don't want buffer overflow
	if (len1 > MAX_PATH || len2 > MAX_PATH)
		return FALSE;

	// Convert Str1 to lowercase
	for (i = 0; i < len1; i++)
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	lStr1[i++] = '\0'; // needs null termination

	// Convert Str2 to lowercase
	for (i = 0; i < len1; i++)
		lStr2[i] = (WCHAR)tolower(Str2[i]);
	lStr2[i++] = '\0'; // needs null termination

	// Comparing lowercase strings
	if (lstrcmpiW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}

HMODULE CustomGetModuleHandleH(IN DWORD dwModuleHash)
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
		if (HashStringDjb2W(pEntryData->FullDllName.Buffer) ==  dwModuleHash)
		{
			//wprintf(L"[+] FOUND: %s\tADDRESS: 0x%p\n", pEntryData->FullDllName.Buffer, pEntryData->DllBase);
			break;
		}
		pEntry = pEntry->Flink;
	}

	return (HMODULE)pEntryData->DllBase;
}

FARPROC GetProcAddressReplacementH(IN HMODULE hModule, IN DWORD dwApiHash) {

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
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		// Getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		// Getting the address of the function through its ordinal
		PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// Searching for the function specified
		if (HashStringDjb2A(pFunctionName) == dwApiHash) {
			//printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
			return pFunctionAddress;
		}
	}

	return NULL;
}


int main()
{
	// Testing
	/*
	HANDLE chHandle = CustomGetModuleHandle(L"C:\\Windows\\SYSTEM32\\ntdll.dll");
	HANDLE ahHandle = GetModuleHandleW(L"NTDLL.DLL");
	printf("[+] Custom GetModuleHandle: 0x%p\n", chHandle);
	printf("[+] API GetModuleHandle: 0x%p\n", ahHandle);
	printf("[+] Custom GetProcAddress: 0x%p\n", GetProcAddressReplacement(chHandle, "NtAllocateVirtualMemory"));
	printf("[+] API GetProcAddress: 0x%p\n", GetProcAddress(ahHandle, "NtAllocateVirtualMemory"));
	*/

	// Precomute hashes
	/*
	printf("NTDLL.DLL (no path): %lu\n", HashStringDjb2W(L"NTDLL.DLL")); // 3289685874
	printf("NTDLL.DLL: %lu\n", HashStringDjb2W(L"C:\\Windows\\SYSTEM32\\ntdll.dll")); // 1746671672
	printf("NtAllocateVirtualMemory: %lu\n", HashStringDjb2W(L"NtAllocateVirtualMemory")); // 2902018353
	printf("NtAllocateVirtualMemory (ascii): %lu\n", HashStringDjb2A("NtAllocateVirtualMemory")); // 2902018353
	*/

	// Should match addresses in above testing
	HANDLE chHandle = CustomGetModuleHandleH(1746671672);
	printf("[+] Custom GetModuleHandleH: 0x%p\n", chHandle);
	printf("[+] Custom GetProcAddress: 0x%p\n", GetProcAddressReplacementH(chHandle, 2902018353));

	return 0;
}
