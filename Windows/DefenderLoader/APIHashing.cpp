#pragma once

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include "APIHashing.h"

// Compile-time API Hasing expressions
constexpr int CompileTimeSeed(void)
{
	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
}
constexpr auto INITIAL_HASH = CompileTimeSeed();
constexpr DWORD COMPTIME_HASHSTRINGW(const wchar_t* String) {
	ULONG Hash = INITIAL_HASH;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}
constexpr auto CE_KERNEL32_HASH = COMPTIME_HASHSTRINGW(L"kernel32.dll");
constexpr auto CE_VIRTUALALLOC_HASH = COMPTIME_HASHSTRINGW(L"VirtualAlloc");

// Copying expression to variables accessible from other files
DWORD KERNEL32_HASH = CE_KERNEL32_HASH;
DWORD VIRTUALALLOC_HASH = CE_VIRTUALALLOC_HASH;

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

LPCWSTR GetFileFromPathW(IN wchar_t* wPath)
{
	wchar_t* context = NULL;
	wchar_t* wFileName = wcstok_s(wPath, L"\\\\", &context);
	wchar_t* wLeaderToken = wcstok_s(NULL, L"\\\\", &context);
	
	while (wLeaderToken != NULL)
	{
		wFileName = wLeaderToken;
		wLeaderToken = wcstok_s(NULL, L"\\\\", &context);
	}

	// +1 for null byte
	_wcslwr_s(wFileName, wcslen(wFileName)+1);
	//wprintf(L"[+] wFileName : %s\n", wFileName);
	return wFileName;
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
	LPCWSTR DllName = NULL;
	while (pEntry != pModuleList)
	{
		pEntryData = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		//wprintf(L"[+] \"%s\"\n", pEntryData->FullDllName.Buffer);
		// Could use wine/xv typedefs to avoid this
		DllName = GetFileFromPathW(pEntryData->FullDllName.Buffer);
		if (HashStringDjb2W((PWCHAR)DllName) == dwModuleHash)
		{
			wprintf(L"[+] FOUND: %s\tADDRESS: 0x%p\n", pEntryData->FullDllName.Buffer, pEntryData->DllBase);
			break;
		}
		pEntry = pEntry->Flink;
	}

	return (HMODULE)(pEntryData->DllBase);

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
			return (FARPROC)pFunctionAddress;
		}
	}

	return NULL;
}

VOID InitializeAPITable(IN PAPI_TABLE pApiTable)
{
	HMODULE modHandle = CustomGetModuleHandleH(KERNEL32_HASH);
	FARPROC funcAddr = GetProcAddressReplacementH(modHandle, VIRTUALALLOC_HASH);
	pApiTable->VirtualAlloc = funcAddr;
	//printf("SET TO : %X\t%X\n", funcAddr, modHandle);
}
