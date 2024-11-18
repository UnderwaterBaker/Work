#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

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

HMODULE CustomGetModuleHandle(IN LPCWSTR lModuleName)
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
		if (IsStringEqual(pEntryData->FullDllName.Buffer, lModuleName))
		{
			//wprintf(L"[+] FOUND: %s\tADDRESS: 0x%p\n", pEntryData->FullDllName.Buffer, pEntryData->DllBase);
			break;
		}
		pEntry = pEntry->Flink;
	}

	return (HMODULE)pEntryData->DllBase;
}

int main()
{
	printf("[+] Custom: 0x%p\n", CustomGetModuleHandle(L"C:\\Windows\\SYSTEM32\\ntdll.dll"));
	printf("[+] API: 0x%p\n", GetModuleHandleW(L"NTDLL.DLL"));

	return 0;
}
