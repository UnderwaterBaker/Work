#include "APIHashing.h"


int main()
{
	extern DWORD KERNEL32_HASH;
	/*
	//printf("[+] INITIAL_HASH : %d\n[+] INITIAL_SEED : %d\n", INITIAL_HASH, INITIAL_SEED);
	printf("#define KERNEL32_HASH\t\t\t%lu\n", HashStringDjb2A((PCHAR)"kernel32"));
	printf("#define VIRTUALALLOC_HASH\t\t%lu\n", HashStringDjb2A((PCHAR)"VirtualAlloc"));
	printf("#define CREATETHREAD_HASH\t\t%lu\n", HashStringDjb2A((PCHAR)"CreateThread"));
	printf("#define CREATEREMOTETHREAD_HASH\t\n%lu", HashStringDjb2A((PCHAR)"CreateRemoteThread"));
	
	API_TABLE apiTable = { 0 };
	InitializeAPITable(&apiTable);
	printf("[+] kernel32C : 0x%p\n[+] Kernel32A : 0x%p\n", CustomGetModuleHandleH(KERNEL32_HASH), GetModuleHandleA("kernel32"));
	printf("[+] VirtualAllocC : 0x%p\n[+] VirtualAllocA : 0x%p", apiTable.VirtualAlloc, GetProcAddress(GetModuleHandleA("kernel32"), "VirtualAlloc"));
	*/
	printf("[+] %lu : %lu\n", KERNEL32_HASH, HashStringDjb2W((PWCHAR)L"kernel32.dll"));
	return 0;
}
