#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// Garbage horrible abominable trashcan solution
#define N_HASHES 2
#define STRING_SIZE 70

DWORD HashStringDjb2A(IN PCHAR String, IN DWORD initialSeed, IN DWORD initialHash)
{
	ULONG Hash = initialHash;
	INT c;

	while (c = *String++)
		Hash = ((Hash << initialSeed) + Hash) + c;

	return Hash;
}

int main()
{
	srand(time(NULL));
	int initialSeed = rand();
	int initialHash = rand();

	char file[] = "C:\\Users\\Bingus\\source\\repos\\LoaderNoCPP\\LoaderNoCPP\\APIHashing.h";
	char cmdLine[500];
	char searchKeys[N_HASHES][STRING_SIZE] = {  "^#define KERNEL32_HASH(.+)$", "^#define VIRTUALALLOC_HASH(.+)$" };
	char replaceKeys[N_HASHES][STRING_SIZE] = { "#define KERNEL32_HASH", "#define VIRTUALALLOC_HASH" };
	char replaceStrs[N_HASHES][STRING_SIZE];
	
	char apis[N_HASHES][40] =
	{
		"kernel32",
		"virtualalloc"
	};

	for (int i = 0; i < N_HASHES; i++)
	{
		char result[90];
		unsigned long long sResultSize = sizeof(result);
		unsigned char hashStr[90];
		unsigned long hash;

		hash = HashStringDjb2A(apis[i], initialSeed, initialHash);
		_ultoa_s(hash, hashStr, sResultSize, 10);

		strcpy_s(result, sResultSize, replaceKeys[i]);
		strcat_s(result, sResultSize, " ");
		strcat_s(result, sResultSize, hashStr);

		strcpy_s(replaceStrs[i], STRING_SIZE, result);
	}

	sprintf_s(cmdLine, sizeof(cmdLine), "powershell.exe -c \"(Get-Content %s) -replace '^#define INITIAL_SEED(.+)$', '#define INITIAL_SEED %d' | Set-Content %s\"", file, initialSeed, file);
	system(cmdLine);
	sprintf_s(cmdLine, sizeof(cmdLine), "powershell.exe -c \"(Get-Content %s) -replace '^#define INITIAL_HASH(.+)$', '#define INITIAL_HASH %d' | Set-Content %s\"", file, initialHash, file);
	system(cmdLine);
	for (int i = 0; i < N_HASHES; i++)
	{
		sprintf_s(cmdLine, sizeof(cmdLine), "powershell.exe -c \"(Get-Content %s) -replace '%s', '%s' | Set-Content %s\"", file, searchKeys[i], replaceStrs[i], file);
		printf("[INFO] %s\n", cmdLine);
		system(cmdLine);
	}

	// TODO: add compilation command
	// exclude boostrap from build and keep static seed and hash values during development
	return 0;
}
