#pragma once

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define INITIAL_SEED 9 


// Random compile-time hash and seed for hashing functions

typedef struct _API_TABLE
{
	FARPROC VirtualAlloc;
} API_TABLE, * PAPI_TABLE;

/*
typedef struct _HASH_TABLE
{
	DWORD dwVirtualAlloc;
} HASH_TABLE, PHASH_TABLE;
*/

// API Hashing functions defined in APIHashing.c
DWORD HashStringDjb2W(_In_ PWCHAR String);
DWORD HashStringDjb2A(_In_ PCHAR String);
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2);
HMODULE CustomGetModuleHandleH(IN DWORD dwModuleHash);
FARPROC GetProcAddressReplacementH(IN HMODULE hModule, IN DWORD dwApiHash);
VOID InitializeAPITable(IN PAPI_TABLE pApiTable);
LPCWSTR GetFileFromPathW(IN LPCWSTR wPath);
