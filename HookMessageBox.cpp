#include <iostream>
#include <Windows.h>

const int TRAMPOLINE_SIZE{ 14 };
LPVOID trampoline_address;
typedef INT(WINAPI* msgbox)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

typedef struct _HookSt
{
	PVOID pFunctionToHook;
	PVOID pFunctionToRun;
	BYTE pOriginalBytes[TRAMPOLINE_SIZE];
	DWORD dwOldProtection;
}HookSt, *PHookSt;

BOOL bErrorCheck(BOOL ret)
{
	if (!ret)
		return -1;
}

INT WINAPI MyMessageBoxW(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	std::wcout << "Original Text: " << lpText << "\nOriginal Caption: " << lpCaption << "\n";
	//return MessageBoxA(hWnd, "Yarr, ye been hooked!", "Yohoho", uType);
	msgbox trampoline = (msgbox)trampoline_address;
	return trampoline(hWnd, L"Yarr, ye been hooked!", L"Yohoho", uType);
}

BOOL InitializeHookStruct(IN PVOID pFunctionToHook, IN PVOID pFunctionToRun, OUT PHookSt Hook)
{
	// Filling the struct
	Hook->pFunctionToHook = pFunctionToHook;
	Hook->pFunctionToRun = pFunctionToRun;

	// Save original bytes for unhooking
	//memcpy(Hook->pOriginalBytes, pFunctionToHook, TRAMPOLINE_SIZE);
 
	// Hardcoding bytes because RIP relative addressing causes function to fail using RIP offset from the hooked function (access violation)
	// In this case the condition doesn't seem important as the hook will always work as intended whether or not the jmp after this compare is taken
	// If the cmp is important for another case we could add a `mov r9, [ADDRESS]` `cmp r9, r11d` instead of setting the offset to 0. (i think)
	// Because we have full control of our trampoline function, we can replace any rip-relative instructions with functionally equivalent ones and be ok
	/**
	0:  48 83 ec 38             sub    rsp,0x38
	4:  45 33 db                xor    r11d,r11d
	7:  44 39 1d 00 00 00 00    cmp    DWORD PTR [rip+0x0],r11d
	**/
	BYTE hardCodeBytes[14] = { 0x48, 0x83, 0xec, 0x38, 0x45, 0x33, 0xdb, 0x44, 0x39, 0x1d, 0x00, 0x00, 0x00, 0x00 };
	memcpy(Hook->pOriginalBytes, hardCodeBytes, TRAMPOLINE_SIZE);

	if (!VirtualProtect(Hook->pFunctionToHook, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &Hook->dwOldProtection))
	{
		std::cout << "[!] VirtualProtect failed with: " << GetLastError() << "\n";
		return FALSE;
	}

	return TRUE;
}

BOOL InstallHook(IN PHookSt Hook)
{
	// Null address will be overwritten at runtime
	// Trampoline x64
	uint8_t uTrampoline[] = {
		0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pAddress
		0x41, 0xFF, 0xE2, 0x90                                            // jmp r10
	};

	// Patching shellcode with FunctionToRun address
	uint64_t uPatch = (uint64_t)Hook->pFunctionToRun;
	memcpy(&uTrampoline[2], &uPatch, sizeof(uPatch));

	// Placing the jump
	memcpy(Hook->pFunctionToHook, uTrampoline, sizeof(uTrampoline));

	// Build trampoline function from bytes
	uint8_t uTrampoline2[] = {
		0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pAddress
		0x41, 0xFF, 0xE2, 0x90                                            // jmp r10
	}; // r10 is a volitial register for x64, 
	uint64_t uPatch2 = (uint64_t)Hook->pFunctionToHook + 14; // Address of hooked function after inserted jump
	memcpy(&uTrampoline2[2], &uPatch2, sizeof(uPatch2));

	// Instructions somehow getting mangled, maybe an alignment issue?
	if (!(trampoline_address = VirtualAlloc(0, 26, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		return FALSE;
	}
	memcpy(trampoline_address, Hook->pOriginalBytes, TRAMPOLINE_SIZE); // Copy overwritten function bytes
	memcpy((uint64_t*)((uint64_t)trampoline_address + 14), uTrampoline2, sizeof(uTrampoline2)); // Jump back in function after inserted hook.

	return TRUE;
}

BOOL RemoveHook(IN PHookSt Hook)
{
	// Copy original bytes over
	memcpy(Hook->pFunctionToHook, Hook->pOriginalBytes, TRAMPOLINE_SIZE);
	// Clean up our buffer
	memset(Hook->pOriginalBytes, '\0', TRAMPOLINE_SIZE);

	if (!VirtualProtect(Hook->pFunctionToHook, TRAMPOLINE_SIZE, Hook->dwOldProtection, &Hook->dwOldProtection))
	{
		std::cout << "[!] VirtualProtect failed with: " << GetLastError() << "\n";
		return FALSE;
	}

	// Setting all to NULL
	Hook->pFunctionToHook = NULL;
	Hook->pFunctionToRun = NULL;
	Hook->dwOldProtection = NULL;

	return TRUE;
}

int main()
{
	// Initiliaze hook struct and get address of target fuction
	HookSt st{ 0 };
	HMODULE user32 = LoadLibraryA("user32.dll");
	if (!user32)
	{
		return -1;
	}
	msgbox pMessageBoxW = (msgbox)GetProcAddress(user32, "MessageBoxW");
	if (!pMessageBoxW)
	{
		return -1;
	}

	if (!InitializeHookStruct(pMessageBoxW, MyMessageBoxW, &st))
	{
		return -1;
	}
	pMessageBoxW(NULL, L"What Do You Think About Malware Development ?", L"Original MsgBox", MB_OK | MB_ICONQUESTION);

	if (!InstallHook(&st))
	{
		return -1;
	}
	pMessageBoxW(NULL, L"I sure do love being a message box", L"Original MsgBox", MB_OK | MB_ICONQUESTION);
	pMessageBoxW(NULL, L"I sure do love being a message box part 2", L"Original MsgBox", MB_OK | MB_ICONQUESTION);
	/**
	if (!RemoveHook(&st))
	{
		return -1;
	}
	pMessageBoxW(NULL, L"Huh, that was weird", L"Original MsgBox", MB_OK | MB_ICONQUESTION);
	**/

	return 0;
}
