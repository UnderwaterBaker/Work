#include <windows.h>
#include <stdio.h>

int main(void)
{
    HMODULE hDLL = LoadLibraryA("C:\\Users\\Bingus\\CLionProjects\\httpDLL\\cmake-build-debug\\libhttpDLL.dll");
    if (hDLL == NULL)
    {
        printf("[!] LoadLibraryA failed with %lu\n", GetLastError());
    }

    FARPROC fDoThing = GetProcAddress(hDLL, "doThing");
    if (fDoThing == NULL)
    {
        printf("[!] GetProcAddress failed with %lu\n", GetLastError());
    }

    (fDoThing());
    return 0;
}
