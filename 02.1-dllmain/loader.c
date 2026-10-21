#include <windows.h>
#include <stdio.h>

int main(void)
{
    HMODULE hModule = LoadLibraryA("labdll.dll");

    if (hModule == NULL)
    {
        printf("[!] LoadLibrary a echoue. Code erreur : %lu\n", GetLastError());
        return 1;
    }

    printf("[+] DLL chargee. HMODULE : %p\n", (void*)hModule);

    FreeLibrary(hModule);
    printf("[+] DLL dechargee.\n");

    return 0;
}