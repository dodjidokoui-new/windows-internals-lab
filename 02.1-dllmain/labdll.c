#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            OutputDebugStringA("[labdll] DLL_PROCESS_ATTACH — DLL chargee\n");
            MessageBoxA(NULL, "labdll.dll chargee avec succes", "Lab 2.1", MB_OK);
            break;

        case DLL_PROCESS_DETACH:
            OutputDebugStringA("[labdll] DLL_PROCESS_DETACH — DLL dechargee\n");
            break;
    }

    return TRUE;
}