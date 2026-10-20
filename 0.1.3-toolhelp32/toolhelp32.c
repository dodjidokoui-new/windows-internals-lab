#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>

void ListModules(DWORD pid) {

	// snapshot of the module, return a HANDLE or INVALID_HANDLE_VALUE
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

	if (hSnapshot == INVALID_HANDLE_VALUE){
		printf("    [!] Cannot enumerate modules (PID %lu)\n", pid);
		return;
	}

    /*
	* MODULEENTRY32 gives us name of the module, base address in memory, image size
	* 
	*/
	MODULEENTRY32 me;
	me.dwSize = sizeof(MODULEENTRY32);


	if (Module32First(hSnapshot, &me)) {
		do {
			printf("   [MOD] %-30s base: 0x%p  size: 0x%08lX\n",
				me.szModule,
				me.modBaseAddr,
				me.modBaseSize);
		} while (Module32Next(hSnapshot, &me));
	}

	CloseHandle(hSnapshot);

}

int main(void) {

	// Snapshot of TH32CS_SNAPPROCESS
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
		return 1;
	}

	// Get the first PROCESSENTRY 32
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe)) {
		printf("[!] Process32First failed: %lu\n", GetLastError());
		CloseHandle(hSnapshot);
		return 1;
	}

	/*
	* For each process, we display the PID / PPID / Threads and Name
	* THen List Modules iterates through modules with Module32First
	* Close the handle then next process
	*/
	do {
		printf("[PID: %5lu | PPID: %5lu | Threads: %3lu] %s\n", 
			pe.th32ProcessID,
			pe.th32ParentProcessID,
			pe.cntThreads,
			pe.szExeFile);
		ListModules(pe.th32ProcessID);
	} while (Process32Next(hSnapshot, &pe));

	CloseHandle(hSnapshot);
	return 0;
}