/*
 * Lab 1.1 : Process Enumerator (Toolhelp32)
 * Goal: list PID, PPID, thread count, image name for every running process,
 *       resolve the owner username via the process token,
 *       and probe whether a handle with injection-level rights can be opened.
 *
 * Compile (Developer Command Prompt):
 *   cl /W4 /Zi enum_proc.c /link /out:enum_proc.exe
 */

#define WIN32_LEAN_AND_MEAN  
#include <windows.h>
#include <tlhelp32.h>         // CreateToolhelp32Snapshot, PROCESSENTRY32
#include <stdio.h>

/*
 * PrintProcessUser — resolve the username that owns a given PID.
 *
 * Chain: PID -> Process handle -> Token handle -> TOKEN_USER -> SID -> name string
 *
 * Returns FALSE silently when access is denied (System, PPL-protected processes).
 * That is expected behaviour, not an error worth reporting to the caller.
 */
static BOOL PrintProcessUser(DWORD pid)
{
    /*
     * Open the process with the minimum right needed to read its token.
     * PROCESS_QUERY_INFORMATION is enough for OpenProcessToken — never ask
     * for more rights than necessary (EDR visibility, DACL rejection).
     */
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        // err=5  ACCESS_DENIED  -> DACL blocks us (System, lsass, PPL processes)
        // err=87 INVALID_PARAM  -> PID does not exist (e.g. PID 0 Idle)
        return FALSE;
    }

    HANDLE hToken = NULL;

    /*
     * OpenProcessToken: get a handle to the access token attached to this process.
     * TOKEN_QUERY is the minimum right to call GetTokenInformation.
     * Note: hProc and hToken are two separate kernel objects with separate DACLs.
     */
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        return FALSE;
    }

    /*
     * GetTokenInformation — double-call pattern.
     *
     * The size of TOKEN_USER is not known at compile time because it embeds a SID,
     * whose length varies per system. We cannot declare it as a stack variable.
     *
     * Step 1: call with NULL buffer and size 0 to ask Windows how many bytes we need.
     *         The call fails on purpose — we only care about the value written to dwSize.
     * Step 2: allocate exactly that many bytes on the heap.
     * Step 3: call again with the real buffer.
     *
     * This "size-probe then allocate" pattern appears in dozens of Win32 APIs.
     */
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize); // step 1 — get size

    TOKEN_USER* pTokenUser = (TOKEN_USER*)HeapAlloc(GetProcessHeap(), 0, dwSize); // step 2
    if (!pTokenUser) {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return FALSE;
    }

    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) { // step 3
        /*
         * LookupAccountSid: translate the SID (binary identifier, e.g. S-1-5-21-...-1001)
         * into a human-readable name ("DOMAIN\Username").
         * Windows stores identities as SIDs internally — names can change, SIDs never do.
         */
        char szName[256]   = {0}; // "sz" prefix = zero-terminated string (Hungarian notation)
        char szDomain[256] = {0};
        DWORD nameLen   = sizeof(szName);
        DWORD domainLen = sizeof(szDomain);
        SID_NAME_USE sidType;

        if (LookupAccountSidA(NULL,                    // local machine
                              pTokenUser->User.Sid,    // SID inside the TOKEN_USER struct
                              szName,   &nameLen,
                              szDomain, &domainLen,
                              &sidType)) {
            printf("  User : %s\\%s\n", szDomain, szName);
        }
    }

    // Always free heap memory — missing HeapFree = kernel handle/memory leak
    HeapFree(GetProcessHeap(), 0, pTokenUser);
    CloseHandle(hToken);
    CloseHandle(hProc);
    return TRUE;
}

/*
 * ProbeHandleRights — attempt to open a handle with the exact rights
 * required for classic remote DLL injection (Lab 2.2).
 *
 * Why these five rights and not PROCESS_ALL_ACCESS?
 *   - Each right maps to exactly one injection API call (see comments below).
 *   - PROCESS_ALL_ACCESS is an immediate IOC: no legitimate software needs
 *     every right simultaneously. EDRs flag it. We don't.
 */
static void ProbeHandleRights(DWORD pid)
{
    DWORD injectionRights =
        PROCESS_CREATE_THREAD     |  // CreateRemoteThread  — starts our payload
        PROCESS_QUERY_INFORMATION |  // read process metadata, open token
        PROCESS_VM_OPERATION      |  // VirtualAllocEx      — allocate space in target
        PROCESS_VM_WRITE          |  // WriteProcessMemory  — copy payload into target
        PROCESS_VM_READ;             // ReadProcessMemory   — verify the write

    HANDLE h = OpenProcess(injectionRights, FALSE, pid);
    if (h) {
        printf("  [+] Handle injection possible (CREATE_THREAD|VM_*)\n");
        CloseHandle(h);
    } else {
        DWORD err = GetLastError();
        printf("  [-] Handle injection denied  (err=%lu)\n", err);
        // err=5  -> DACL blocks us (System, lsass, PPL-protected processes)
        // err=87 -> invalid PID (Idle, PID 0)
    }
}

int main(void)
{
    /*
     * CreateToolhelp32Snapshot: ask the kernel for a frozen copy of the process list.
     *
     * Why a snapshot and not a live query?
     * The process list changes continuously. Without a snapshot we could read a
     * partially updated entry or miss a process that exited between two calls
     * (race condition). The snapshot freezes state at one instant.
     *
     * The second parameter (0) is ignored for TH32CS_SNAPPROCESS.
     * The returned handle points to a temporary kernel object — close it when done.
     */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Snapshot failed: %lu\n", GetLastError());
        return 1;
    }

    /*
     * PROCESSENTRY32: the struct Windows fills for each process in the snapshot.
     *
     * CRITICAL: dwSize MUST be set to sizeof(PROCESSENTRY32) before Process32First.
     * Windows reads this field first to know how many bytes it may write safely.
     * This guards against struct layout changes across SDK versions.
     * Forgetting dwSize -> immediate ERROR_INSUFFICIENT_BUFFER / crash.
     *
     * This "set dwSize before use" pattern is universal across Win32 structs.
     */
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    /*
     * Process32First: seed the iteration — fills pe32 with the first process entry.
     */
    if (!Process32First(hSnap, &pe32)) {
        fprintf(stderr, "Process32First failed: %lu\n", GetLastError());
        CloseHandle(hSnap);
        return 1;
    }

    // Column headers — %-Ns = left-aligned string padded to N characters
    printf("%-8s %-8s %-6s %-40s\n", "PID", "PPID", "Thds", "Name");
    printf("%-8s %-8s %-6s %-40s\n", "---", "----", "----", "----");

    /*
     * do...while and not while: Process32First already loaded the first entry into pe32.
     * A regular while loop would call Process32Next before printing it, skipping entry 0.
     * Process32Next overwrites pe32 on each call — one struct serves the whole iteration.
     * Returns FALSE when there are no more entries.
     */
    do {
        printf("%-8lu %-8lu %-6lu %-40s\n",
               pe32.th32ProcessID,        // PID
               pe32.th32ParentProcessID,  // PPID — who spawned this process
               pe32.cntThreads,           // active thread count
               pe32.szExeFile);           // image name (no full path)

        ProbeHandleRights(pe32.th32ProcessID);
        PrintProcessUser(pe32.th32ProcessID);
        printf("\n");

    } while (Process32Next(hSnap, &pe32));

    // Release the snapshot kernel object — never skip CloseHandle
    CloseHandle(hSnap);
    return 0;
}