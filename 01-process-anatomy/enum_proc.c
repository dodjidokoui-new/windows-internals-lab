/*
Lab 1.1 - Enumerateur de processus avec Toolhelp32
Objectif : lister PID, PPID, nom, nombre de threads
           et ouvrir un handle pour inspecter les droits

Compile (ligne de commande) : cl /W4 /Zi enum_proc.c /link /out:enum_proc.exe
Compile (Visual Studio)     : projet C, jeu de caractères -> "Non défini" OU
                              laisser tel quel (le #undef ci-dessous gère tout)
*/

/*
 * FIX TCHAR / UNICODE
 * Visual Studio définit UNICODE et _UNICODE par défaut dans ses projets,
 * ce qui fait que PROCESSENTRY32 / Process32First deviennent des alias
 * vers les variantes wchar_t (PROCESSENTRY32W). printf("%s") lit alors
 * les wchar_t comme des char* et n'affiche qu'une seule lettre.
 *
 * On force ici la version ANSI en undéfinissant UNICODE avant tout include
 * Windows. Cela garantit que PROCESSENTRY32 == PROCESSENTRY32A (char[])
 * quelle que soit la configuration du projet VS.
 */
#undef  UNICODE
#undef  _UNICODE

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tlhelp32.h>   /* CreateToolhelp32Snapshot, PROCESSENTRY32 */
#include <stdio.h>

// Definition de la strct pour ProbeHandleRightGranular
typedef struct {
    DWORD       right;      // la valeur numérique du droit
    const char* name; // son nom lisible pour l'affichage
} RightEntry;

 /*
  * Affiche le nom d'utilisateur associe a un PID.
  * Ouvre le processus, recupere son token, interroge le SID.
  * Retourne FALSE si acces refuse (processus SYSTEM sans SeDebugPrivilege).
  */
static BOOL PrintProcessUser(DWORD pid)
{
    /* Droit minimal pour lire le token : QUERY_INFORMATION seulement */
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        /* ACCESS_DENIED normal pour System, Idle, processus proteges */
        return FALSE;
    }

    HANDLE hToken = NULL;
    /* TOKEN_QUERY : droit minimal pour lire les infos du token */
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        return FALSE;
    }

    /*
     * GetTokenInformation pattern en deux passes :
     *   1re passe : buffer NULL, taille 0 -> Windows ecrit la taille requise dans dwSize
     *   2e  passe : buffer alloue de dwSize octets -> Windows remplit TOKEN_USER
     *
     * BUG CORRIGE : la version initiale passait "9" au lieu de "0" au 4e argument,
     * ce qui causait un calcul de taille incorrect et une heap corruption silencieuse.
     */
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);

    TOKEN_USER* pTokenUser = (TOKEN_USER*)HeapAlloc(GetProcessHeap(), 0, dwSize);
    if (!pTokenUser) {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return FALSE;
    }

    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        /* LookupAccountSidA : convertit le SID en nom lisible DOMAIN\User */
        char szName[256] = { 0 };
        char szDomain[256] = { 0 };
        DWORD nameLen = sizeof(szName);
        DWORD domainLen = sizeof(szDomain);
        SID_NAME_USE sidType;

        if (LookupAccountSidA(NULL, pTokenUser->User.Sid,
            szName, &nameLen,
            szDomain, &domainLen, &sidType)) {
            printf("  User: %s\\%s\n", szDomain, szName);
        }
    }

    HeapFree(GetProcessHeap(), 0, pTokenUser);
    CloseHandle(hToken);
    CloseHandle(hProc);
    return TRUE;
}

/*
 * Tente d'ouvrir un handle avec les droits minimaux necessaires
 * a l'injection classique (Lab 2.2) et affiche le resultat.
 *
 * Objectif pedagogique : comprendre les DACL en pratique.
 * Un processus protege (PPL, SYSTEM) bloquera ici avec ERROR_ACCESS_DENIED (5).
 */
static void ProbeHandleRights(DWORD pid)
{
    DWORD injectionRights =
        PROCESS_CREATE_THREAD | /* CreateRemoteThread              */
        PROCESS_QUERY_INFORMATION | /* Lire infos process              */
        PROCESS_VM_OPERATION | /* VirtualAllocEx                  */
        PROCESS_VM_WRITE | /* WriteProcessMemory              */
        PROCESS_VM_READ;            /* ReadProcessMemory               */

    HANDLE h = OpenProcess(injectionRights, FALSE, pid);
    if (h) {
        printf("  [+] Handle injection possible (CREATE_THREAD|VM_*)\n");
        CloseHandle(h);
    }
    else {
        DWORD err = GetLastError();
        printf("  [-] Handle injection refuse (err=%lu)\n", err);
        /* 5  = ERROR_ACCESS_DENIED     -> DACL bloque                 */
        /* 87 = ERROR_INVALID_PARAMETER -> PID invalide / process mort */
    }
}



/*
* Teste chaque droit d'injection individuellement.
* Permet de voir exactement quels droits sont accordés
* après activation de SeDebugPrivilege.
* Utile pour diagnostiquer les sprocessus PPL ou à DACL restrictive.
*/
static void ProbeHandleRightsGranular(DWORD pid)
{
    printf("  [Granulaire] Droits testés un par un :\n");
    /* Tableau des droits à tester individuellement */
    RightEntry rights[] = {
        { PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION" },
        { PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD" },
        { PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION" },
        { PROCESS_VM_WRITE, "PROCESS_VM_WRITE" },
        { PROCESS_VM_READ, "PROCESS_VM_READ" },
    };

    /* Calcul du nombre d'entrées */
    int count = sizeof(rights) / sizeof(rights[0]);

    for (int i = 0; i < count; i++) {
        HANDLE h = OpenProcess(rights[i].right, FALSE, pid);
        if (h) {
            printf(" [+] %-35s OK\n", rights[i].name);
            CloseHandle(h);
        }
        else {
            printf("[-] %-35s REFUSE (err=%lu)\n",
                rights[i].name, GetLastError());
        }
    }
}

static BOOL EnableSeDebugPrivilege(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken))
        return FALSE;

    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    BOOL ok = (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
    CloseHandle(hToken);
    return ok;
}

int main(void)
{
    /*
     * CP_UTF8 : aligne la console Windows 11 sur l'encodage UTF-8.
     * Sans ca, les caracteres accentues dans les noms de comptes
     * (ex. "Systeme") s'affichent en mojibake.
     * Note : les noms de processus (szExeFile) sont ASCII pur -> pas affectes.
     */
    SetConsoleOutputCP(CP_UTF8);

    /*
     * CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
     *
     * Cree un snapshot de la table des processus du noyau.
     * Le second parametre (0) est ignore pour TH32CS_SNAPPROCESS.
     *
     * Pourquoi un snapshot ?
     * La liste des processus change en permanence. Le snapshot fige
     * l'etat a un instant T, eliminant les race conditions (un process
     * qui meurt entre deux appels ne corromprait pas l'iteration).
     */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Snapshot echoue: %lu\n", GetLastError());
        return 1;
    }

    /*
     * PROCESSENTRY32 : structure decrivant un processus dans le snapshot.
     * Grace au #undef UNICODE en tete de fichier, cette macro resout vers
     * PROCESSENTRY32A, dont le champ szExeFile est char[] -> compatible %s.
     *
     * CHAMP CLE : dwSize DOIT etre initialise avant Process32First.
     * Pattern Windows de compatibilite ascendante : si la struct grandit
     * dans une future version du SDK, la taille permet de l'adapter.
     * Oublier dwSize -> ERROR_INSUFFICIENT_BUFFER immediat.
     */
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnap, &pe32)) {
        fprintf(stderr, "Process32First echoue: %lu\n", GetLastError());
        CloseHandle(hSnap);
        return 1;
    }

    printf("%-8s %-8s %-6s %-40s\n", "PID", "PPID", "Thds", "Nom");
    printf("%-8s %-8s %-6s %-40s\n", "---", "----", "----", "---");

    do {
        printf("%-8lu %-8lu %-6lu %-40s\n",
            pe32.th32ProcessID,       /* PID                          */
            pe32.th32ParentProcessID, /* PPID - qui a spawne ce proc  */
            pe32.cntThreads,          /* nb de threads actifs         */
            pe32.szExeFile);          /* char[] garanti -> %s correct */

        ProbeHandleRights(pe32.th32ProcessID);
        PrintProcessUser(pe32.th32ProcessID);
        printf("\n");

    } while (Process32Next(hSnap, &pe32));


    printf("\n=== Démonstration SeDebugPrivilege ===\n");
    printf("Entrez le PID cible (visible dans la liste ci-dessus) : ");

    DWORD targetPid = 0;
    scanf_s("%lu", &targetPid);

    printf("\n[Avant] Tentative sans SeDebugPrivilege : \n");
    ProbeHandleRights(targetPid);

    if (EnableSeDebugPrivilege()) {
        printf("\n[+] SeDebugPrivilege activé.\n");
    }
    else {
        printf("\n[-] Activation échouée - lance en tant qu'Administrateur.\n");
        CloseHandle(hSnap);
        return 1;
    }

    printf("\n[Après] Tentative avec SeDebugPrivilege : \n");
    ProbeHandleRights(targetPid);
    ProbeHandleRightsGranular(targetPid);

    printf("\n[!] Ce handle sur lsass est le prérequis de Mimikatz sekurlsa.\n");
    printf("    Les EDR modernes surveillent OpenProcess(lsass) via ETW-TI.\n");

    CloseHandle(hSnap);
    return 0;
}