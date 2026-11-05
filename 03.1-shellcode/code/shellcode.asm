bits 64
default rel

;==================================
;Lab 3.1 - shellcode.asm
; Shellcode x64 : MessageBox via resolution dynamique d'API
; Compilation : nasm -f bin shellcode.asm -o shellcode.bin
;
; Register map (main) :
;   r12 = kernel32.dll DllBase
;   r13 = GetProcAddress
;   r14 = LoadLibraryA
;   r15 = user32.dll DllBase
;
; find_export convention :
;   in  rbx = DllBase
;   in  rdx = ptr ASCII name (null-terminated)
;   out rax = adresse de la fonction (0 si non trouvée)
;   clobbers : rax, rcx, r8-r11, rsi, rdi
; ================================================================


_start:

; Bloc A : Prologue
	push rbp
	mov  rbp, rsp
	push rbx
	push rdi
	push rsi
	push r12
	push r13
	push r14
	push r15
	sub  rsp, 0x28      ;shadow space 32B + 8B aligment 16 bytes


; Bloc B : PEB Walk → kernel32.dll 

	mov rax, [gs:0x60]           ; rax = PEB*
	mov rax, [rax + 0x18]        ; rax = PEB->Ldr (PEB_LDR_DATA*)
	mov rax, [rax + 0x10]        ; rax = Ldr->InLoadOrderModuleList.Flink
								 ;     = premier LDR_DATA_TABLE_ENTRY*

.walk:
	mov rcx, [rax + 0x60]    ; rcx = BaseDllName.Buffer (PWSTR, UTF-16LE)

	; "KE" UTF-16LE -> bytes: 4B 00 45 00 -> DWORD 0x0045004B
	cmp dword[rcx], 0x0045004B
	jne .next_mod
	; "RN" UTF-16LE -> bytes: 52 00 4E 00 -> DWORD 0x004E0052
	cmp dword [rcx + 4], 0x004E0052
	je .got_k32

.next_mod:
	mov rax, [rax]                ; suivre InLoadOrderLinks.Flink
	jmp .walk

.got_k32:
	mov r12, [rax + 0x30]       ; r12 = kernel32.dll DllBase



; Bloc C : Corps principal

; Etape 2 : GetProcAddress dans kernel32
	mov rbx, r12
	lea rdx, [str_GPA]      ; "GetProcAddress"
	call find_export
	mov r13, rax       ; r13 = GetProcAddress

; Etape 3 : LoadLibraryA dans kernel32
	lea rdx, [str_LLA]
	call find_export
	mov r14, rax          ; r14 = LoadLibraryA

; Etape 4 charger user32.dll
	lea rcx, [str_u32]           ; LPCSTR = "user32.dll"
	call r14                     ; LoadLibraryA("user32.dll")
	mov r15, rax                 ; r15 = user32.dll DllBase

; Etape 5 : résoudre MessageBoxA
	mov rcx, r15                 ; HMODULE = user32
	lea rdx, [str_MBA]           ; LPCSTR = "MessageBoxA"
	call r13                     ; GetProcAddress(user32, "MessageBoxA")
	 ; rax = MessageBoxA

; Etape 6 : appeler MessageBoxA(Null, text, caption, MB_OK)
	xor ecx, ecx               ; hWnd = NULL
	lea rdx, [str_text]        ; lpText
	lea r8, [str_cap]          ; lpCaption
	xor r9d, r9d               ; uType = 0 (MB_OK)
	call rax

; Epilogue (sysmetrique au prologue, ordre inversé)
	add rsp, 0x28
	pop r15
	pop r14
	pop r13
	pop r12
	pop rsi
	pop rdi
	pop rbx
	pop rbp
	ret


; ================================================================
; find_export : parse l'Export Directory d'un module PE x64
; ================================================================

find_export:

	; 1. e_lfanew -> NT Headers
	mov eax, dword [rbx + 0x3C]      ; eax = e_lfanew 
	add rax, rbx                     ; rax = IMAGE_NT_HEADERS64* 

	; 2. Export Directory : NT + 0x18 (OptHdr) + 0x70 (DataDirectory[0]) = NT + 0x88
	mov eax, dword [rax + 0x88]        ; eax = Export Directory RVA
	add rax, rbx                       ; rax = IMAGE_EXPORT_DIRECTORY* (absolu)

	; 3. Lire les 4 champs utiles
	mov r10d, dword [rax + 0x18]    ; r10d = NumberOfNames

	mov r8d, dword [rax + 0x20]   ; AddressOfNames RVA
	add r8, rbx                   ; r8 = AddressOfNam (absolu)

	mov  r9d,  dword [rax + 0x24]   ; AddressOfNameOrdinals RVA
    add  r9,   rbx                  ; r9  = AddressOfNameOrdinals (absolu)

    mov  r11d, dword [rax + 0x1C]   ; AddressOfFunctions RVA
    add  r11,  rbx                  ; r11 = AddressOfFunctions (absolu)

	; 4. Boucle : for (i = 0; i < NumberOfNames; i++)
    xor  rcx, rcx                   ; rcx = i = 0

.fe_loop:
    cmp  ecx, r10d                  ; i >= NumberOfNames → échec
    jge  .fe_fail

    ; Récupérer le pointeur vers le nom courant
    mov  eax, dword [r8 + rcx*4]    ; eax = AddressOfNames[i] (RVA, DWORD)
    add  rax, rbx                   ; rax = ptr vers nom ASCII (absolu)

    ; Comparer avec rdx (nom cible) - strcmp char par char
    push rcx                        ; sauver i (rcx va être utilisé comme scratch)
    push rdx                        ; sauver ptr cible
    mov  rsi, rax                   ; rsi = nom courant (dans le module)
    mov  rdi, rdx                   ; rdi = nom cible (notre string)

.str_cmp:
    mov  al,  byte [rsi]            ; al = char courant
    cmp  al,  byte [rdi]            ; comparer avec char cible
    jne  .str_diff                  ; différent → pas de match
    test al,  al                    ; les deux = '\0' → match !
    jz   .str_match
    inc  rsi
    inc  rdi
    jmp  .str_cmp

.str_diff:
    pop  rdx
    pop  rcx
    inc  ecx                        ; i++
    jmp  .fe_loop

.str_match:
    pop  rdx                        ; restaurer (plus utilisé)
    pop  rcx                        ; rcx = i (pour indexer les ordinals)

    ; ordinal = AddressOfNameOrdinals[i]  (WORD = 2 bytes)
    movzx rax, word [r9 + rcx*2]   ; rax = ordinal (index dans AddressOfFunctions)

    ; adresse = base + AddressOfFunctions[ordinal]  (DWORD = RVA)
    mov   eax, dword [r11 + rax*4] ; eax = RVA de la fonction
    add   rax, rbx                  ; rax = adresse absolue
    ret

.fe_fail:
    xor  rax, rax                   ; retourne NULL
    ret




; Données : ASCII null-terminated, adresséees par RIP-relative LEA
str_GPA: db "GetProcAddress", 0
str_LLA: db "LoadLibraryA", 0
str_u32: db "user32.dll", 0
str_MBA: db "MessageBoxA", 0
str_text: db "Shellcode actif !", 0
str_cap: db "Lab3.1", 0