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
       push 78b5b983h
       call dword ptr [ebp+4h]        ;
       mov [ebp+10h], eax             ;Save TerminateProcess address for later

       push 0ec0e4e8eh
       call dword ptr [ebp+4h]        ;
       mov [ebp+14h], eax             ;Save LoadLibraryA address for later

       push 0C1634AF9h
       call dword ptr [ebp+4h]        ;
       mov [ebp+20h], eax             ;Save WideCharToMultiByte address for later

    load_Advapi32:
       push 0h
       push 6c6c642eh;
       push 32336970h;
       push 61766441h;
       push esp;
       call dword ptr [ebp+14h];
       mov ebx, eax                   ;Move the base address of Advapi32.dll to EBX

       push 5C52AA34h;
       call dword ptr [ebp+4h]        ;
       mov [ebp+18h], eax             ;Save Getusernamea address for later

    load_User32:
       push 00006c6ch;
       push 642e3233h;
       push 72657375h;
       push esp;
       call dword ptr [ebp+14h];
       mov ebx, eax                   ;Move the base address of User32.dll to EBX

       push 0BC4DA2A8h;
       call dword ptr [ebp+4h]        ;
       mov [ebp+1ch], eax             ;Save Messageboxa address for later


       sub esp, 260       ; 为用户名缓冲区分配空间
       mov dword ptr [esp], 256  ; 将缓冲区长度设置为256
       mov byte ptr [esp+4], 48H;
       mov byte ptr [esp+5], 65H;
       mov byte ptr [esp+6], 6cH;
       mov byte ptr [esp+7], 6cH;
       mov byte ptr [esp+8], 6fH;
       mov byte ptr [esp+9], 20H;
       lea eax, [esp+10]  ; 将用户名缓冲区的地址加载到eax
       push esp          ; 将长度变量的地址入栈
       push eax          ; 将用户名缓冲区的地址入栈
       call dword ptr [ebp+18h];

       lea eax, [esp+4];
       push 3h;
       push 0h;
       push eax;
       push 0h;
       call dword ptr [ebp+1ch];

 













end start
