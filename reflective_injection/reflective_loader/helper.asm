.code

_GetHash PROC
    push rdi
    push rsi
    push rbx
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    compute_hash:
        xor rax, rax
        mov rsi, rcx
        cdq
        cld

    compute_hash_loop:
        lodsb
        test al, al
        jz compute_hash_end
        ror rdx, 0Dh
        add rdx, rax
        jmp compute_hash_loop

    compute_hash_end:
        mov rax, rdx

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop rbx
    pop rsi
    pop rdi
    ret
_GetHash ENDP

_GetModuleHandle PROC
    push rdi
    push rsi
    push rbx
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    
    mov r15, rcx ; save

    cld
    find_lib:
        mov rsi, qword ptr gs:[060h]
        mov rsi, qword ptr [rsi+018h]
        mov rsi, qword ptr [rsi+030h]

    parse_next_module:
        mov rcx, r15
        mov rbx, qword ptr [rsi+010h]
        mov rdi, qword ptr [rsi+040h]
        mov rsi, qword ptr [rsi]
	
    cmp_string:
        mov ax, word ptr [rcx]
        mov dx, word ptr [rdi]
        add rcx, 2
        add rdi, 2
        cmp ax, dx
        jne parse_next_module
        test ax, ax
        jne cmp_string

    mov rax, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop rbx
    pop rsi
    pop rdi
    ret
_GetModuleHandle ENDP

_GetProcAddress PROC
    push rdi
    push rsi
    push rbx
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rbx, rcx
    mov r14, rdx

    find_function:
        xor rax, rax
        xor rdi, rdi
        xor rcx, rcx
        mov eax, dword ptr [rbx+03ch] ; PE Header Offset
        add rax, rbx
        mov edi, dword ptr [rax+088h] ; Export Dir Table relative addr
        add rdi, rbx ; EDT absolute addr
        mov ecx, dword ptr [rdi+018h] ; NumberOfNames
        xor rax, rax
        mov eax, dword ptr [rdi+020h] ; AddressOfNames relative addr
        add rax, rbx ; AddressOfNames absolute addr
        mov r15, rax ; store addr
    
    find_function_loop:
        jecxz find_function_finish
        dec rcx
        mov rax, r15
        xor rsi, rsi
        mov esi, dword ptr [rax+rcx*4] ; Name relative addr
        add rsi, rbx ; Name absolute addr

    compute_hash:
        xor rax, rax
        cdq ; zero rdx (since rax is 0)
        cld ; forward string operations
	
    compute_hash_loop:
        lodsb
        test al, al ; end of string null
        jz compute_hash_end
        ror rdx, 0dh
        add rdx, rax
        jmp compute_hash_loop

    compute_hash_end: ; just a label

    find_function_compare:
        cmp rdx, r14 ; r14 stores precalculated hash
        jnz find_function_loop
        xor rdx, rdx
        mov edx, dword ptr [rdi+024h] ; AddressOfNameOrdinals relative addr
        add rdx, rbx ; AddressOfNameOrdinals absolute addr
        mov cx, word ptr [rdx+2*rcx] ; Ordinals index
        mov edx, dword ptr [rdi+01ch] ; AddressOfFunctions relative addr
        add rdx, rbx ; AddressOfFunctions absolute addr
        mov eax, dword ptr [rdx+4*rcx] ; function relative addr
        add rax, rbx ; function absolute addr

    find_function_finish:
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop rbx
        pop rsi
        pop rdi
        ret
_GetProcAddress ENDP

_GetBase PROC
    call callback
    
    callback:
        pop rax
    
    search:
        dec rax
        cmp word ptr [rax], 5A4Dh ; IMAGE_DOS_HEADE.e_magic
    jne search

    push rax
    pop rcx
    add cx, word ptr [rax + 3Ch] ; IMAGE_DOS_HEADE.e_lfanew
    cmp word ptr [rcx], 4550h ; IMAGE_NT_HEADERS.Signature
    jne search

    ret

_GetBase ENDP

END