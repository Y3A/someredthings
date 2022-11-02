; Hell's Gate Modified
; Dynamic system call invocation 
; 
; Originally by smelly__vx (@RtlMateusz) and am0nsec (@am0nsec)

.data
	wSystemCall  DWORD 000h
    pSyscallAddr QWORD 000h

.code 
	HellsGate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	HellsGate ENDP

    CharonFerry PROC
        mov pSyscallAddr, 000h
        mov pSyscallAddr, rcx
        ret
    CharonFerry ENDP

	HellDescent PROC
		mov r10, rcx
		mov eax, wSystemCall
		push pSyscallAddr
        ret
	HellDescent ENDP

end
