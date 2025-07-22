;
; SyscallInvoker64 - 64-bit system call invocation helper
;

;
; Saved registers and calling convention references:
; https://en.wikipedia.org/wiki/X86_calling_conventions
; https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170#callercallee-saved-registers
;

IFDEF RAX

.CODE

invoke_syscall PROC
    push rbp
    mov rbp, rsp

    ; Preserve non-volatile (callee-saved) registers
    push rdi
    push rsi
    push rbx

    ; Save syscall context structure pointer (passed in RCX) to shadow space
    mov [rbp + 16], rcx

    ; Ensure the context pointer is not null
    test rcx, rcx
    jz exit

    ; Encrypt and store the return address
    mov rbx, qword ptr [rbp + 8]
    xor rbx, [rcx + 16]
    mov qword ptr [rbp + 32], rbx

    ; Store fake return address
    mov rbx, qword ptr [rcx + 48]
    mov qword ptr [rbp + 40], rbx

    ; Load number of syscall parameters
    mov rsi, [rcx + 32]

    ; If 4 or fewer parameters, skip pushing stack arguments
    cmp rsi, 4
    jbe begin_invoke

    ; Calculate number of extra arguments beyond the first 4 registers
    sub rsi, 4
    mov [rbp + 24], rsi

    ; Load parameter buffer base address
    mov r9, qword ptr [rcx + 40]

    ; Ensure stack alignment if extra argument count is even
    test rsi, 1
    jnz push_extra_args
    sub rsp, 8

push_extra_args:
    push qword ptr [r9 + 24 + 8 * rsi]
    dec rsi
    test rsi, rsi
    jnz push_extra_args

begin_invoke:
    ; Reserve shadow space (home space for Windows x64 ABI)
    sub rsp, 32

    ; Push gadget as return address
    push qword ptr [rcx + 8]

    ; Set up RDI with address of local_return for use by the return gadget
    lea rdi, [local_return]

    ; Load syscall stub address (thunk)
    mov rbx, qword ptr [rcx]

    ; Set EAX to system call number
    mov eax, [rcx + 24]

    ; Load first 4 parameters to appropriate registers per Windows x64 calling convention
    mov r10, [r9]         ; RCX → R10
    mov rdx, [r9 + 8]
    mov r8,  [r9 + 16]
    mov r9,  [r9 + 24]

    ; Skip past the syscall stub prologue if necessary (hook bypass)
    add rbx, 8

    ; Replace real return address with fake one
    mov rcx, qword ptr [rbp + 40]
    mov [rbp + 8], rcx

    ; Invoke the syscall stub
    jmp rbx

local_return:
    ; Restore shadow space
    add rsp, 32

    ; Decrypt the original return address
    mov r9, [rbp + 16]      ; syscall context
    mov rbx, [rbp + 32]     ; encrypted return address
    xor rbx, [r9 + 16]      ; decrypt using key from context
    mov [rbp + 8], rbx      ; restore real return address

    ; Retrieve number of stack-pushed arguments
    mov r9, [rbp + 24]
    test r9, r9
    jz exit

    ; Adjust stack to remove pushed parameters
    imul r9, 8
    add rsp, r9

    ; Re-align stack if needed
    mov r9, [rbp + 24]
    test r9, 1
    jnz exit
    add rsp, 8

exit:
    ; Restore preserved registers
    pop rbx
    pop rsi
    pop rdi
	
    mov rsp, rbp
    pop rbp
	
    ret
invoke_syscall ENDP

ENDIF

END