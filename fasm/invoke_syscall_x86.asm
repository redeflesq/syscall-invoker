;
;	SyscallInvoker32 - 32-bit system call invocation helper
;

;
;	Default 32-bit syscall function thunk in NTDLL (WOW64)
;
;	Offset  Instruction             Description
;	0x00:   B8 ?? ?? ?? ??          mov eax, ?            ; Load system call number into EAX
;	0x05:   BA ?? ?? ?? ??          mov edx, ?            ; Load address of WOW64 transition function into EDX
;	0x0A:   FF D2                   call edx              ; Call WOW64 transition
;	0x0A:   FF 12                   call dword ptr [edx]  ; Alternative indirect call variant
;	0x0C:   C2 ?? ??                ret <stack cleanup>   ; Return with stack cleanup
;	0x0C:   C3                      ret                   ; Alternative return without stack cleanup
;

;
;	Non-volatile (callee-saved) registers per x86 calling conventions
;
;	Refer to:
;	https://en.wikipedia.org/wiki/X86_calling_conventions
;	https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170#callercallee-saved-registers
;

use32

invoke_syscall:
	push ebp
	mov ebp, esp
	
	; Allocate local stack space for temporary storage
	sub esp, 4
	
	; Save callee-saved registers
	push ebx
	push edi

	; Load pointer to syscall context structure into EDX
	mov edx, [ebp + 8]
	; Check for null pointer and exit if null
	test edx, edx
	jz exit

	; Load original return address from the stack into EBX
	mov ebx, dword [ebp + 4]
	; Encrypt return address using XOR with key from context (simple obfuscation)
	xor ebx, [edx + 8]
	; Store encrypted return address in local variable
	mov [ebp - 4], ebx

	; Load number of syscall arguments from context into ECX
	mov ecx, [edx + 16]
	; If zero arguments, skip argument pushing
	test ecx, ecx
	jz begin_invoke

	; Load pointer to syscall arguments array into EAX
	mov eax, [edx + 20]

push_args:
	; Push arguments onto the stack in reverse order
	push dword [eax - 4 + 4 * ecx]
	dec ecx
	test ecx, ecx
	jnz push_args

begin_invoke:
	; Load fake return address from context into ECX
	mov ecx, dword [edx + 24]
	; Push the "gadget" return address onto the stack
	push dword [edx + 4]

	; Position-independent code trick: call next instruction to get EIP
	call get_eip

get_eip:
	; Pop return address into EDI and calculate offset to local_return label
	pop edi
	add edi, local_return - get_eip

	; Load syscall number into EAX from context
	mov eax, [edx + 12]
	; Load native syscall function address into EDX from context
	mov edx, dword [edx]
	; Adjust address to skip potential hooks (offset by 5 bytes)
	add edx, 5

	; Overwrite real return address on stack with fake return address
	mov [ebp + 4], ecx

	; Jump to native syscall function to invoke the syscall
	jmp edx

local_return:
	; Restore context pointer into EDX
	mov edx, [ebp + 8]
	; Load encrypted return address from local variable into EBX
	mov ebx, [ebp - 4]
	; Decrypt return address by XOR with key
	xor ebx, [edx + 8]
	; Restore real return address on the stack
	mov [ebp + 4], ebx

	; Stack cleanup is not required here as the syscall thunk uses 'ret <stack cleanup>' instruction

exit:
	; Restore callee-saved registers
	pop edi
	pop ebx

	mov esp, ebp
	pop ebp
	ret
