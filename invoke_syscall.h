#ifndef INVOKE_SYSCALL_H
#define INVOKE_SYSCALL_H

/*
 * SyscallInvoker (c) 2020
 * Supports both x86 (32-bit) and x64 (64-bit) Windows platforms.
 *
 * Allows indirect invocation of system calls with spoofed return addresses —
 * both for the original function return and the syscall return itself.
 *
 * On x64 Windows:
 *  - Any instruction containing `syscall` can be used, regardless of the function it's in.
 *    For example, you can issue syscall number 0x18 (NtAllocateVirtualMemory)
 *    even from a thunk for NtFreeVirtualMemory.
 *
 * On x86 Windows:
 *  - Thunks in NTDLL often end with a `ret` instruction that pops arguments off the stack.
 *    This means you must match the system call with the correct number of parameters,
 *    otherwise you'll corrupt the stack.
 */

#ifndef _UINTPTR_T_DEFINED
#define _UINTPTR_T_DEFINED
#ifdef _WIN64
typedef unsigned __int64 uintptr_t;
#else
typedef unsigned int uintptr_t;
#endif
#endif

/**
 * @struct invoke_context
 * @brief Describes the context needed to perform a spoofed syscall
 */
struct invoke_context
{
	void*      function;      // Pointer to syscall thunk (e.g., NtXxx in NTDLL)
	void*      gadget;        // Gadget for control flow hijack (e.g., jmp rdi/edi from kernel32 or elsewhere)
	uintptr_t  key;           // Key to encode the actual return address (for simple spoofing/encryption)
	unsigned   ssn;           // System service number (used as syscall index)
	size_t     params_count;  // Number of syscall arguments
	uintptr_t* params;        // Array of arguments
	void*      fake_addr;     // Fake return address to place on stack during syscall
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Performs the syscall specified in the context with stack/return spoofing
 *
 * @param ctx The call context containing syscall number, arguments, and spoofing info
 * @return Return value from the syscall (depends on the syscall itself; may be undefined if void)
 */
uintptr_t __cdecl invoke_syscall(const invoke_context* ctx);

#ifdef __cplusplus
}
#endif

#endif // INVOKE_SYSCALL_H
