#include <Windows.h>
#include <cstdint>
#include <stdio.h>
#include "invoke_syscall.h"

void* find_gadget(void* base)
{
	auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	auto nts = reinterpret_cast<IMAGE_NT_HEADERS*>(uintptr_t(base) + dos->e_lfanew);

	if (nts->OptionalHeader.SizeOfCode <= 2)
		return nullptr;

	auto code = reinterpret_cast<uint8_t*>(uintptr_t(base) + nts->OptionalHeader.BaseOfCode);

	for (size_t i = 0; i <= nts->OptionalHeader.SizeOfCode - 2; i++) {

		if (*reinterpret_cast<uint16_t*>(code + i) == 0xE7FF)
			return reinterpret_cast<void*>(code + i);
	}

	return nullptr;
}
 
NTSTATUS
NTAPI
nt_allocate_virtual_memory(
	IN HANDLE		process_handle,
	IN OUT PVOID*	base_address,
	IN ULONG		zero_bits,
	IN OUT PSIZE_T	region_size,
	IN ULONG		allocation_type,
	IN ULONG		protect)
{
    auto kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32)
        return static_cast<NTSTATUS>(-1);

    auto gadget = find_gadget(kernel32);
    if (!gadget)
        return static_cast<NTSTATUS>(-1);

    auto ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return static_cast<NTSTATUS>(-1);

    auto syscall_stub = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
    if (!syscall_stub)
        return static_cast<NTSTATUS>(-1);

    auto fake_ret = reinterpret_cast<void*>(GetProcAddress(kernel32, "VirtualAlloc"));
    if (!fake_ret)
        return static_cast<NTSTATUS>(-1);

    uintptr_t params[] = {
        reinterpret_cast<uintptr_t>(process_handle),
        reinterpret_cast<uintptr_t>(base_address),
        static_cast<uintptr_t>(zero_bits),
        reinterpret_cast<uintptr_t>(region_size),
        static_cast<uintptr_t>(allocation_type),
        static_cast<uintptr_t>(protect)
    };

	LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);

#ifdef _WIN64
	const auto key = static_cast<uintptr_t>(counter.QuadPart);
#else
	const auto key = static_cast<uintptr_t>(counter.LowPart ^ counter.HighPart);
#endif

	invoke_context ctx = {
		.function = syscall_stub,
		.gadget = gadget,
		.key = key,
		.ssn = 0x18u, // Only for Windows 10+
		.params_count = 6,
		.params = params,
		.fake_addr = fake_ret
	};

	return static_cast<NTSTATUS>(invoke_syscall(&ctx));
}

int main()
{
	PVOID base_addr;
	SIZE_T region_size;
	NTSTATUS status;

	for (size_t i = 0; i < 10; i++) {
		
		base_addr = nullptr;
		region_size = 0x1000;
		status = nt_allocate_virtual_memory(GetCurrentProcess(), &base_addr, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (status == 0 && base_addr && region_size > 0) {
			printf("[+] (%zu) Allocated memory at: 0x%p [0x%zx]\n", i, base_addr, region_size);
		}
		else {
			printf("[-] (%zu) NtAllocateVirtualMemory failed: 0x%lu\n", i, status);
		}
	}

    return 0;
}