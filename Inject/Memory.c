#include "Memory.h"

#define PTE_BASE 0xFFFFF68000000000ull

ULONG64 pteBase = 0;

PHARDWARE_PTE GetPte(ULONG64 virtualAddr)
{
	if (pteBase == 0)
	{

		
		RTL_OSVERSIONINFOEXW version = {0};
		RtlGetVersion(&version);

		if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601)
		{
			pteBase = PTE_BASE;
		}
		else 
		{
			UNICODE_STRING apiName = {0};
			RtlInitUnicodeString(&apiName, L"MmGetVirtualForPhysical");
			PUCHAR api = (PUCHAR)MmGetSystemRoutineAddress(&apiName);
			pteBase = *(PULONG64)(api + 0x22);
		}
	}

	return (PHARDWARE_PTE)(((virtualAddr >> 9) & 0x7FFFFFFFF8) + pteBase);
}

PHARDWARE_PTE GetPde(ULONG64 virtualAddr)
{
	ULONG64 pte = (ULONG64)GetPte(virtualAddr);

	return (((pte >> 9) & 0x7FFFFFFFF8) + pteBase);
}

PHARDWARE_PTE GetPdpte(ULONG64 virtualAddr)
{
	ULONG64 pte = (ULONG64)GetPde(virtualAddr);

	return (((pte >> 9) & 0x7FFFFFFFF8) + pteBase);
}

PHARDWARE_PTE GetPml4(ULONG64 virtualAddr)
{
	ULONG64 pte = (ULONG64)GetPdpte(virtualAddr);

	return (((pte >> 9) & 0x7FFFFFFFF8) + pteBase);
}


VOID SetExecutePage(ULONG64 virtualAddr, ULONG64 size)
{
	ULONG64 startPage = (virtualAddr & (~0xFFF));
	ULONG64 endPage = (virtualAddr + size);

	if (endPage & 0xFFF)
	{
		endPage &= ~0xfff;
		endPage += PAGE_SIZE;
	}
	else 
	{
		endPage += PAGE_SIZE;
	}

	while (startPage < endPage)
	{

		PHARDWARE_PTE pte = GetPte(startPage);
		PHARDWARE_PTE pde = GetPde(startPage);

		if (MmIsAddressValid(pde))
		{
			pde->Write = 1;
			pde->NoExecute = 0;
		}

		if (MmIsAddressValid(pte))
		{
			pte->Write = 1;
			pte->NoExecute = 0;
		}

		startPage += PAGE_SIZE;
	}
}

PVOID AllocateMemory(ULONG64 size)
{
	PVOID mem = ExAllocatePool(PagedPool, size);
	memset(mem, 0, size);
	
	SetExecutePage(mem, size);

	return mem;
}