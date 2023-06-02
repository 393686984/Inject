#pragma once
#include <ntifs.h>

typedef struct _HARDWARE_PTE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Write : 1;                                                      //0x0
	ULONGLONG Owner : 1;                                                      //0x0
	ULONGLONG WriteThrough : 1;                                               //0x0
	ULONGLONG CacheDisable : 1;                                               //0x0
	ULONGLONG Accessed : 1;                                                   //0x0
	ULONGLONG Dirty : 1;                                                      //0x0
	ULONGLONG LargePage : 1;                                                  //0x0
	ULONGLONG Global : 1;                                                     //0x0
	ULONGLONG CopyOnWrite : 1;                                                //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG reserved0 : 1;                                                  //0x0
	ULONGLONG PageFrameNumber : 40;                                           //0x0
	ULONGLONG SoftwareWsIndex : 11;                                           //0x0
	ULONGLONG NoExecute : 1;                                                  //0x0
}HARDWARE_PTE,*PHARDWARE_PTE;

PHARDWARE_PTE GetPte(ULONG64 virtualAddr);

PHARDWARE_PTE GetPde(ULONG64 virtualAddr);

PHARDWARE_PTE GetPdpte(ULONG64 virtualAddr);

PHARDWARE_PTE GetPml4(ULONG64 virtualAddr);

VOID SetExecutePage(ULONG64 virtualAddr,ULONG64 size);


PVOID AllocateMemory(ULONG64 size);