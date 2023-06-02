#pragma once
#include<ntifs.h>
NTSTATUS Inject(ULONG64 pid, char* file, SIZE_T fileSize);