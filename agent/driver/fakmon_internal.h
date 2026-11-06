#pragma once
#include "fakmon.h"

VOID FaPush(ULONG type, ULONG pid, ULONG ppid, ULONG tid, PCUNICODE_STRING path);
BOOLEAN FaContains(PCUNICODE_STRING s, PCWSTR needle);

NTSTATUS FaRegInit(PDRIVER_OBJECT DriverObject);
VOID FaRegUnload(VOID);
