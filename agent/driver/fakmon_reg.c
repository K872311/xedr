// 注册表回调：Agent 服务键自保护 + ASEP 相关键写入遥测。
#include <ntifs.h>
#include "fakmon.h"
#include "fakmon_internal.h"

static LARGE_INTEGER g_RegCookie = { 0 };

static BOOLEAN FaRegPathProtect(PCUNICODE_STRING name)
{
    if (!name || !name->Buffer || !name->Length) return FALSE;
    return FaContains(name, L"\\SERVICES\\FORENSICAGENT") ||
           FaContains(name, L"\\SERVICES\\FAKMON");
}

static BOOLEAN FaRegPathASEP(PCUNICODE_STRING name)
{
    if (!name || !name->Buffer || !name->Length) return FALSE;
    return FaContains(name, L"\\CURRENTVERSION\\RUN") ||
           FaContains(name, L"\\RUNONCE") ||
           FaContains(name, L"\\WINLOGON") ||
           FaContains(name, L"\\IMAGE FILE EXECUTION OPTIONS") ||
           FaContains(name, L"\\APPINIT_DLLS") ||
           (FaContains(name, L"\\SERVICES\\") && FaContains(name, L"\\IMAGEPATH"));
}

static NTSTATUS FaRegGetKeyPath(PVOID object, PUNICODE_STRING* outPath)
{
    PUNICODE_STRING id = NULL;
    NTSTATUS st;
    if (!object || !outPath) return STATUS_INVALID_PARAMETER;
    *outPath = NULL;
    st = CmCallbackGetKeyObjectIDEx(&g_RegCookie, object, NULL, &id, 0);
    if (!NT_SUCCESS(st) || !id) return st;
    *outPath = id;
    return STATUS_SUCCESS;
}

static VOID FaRegReleasePath(PUNICODE_STRING path)
{
    if (path) CmCallbackReleaseKeyObjectIDEx(path);
}

static NTSTATUS FaRegCallback(PVOID Ctx, PVOID Arg1, PVOID Arg2)
{
    REG_NOTIFY_CLASS nc = (REG_NOTIFY_CLASS)(ULONG_PTR)Arg1;
    PVOID object = NULL;
    PUNICODE_STRING path = NULL;
    ULONG pid;
    UNREFERENCED_PARAMETER(Ctx);

    switch (nc) {
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Arg2;
        if (!info) break;
        object = info->Object;
        break;
    }
    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Arg2;
        if (!info) break;
        object = info->Object;
        break;
    }
    case RegNtPreDeleteKey: {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Arg2;
        if (!info) break;
        object = info->Object;
        break;
    }
    default:
        return STATUS_SUCCESS;
    }

    if (!object) return STATUS_SUCCESS;
    if (!NT_SUCCESS(FaRegGetKeyPath(object, &path)) || !path) return STATUS_SUCCESS;

    pid = HandleToULong(PsGetCurrentProcessId());
    if (FaRegPathProtect(path)) {
        if (pid != 4) {
            FaPush(FA_EV_REG_PROTECT, pid, (ULONG)nc, 0, path);
            FaRegReleasePath(path);
            return STATUS_ACCESS_DENIED;
        }
    } else if (FaRegPathASEP(path) && pid > 4) {
        FaPush(FA_EV_REGISTRY, pid, (ULONG)nc, 0, path);
    }

    FaRegReleasePath(path);
    return STATUS_SUCCESS;
}

NTSTATUS FaRegInit(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"385202");
    if (g_RegCookie.QuadPart) return STATUS_SUCCESS;
    return CmRegisterCallbackEx(FaRegCallback, &altitude, DriverObject, NULL, &g_RegCookie, NULL);
}

VOID FaRegUnload(VOID)
{
    if (g_RegCookie.QuadPart) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCookie.QuadPart = 0;
    }
}
