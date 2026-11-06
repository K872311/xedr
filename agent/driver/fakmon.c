// ForensicAgent 内核监控驱动（WDM）。
// - 进程创建/退出：PsSetCreateProcessNotifyRoutineEx
// - 映像加载：PsSetLoadImageNotifyRoutine
// - 远程线程（注入面）：PsSetCreateThreadNotifyRoutine，创建者进程 != 目标进程
// - 自保护：ObRegisterCallbacks 剥离对 Agent 进程的 TERMINATE/VM_WRITE 等权限
// 事件写入环形缓冲，用户态经 IOCTL_FA_READ_EVENTS 批量读取。
// 需链接 /INTEGRITYCHECK，且必须签名（测试环境可 bcdedit /set testsigning on）。

#include <ntifs.h>
#include <wdmsec.h>
#include "fakmon.h"
#include "fakmon_internal.h"

#define FA_TAG 'nmKF'

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE         0x0001
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION      0x0008
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE          0x0020
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME    0x0800
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD     0x0002
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ           0x0010
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD FaUnload;
_Dispatch_type_(IRP_MJ_CREATE) _Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH FaCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH FaIoctl;

static PDEVICE_OBJECT g_Device = NULL;
static KSPIN_LOCK g_RingLock;
static FA_EVENT* g_Ring = NULL;
static ULONG g_Head = 0;   // 下一个写入位置
static ULONG g_Count = 0;  // 当前缓冲条数
static ULONG g_Dropped = 0;
static volatile LONG g_ProtectedPid = 0;
static PVOID g_ObHandle = NULL;
static BOOLEAN g_ProcCb = FALSE, g_ImageCb = FALSE, g_ThreadCb = FALSE, g_RegCb = FALSE;

// 最近创建的进程（子 PID → 父 PID）。父进程为子进程创建首个线程属正常行为，
// 不能当作远程线程注入上报。
#define FA_RECENT 128
typedef struct _FA_RECENT_PROC { ULONG Pid; ULONG Ppid; } FA_RECENT_PROC;
static FA_RECENT_PROC g_Recent[FA_RECENT];
static ULONG g_RecentHead = 0;
static KSPIN_LOCK g_RecentLock;

static VOID FaRecentAdd(ULONG pid, ULONG ppid)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_RecentLock, &irql);
    g_Recent[g_RecentHead].Pid = pid;
    g_Recent[g_RecentHead].Ppid = ppid;
    g_RecentHead = (g_RecentHead + 1) % FA_RECENT;
    KeReleaseSpinLock(&g_RecentLock, irql);
}

static BOOLEAN FaRecentIsParent(ULONG pid, ULONG creator)
{
    KIRQL irql;
    ULONG i;
    BOOLEAN hit = FALSE;
    KeAcquireSpinLock(&g_RecentLock, &irql);
    for (i = 0; i < FA_RECENT; i++) {
        if (g_Recent[i].Pid == pid && g_Recent[i].Ppid == creator) { hit = TRUE; break; }
    }
    KeReleaseSpinLock(&g_RecentLock, irql);
    return hit;
}

static WCHAR FaUp(WCHAR c) { return (c >= L'a' && c <= L'z') ? (WCHAR)(c - 32) : c; }

// 大小写不敏感子串匹配（needle 须为大写）
BOOLEAN FaContains(PCUNICODE_STRING s, PCWSTR needle)
{
    USHORT n = s->Length / sizeof(WCHAR);
    USHORT m = 0, i, j;
    while (needle[m]) m++;
    if (!s->Buffer || m == 0 || n < m) return FALSE;
    for (i = 0; i + m <= n; i++) {
        for (j = 0; j < m; j++) {
            if (FaUp(s->Buffer[i + j]) != needle[j]) break;
        }
        if (j == m) return TRUE;
    }
    return FALSE;
}

static BOOLEAN FaPathHot(PCUNICODE_STRING p)
{
    if (!p || !p->Buffer || !p->Length) return FALSE;
    return FaContains(p, L"\\TEMP\\") || FaContains(p, L"\\TMP\\") ||
           FaContains(p, L"\\APPDATA\\") || FaContains(p, L"\\USERS\\PUBLIC\\") ||
           FaContains(p, L"\\DOWNLOADS\\");
}

VOID FaPush(ULONG type, ULONG pid, ULONG ppid, ULONG tid, PCUNICODE_STRING path)
{
    KIRQL irql;
    FA_EVENT* ev;
    if (!g_Ring) return;
    KeAcquireSpinLock(&g_RingLock, &irql);
    ev = &g_Ring[g_Head];
    RtlZeroMemory(ev, sizeof(*ev));
    ev->Type = type;
    ev->Pid = pid;
    ev->Ppid = ppid;
    ev->Tid = tid;
    KeQuerySystemTime(&ev->Time);
    if (path && path->Buffer && path->Length) {
        USHORT chars = path->Length / sizeof(WCHAR);
        // 保留路径尾部（文件名最有价值）
        USHORT start = chars > (FA_PATH_CHARS - 1) ? (USHORT)(chars - (FA_PATH_CHARS - 1)) : 0;
        RtlCopyMemory(ev->Path, path->Buffer + start, (chars - start) * sizeof(WCHAR));
    }
    g_Head = (g_Head + 1) % FA_RING_SIZE;
    if (g_Count < FA_RING_SIZE) {
        g_Count++;
    } else {
        g_Dropped++; // 覆盖最旧
    }
    KeReleaseSpinLock(&g_RingLock, irql);
}

static VOID FaProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    if (CreateInfo) {
        FaRecentAdd(HandleToULong(ProcessId), HandleToULong(CreateInfo->CreatingThreadId.UniqueProcess));
        FaPush(FA_EV_PROCESS_CREATE, HandleToULong(ProcessId),
               HandleToULong(CreateInfo->ParentProcessId), 0,
               CreateInfo->ImageFileName);
    } else {
        FaPush(FA_EV_PROCESS_EXIT, HandleToULong(ProcessId), 0, 0, NULL);
    }
}

static VOID FaImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    // 全量 DLL 加载量极大会挤爆环形缓冲：只留内核模块（驱动）与可疑目录映像
    BOOLEAN sysImage = ImageInfo && ImageInfo->SystemModeImage;
    if (!sysImage && !FaPathHot(FullImageName)) return;
    FaPush(FA_EV_IMAGE_LOAD, HandleToULong(ProcessId), 0, 0, FullImageName);
}

static VOID FaThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    HANDLE creator;
    ULONG target, from;
    if (!Create) return;
    creator = PsGetCurrentProcessId();
    target = HandleToULong(ProcessId);
    from = HandleToULong(creator);
    // 由其他进程在目标进程中创建线程 => 远程线程（排除 System 与父进程创建子进程首线程）
    if (creator != ProcessId && from > 4 && !FaRecentIsParent(target, from)) {
        FaPush(FA_EV_REMOTE_THREAD, target, from, HandleToULong(ThreadId), NULL);
    }
}

static BOOLEAN FaImageNameIs(PUCHAR img, const char* want)
{
    SIZE_T i;
    if (!img || !want) return FALSE;
    for (i = 0; want[i]; i++) {
        char a = img[i];
        char b = want[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
        if (a != b) return FALSE;
    }
    return (img[i] == 0);
}

static VOID FaObSensitiveOpen(POB_PRE_OPERATION_INFORMATION Info, ULONG target, ULONG requester)
{
    ACCESS_MASK acc = 0;
    ACCESS_MASK sensitive = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;
    if (Info->KernelHandle || requester <= 4 || requester == target) return;
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE)
        acc = Info->Parameters->CreateHandleInformation.DesiredAccess;
    else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        acc = Info->Parameters->DuplicateHandleInformation.DesiredAccess;
    else
        return;
    if (acc & sensitive)
        FaPush(FA_EV_PROCESS_OPEN, target, requester, (ULONG)acc, NULL);
}

static OB_PREOP_CALLBACK_STATUS FaObPre(PVOID Ctx, POB_PRE_OPERATION_INFORMATION Info)
{
    ULONG target;
    ULONG requester;
    ACCESS_MASK strip = PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                        PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD;
    PEPROCESS targetProc;
    UNREFERENCED_PARAMETER(Ctx);
    if (Info->ObjectType != *PsProcessType) return OB_PREOP_SUCCESS;
    targetProc = (PEPROCESS)Info->Object;
    target = HandleToULong(PsGetProcessId(targetProc));
    requester = HandleToULong(PsGetCurrentProcessId());

    if (FaImageNameIs(PsGetProcessImageFileName(targetProc), "lsass.exe"))
        FaObSensitiveOpen(Info, target, requester);

    if (g_ProtectedPid == 0 || Info->KernelHandle) return OB_PREOP_SUCCESS;
    if (target != (ULONG)g_ProtectedPid) return OB_PREOP_SUCCESS;
    if (requester == target) return OB_PREOP_SUCCESS;

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        if (Info->Parameters->CreateHandleInformation.DesiredAccess & strip) {
            Info->Parameters->CreateHandleInformation.DesiredAccess &= ~strip;
            FaPush(FA_EV_PROTECT_BLOCK, target, requester, 0, NULL);
        }
    } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        if (Info->Parameters->DuplicateHandleInformation.DesiredAccess & strip) {
            Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~strip;
            FaPush(FA_EV_PROTECT_BLOCK, target, requester, 0, NULL);
        }
    }
    return OB_PREOP_SUCCESS;
}

static NTSTATUS FaRegisterOb(VOID)
{
    OB_OPERATION_REGISTRATION op = { 0 };
    OB_CALLBACK_REGISTRATION reg = { 0 };
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"385201");
    op.ObjectType = PsProcessType;
    op.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    op.PreOperation = FaObPre;
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 1;
    reg.Altitude = altitude;
    reg.OperationRegistration = &op;
    return ObRegisterCallbacks(&reg, &g_ObHandle);
}

NTSTATUS FaCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS FaIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;
    ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS st = STATUS_SUCCESS;
    ULONG_PTR info = 0;
    UNREFERENCED_PARAMETER(DeviceObject);

    switch (code) {
    case IOCTL_FA_READ_EVENTS: {
        KIRQL irql;
        ULONG max = outLen / sizeof(FA_EVENT);
        ULONG n, i, tail;
        if (max == 0 || !buf) { st = STATUS_BUFFER_TOO_SMALL; break; }
        KeAcquireSpinLock(&g_RingLock, &irql);
        n = g_Count < max ? g_Count : max;
        tail = (g_Head + FA_RING_SIZE - g_Count) % FA_RING_SIZE; // 最旧一条
        for (i = 0; i < n; i++) {
            RtlCopyMemory((FA_EVENT*)buf + i, &g_Ring[(tail + i) % FA_RING_SIZE], sizeof(FA_EVENT));
        }
        g_Count -= n;
        KeReleaseSpinLock(&g_RingLock, irql);
        info = (ULONG_PTR)n * sizeof(FA_EVENT);
        break;
    }
    case IOCTL_FA_PROTECT_PID:
        if (inLen < sizeof(ULONG) || !buf) { st = STATUS_INVALID_PARAMETER; break; }
        InterlockedExchange(&g_ProtectedPid, (LONG)*(ULONG*)buf);
        break;
    case IOCTL_FA_GET_STATS: {
        PFA_STATS s = (PFA_STATS)buf;
        if (outLen < sizeof(FA_STATS) || !buf) { st = STATUS_BUFFER_TOO_SMALL; break; }
        s->Queued = g_Count;
        s->Dropped = g_Dropped;
        s->ProtectedPid = (ULONG)g_ProtectedPid;
        s->Reserved = (g_ProcCb ? 1 : 0) | (g_ImageCb ? 2 : 0) | (g_ThreadCb ? 4 : 0) |
                      (g_ObHandle ? 8 : 0) | (g_RegCb ? 16 : 0);
        info = sizeof(FA_STATS);
        break;
    }
    default:
        st = STATUS_INVALID_DEVICE_REQUEST;
    }
    Irp->IoStatus.Status = st;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return st;
}

VOID FaUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING link = RTL_CONSTANT_STRING(FA_SYMLINK_NAME);
    UNREFERENCED_PARAMETER(DriverObject);
    FaRegUnload();
    if (g_ObHandle) { ObUnRegisterCallbacks(g_ObHandle); g_ObHandle = NULL; }
    if (g_ThreadCb) PsRemoveCreateThreadNotifyRoutine(FaThreadNotify);
    if (g_ImageCb) PsRemoveLoadImageNotifyRoutine(FaImageNotify);
    if (g_ProcCb) PsSetCreateProcessNotifyRoutineEx(FaProcessNotify, TRUE);
    IoDeleteSymbolicLink(&link);
    if (g_Device) IoDeleteDevice(g_Device);
    if (g_Ring) { ExFreePoolWithTag(g_Ring, FA_TAG); g_Ring = NULL; }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(FA_DEVICE_NAME);
    UNICODE_STRING link = RTL_CONSTANT_STRING(FA_SYMLINK_NAME);
    NTSTATUS st;
    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&g_RingLock);
    KeInitializeSpinLock(&g_RecentLock);
    RtlZeroMemory(g_Recent, sizeof(g_Recent));
    g_Ring = (FA_EVENT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FA_EVENT) * FA_RING_SIZE, FA_TAG);
    if (!g_Ring) return STATUS_INSUFFICIENT_RESOURCES;

    // 仅 SYSTEM / 管理员可打开设备；否则普通用户可借 PROTECT_PID 保护任意进程
    st = IoCreateDeviceSecure(DriverObject, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
                              &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, NULL, &g_Device);
    if (!NT_SUCCESS(st)) { FaUnload(DriverObject); return st; }
    st = IoCreateSymbolicLink(&link, &name);
    if (!NT_SUCCESS(st)) { FaUnload(DriverObject); return st; }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = FaCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = FaCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FaIoctl;
    DriverObject->DriverUnload = FaUnload;

    g_ProcCb = NT_SUCCESS(PsSetCreateProcessNotifyRoutineEx(FaProcessNotify, FALSE));
    g_ImageCb = NT_SUCCESS(PsSetLoadImageNotifyRoutine(FaImageNotify));
    g_ThreadCb = NT_SUCCESS(PsSetCreateThreadNotifyRoutine(FaThreadNotify));
    if (!NT_SUCCESS(FaRegisterOb())) g_ObHandle = NULL;
    g_RegCb = NT_SUCCESS(FaRegInit(DriverObject));
    return STATUS_SUCCESS;
}
