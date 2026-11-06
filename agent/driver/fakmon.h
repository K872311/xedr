// ForensicAgent 内核监控驱动与用户态共享的协议定义。
// Go 侧镜像：agent/driver_windows.go（字段顺序与大小必须一致）。
#pragma once

#define FA_DEVICE_NAME   L"\\Device\\FaKmon"
#define FA_SYMLINK_NAME  L"\\DosDevices\\FaKmon"

#define FA_DEVICE_TYPE 0x8A00
#define IOCTL_FA_READ_EVENTS   CTL_CODE(FA_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_FA_PROTECT_PID   CTL_CODE(FA_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_FA_GET_STATS     CTL_CODE(FA_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)

#define FA_EV_PROCESS_CREATE  1
#define FA_EV_PROCESS_EXIT    2
#define FA_EV_IMAGE_LOAD      3
#define FA_EV_REMOTE_THREAD   4
#define FA_EV_PROTECT_BLOCK   5
#define FA_EV_PROCESS_OPEN    6   // 打开 lsass 等敏感进程；Tid=DesiredAccess
#define FA_EV_REGISTRY        7   // 注册表 ASEP 写入；Path=键路径
#define FA_EV_REG_PROTECT     8   // 拦截对 Agent 服务键的篡改

#define FA_PATH_CHARS 260
#define FA_RING_SIZE  4096

#pragma pack(push, 8)
typedef struct _FA_EVENT {
    ULONG Type;
    ULONG Pid;
    ULONG Ppid;        // 进程创建：父进程；远程线程：发起进程；保护拦截：请求方
    ULONG Tid;
    LARGE_INTEGER Time; // KeQuerySystemTime，100ns since 1601
    WCHAR Path[FA_PATH_CHARS];
} FA_EVENT, *PFA_EVENT;

typedef struct _FA_STATS {
    ULONG Queued;
    ULONG Dropped;
    ULONG ProtectedPid;
    ULONG Reserved;
} FA_STATS, *PFA_STATS;
#pragma pack(pop)
