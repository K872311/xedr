# FaKmon 内核监控驱动

**默认安装包不再下发、不安装本驱动**（测试过程有蓝屏风险；生产需正式签名与充分验证）。

以下为实验室可选能力：驱动加载后 Agent 可上报 `kernel_*` 时间线；未加载时使用 ETW / WMI / 事件日志等用户态采集，不影响运行。

| 能力 | 内核接口 | 时间线 etype |
| --- | --- | --- |
| 进程创建 / 退出 | `PsSetCreateProcessNotifyRoutineEx` | `process_create_kernel` / `process_exit_kernel` |
| 映像加载（DLL/驱动） | `PsSetLoadImageNotifyRoutine` | `image_load_kernel`（仅上报可疑路径） |
| 远程线程（注入面） | `PsSetCreateThreadNotifyRoutine` | `remote_thread_kernel` |
| Agent 进程防结束 / 防写内存 | `ObRegisterCallbacks` | `protect_block_kernel` |
| 打开 lsass（VM 读/写/线程等） | `ObRegisterCallbacks` | `process_access_kernel` |
| ASEP 注册表写入 | `CmRegisterCallbackEx` | `registry_write_kernel` |
| Agent 服务注册表键防篡改 | `CmRegisterCallbackEx` | `reg_protect_kernel` |

> **Minifilter 文件自保护**：尚未接入（需 FltMgr 与独立 altitude）；当前文件完整性仍由用户态 FIM 负责。

## 编译

需要 Visual Studio + WDK（Windows Driver Kit）。

**一键检测 / 编译（推荐）**：

```powershell
cd agent\driver
.\build-driver.ps1 -CheckOnly   # 只看 VS / WDK / 测试签名 / 服务是否就绪
.\build-driver.ps1              # 有工具链则编出 out\fakmon.sys
.\build-driver.ps1 -Install     # 编完后复制到 ProgramData 并 sc create/start
```

若脚本因环境差异编不过，可手动：

1. VS 新建 “Kernel Mode Driver, Empty (KMDF)” 或 WDM 空项目，加入 `fakmon.c`、`fakmon.h`。
2. 链接器 → 命令行追加 `/INTEGRITYCHECK`（`PsSetCreateProcessNotifyRoutineEx` 与 `ObRegisterCallbacks` 强制要求）。
3. 目标平台 x64，Release 生成 `fakmon.sys`。

## 签名与安装

生产环境必须使用 EV 证书并经微软 Attestation 签名。测试环境：

```bat
bcdedit /set testsigning on
:: 重启后
sc create FaKmon type= kernel start= auto binPath= C:\ProgramData\ForensicAgent\fakmon.sys
sc start FaKmon
```

卸载：`sc stop FaKmon && sc delete FaKmon`。

## 协议

`fakmon.h` 中 `FA_EVENT` 的布局与 `agent/driver_windows.go` 中的 `faEvent` 一一对应，修改任一侧都要同步另一侧。
