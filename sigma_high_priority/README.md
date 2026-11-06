# Sigma 高危规则候选（level=high/critical，Windows）

源目录: `D:\360极速浏览器X下载\sigma_all_rules`
筛选结果: **1273** 条 high/critical（Windows 相关）

## 已导入后端

- **eventlog_sigma（202）** → `log_rules/rules/SigmaHQ_*.yml`
- **file / process / registry / driver** → 已写入 `rules/` JSON（`source=sigma_high_priority`）
  - `rules-files.json` ← 路径/文件名 IOC
  - `rules-keywords.json` ← 进程/命令行关键字（新建）
  - `rules-windows-system.json` ← 注册表 / 服务 / 计划任务
- 重导脚本：`import_eventlog.py`、`import_json_rules.py`
- 清单：`imported_eventlog.txt`、`imported_json.txt`

## 分桶统计

- **process_lolbin**: 631  — 进程/命令行 → 关键词或 process 规则
- **eventlog_sigma**: 202  — 可直接进 log_rules/rules（事件日志）
- **registry_persist**: 140  — 注册表持久化 → rules-windows-system.json
- **skip_sysmon_deep**: 125  — 依赖 Sysmon 深度事件，本平台默认跳过
- **file_path_ioc**: 104  — 路径 IOC → rules-files.json（多数需 Sysmon 原规则，取路径）
- **eventlog_or_review**: 41  — 需人工看是否可映射事件日志
- **review**: 20  — 待人工分类
- **driver_ioc**: 10  — 驱动名 IOC

## eventlog_sigma (202)

| level | title | category/service | file |
|---|---|---|---|
| critical | Active Directory Replication from Non Machine Account | security | `rules/windows/builtin/security/win_security_ad_replication_non_machine_account.yml` |
| critical | AD Object WriteDAC Access | security | `rules/windows/builtin/security/win_security_ad_object_writedac_access.yml` |
| critical | Bad Opsec Powershell Code Artifacts | ps_module | `rules/windows/powershell/powershell_module/posh_pm_bad_opsec_artifacts.yml` |
| critical | CobaltStrike Service Installations - System | system | `rules/windows/builtin/system/service_control_manager/win_system_cobaltstrike_service_installs.yml` |
| critical | DiagTrackEoP Default Login Username | security | `rules/windows/builtin/security/account_management/win_security_diagtrack_eop_default_login_username.yml` |
| critical | Moriya Rootkit - System | system | `rules/windows/builtin/system/service_control_manager/win_system_moriya_rootkit.yml` |
| critical | RedSun - TieringEngineService.exe Detected as EICAR Test File | windefend | `rules-emerging-threats/2026/Exploits/RedSun/win_defender_exploit_redsun_tiering_engine_detected_as_eicar.yml` |
| critical | Silence.EDA Detection | ps_script | `rules/windows/powershell/powershell_script/posh_ps_apt_silence_eda.yml` |
| critical | Suspicious PowerShell Mailbox Export to Share - PS | ps_script | `rules/windows/powershell/powershell_script/posh_ps_mailboxexport_share.yml` |
| critical | WCE wceaux.dll Access | security | `rules/windows/builtin/security/win_security_mal_wceaux_dll.yml` |
| critical | Win Susp Computer Name Containing Samtheadmin | security | `rules/windows/builtin/security/win_security_susp_computer_name.yml` |
| critical | Zerologon Exploitation Using Well-known Tools | system | `rules/windows/builtin/system/netlogon/win_system_possible_zerologon_exploitation_using_wellknown_tools.yml` |
| high | AADInternals PowerShell Cmdlets Execution - PsScript | ps_script | `rules/windows/powershell/powershell_script/posh_ps_aadinternals_cmdlets_execution.yml` |
| high | Abuse of Service Permissions to Hide Services Via Set-Service - PS | ps_script | `rules/windows/powershell/powershell_script/posh_ps_using_set_service_to_hide_services.yml` |
| high | Active Directory User Backdoors | security | `rules/windows/builtin/security/win_security_alert_ad_user_backdoors.yml` |
| high | AD Privileged Users or Groups Reconnaissance | security | `rules/windows/builtin/security/win_security_account_discovery.yml` |
| high | ADCS Certificate Template Configuration Vulnerability with Risky EKU | security | `rules/windows/builtin/security/win_security_adcs_certificate_template_configuration_vulnerability_eku.yml` |
| high | AMSI Bypass Pattern Assembly GetType | ps_script | `rules/windows/powershell/powershell_script/posh_ps_amsi_bypass_pattern_nov22.yml` |
| high | Clearing Windows Console History | ps_script | `rules/windows/powershell/powershell_script/posh_ps_clearing_windows_console_history.yml` |
| high | CobaltStrike Service Installations - Security | security | `rules/windows/builtin/security/win_security_cobaltstrike_service_installs.yml` |
| high | Code Executed Via Office Add-in XLL File | ps_script | `rules/windows/powershell/powershell_script/posh_ps_office_comobject_registerxll.yml` |
| high | Create Volume Shadow Copy with Powershell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_create_volume_shadow_copy.yml` |
| high | Credential Dumping Tools Service Execution - Security | security | `rules/windows/builtin/security/win_security_mal_creddumper.yml` |
| high | Credential Dumping Tools Service Execution - System | system | `rules/windows/builtin/system/service_control_manager/win_system_mal_creddumper.yml` |
| high | Critical Hive In Suspicious Location Access Bits Cleared | system | `rules/windows/builtin/system/microsoft_windows_kernel_general/win_system_susp_critical_hive_location_access_bits_cleared.yml` |
| high | DCOM InternetExplorer.Application Iertutil DLL Hijack - Security | security | `rules/windows/builtin/security/win_security_dcom_iertutil_dll_hijack.yml` |
| high | Delete Volume Shadow Copies Via WMI With PowerShell | ps_classic_start | `rules/windows/powershell/powershell_classic/posh_pc_delete_volume_shadow_copies.yml` |
| high | Deletion of Volume Shadow Copies via WMI with PowerShell - PS Script | ps_script | `rules/windows/powershell/powershell_script/posh_ps_susp_win32_shadowcopy_deletion.yml` |
| high | DHCP Server Error Failed Loading the CallOut DLL | system | `rules/windows/builtin/system/microsoft_windows_dhcp_server/win_system_susp_dhcp_config_failed.yml` |
| high | DHCP Server Loaded the CallOut DLL | system | `rules/windows/builtin/system/microsoft_windows_dhcp_server/win_system_susp_dhcp_config.yml` |
| high | Disable of ETW Trace - Powershell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_etw_trace_evasion.yml` |
| high | Disable Powershell Command History | ps_script | `rules/windows/powershell/powershell_script/posh_ps_disable_psreadline_command_history.yml` |
| high | Disable-WindowsOptionalFeature Command PowerShell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_disable_windows_optional_feature.yml` |
| high | DNS Server Error Failed Loading the ServerLevelPluginDLL | dns-server | `rules/windows/builtin/dns_server/win_dns_server_susp_server_level_plugin_dll.yml` |
| high | DPAPI Domain Backup Key Extraction | security | `rules/windows/builtin/security/win_security_dpapi_domain_backupkey_extraction.yml` |
| high | DSInternals Suspicious PowerShell Cmdlets - ScriptBlock | ps_script | `rules/windows/powershell/powershell_script/posh_ps_dsinternals_cmdlets.yml` |
| high | Enabled User Right in AD to Control User Objects | security | `rules/windows/builtin/security/win_security_alert_active_directory_user_control.yml` |
| high | ETW Logging Disabled In .NET Processes - Registry | security | `rules/windows/builtin/security/win_security_dot_net_etw_tamper.yml` |
| high | External Remote SMB Logon from Public IP | security | `rules/windows/builtin/security/account_management/win_security_successful_external_remote_smb_login.yml` |
| high | First Time Seen Remote Named Pipe | security | `rules/windows/builtin/security/win_security_lm_namedpipe.yml` |
| high | HackTool - EDRSilencer Execution - Filter Added | security | `rules/windows/builtin/security/win_security_hktl_edr_silencer.yml` |
| high | HackTool - Evil-WinRm Execution - PowerShell Module | ps_module | `rules/windows/powershell/powershell_module/posh_pm_hktl_evil_winrm_execution.yml` |
| high | HackTool - NoFilter Execution | security | `rules/windows/builtin/security/win_security_hktl_nofilter.yml` |
| high | HackTool - Rubeus Execution - ScriptBlock | ps_script | `rules/windows/powershell/powershell_script/posh_ps_hktl_rubeus.yml` |
| high | HackTool - WinPwn Execution - ScriptBlock | ps_script | `rules/windows/powershell/powershell_script/posh_ps_hktl_winpwn.yml` |
| high | Hacktool Ruler | security | `rules/windows/builtin/security/win_security_alert_ruler.yml` |
| high | HackTool Service Registration or Execution | system | `rules/windows/builtin/system/service_control_manager/win_system_service_install_hacktools.yml` |
| high | Hidden Local User Creation | security | `rules/windows/builtin/security/win_security_hidden_user_creation.yml` |
| high | HybridConnectionManager Service Installation | security | `rules/windows/builtin/security/win_security_hybridconnectionmgr_svc_installation.yml` |
| high | Impacket PsExec Execution | security | `rules/windows/builtin/security/win_security_impacket_psexec.yml` |
| high | Important Scheduled Task Deleted or Disabled | taskscheduler | `rules/windows/builtin/taskscheduler/win_taskscheduler_susp_schtasks_delete_or_disable.yml` |
| high | Important Scheduled Task Deleted/Disabled | security | `rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable.yml` |
| high | Important Windows Event Auditing Disabled | security | `rules/windows/builtin/security/win_security_disable_event_auditing_critical.yml` |
| high | Important Windows Eventlog Cleared | system | `rules/windows/builtin/system/microsoft_windows_eventlog/win_system_susp_eventlog_cleared.yml` |
| high | Important Windows Service Terminated Unexpectedly | system | `rules/windows/builtin/system/service_control_manager/win_system_service_terminated_unexpectedly.yml` |
| high | Important Windows Service Terminated With Error | system | `rules/windows/builtin/system/service_control_manager/win_system_service_terminated_error_important.yml` |
| high | Invoke-Obfuscation CLIP+ Launcher - PowerShell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_clip.yml` |
| high | Invoke-Obfuscation CLIP+ Launcher - PowerShell Module | ps_module | `rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_clip.yml` |
| high | Invoke-Obfuscation CLIP+ Launcher - Security | security | `rules/windows/builtin/security/win_security_invoke_obfuscation_clip_services_security.yml` |
| high | Invoke-Obfuscation CLIP+ Launcher - System | system | `rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_clip_services.yml` |
| high | Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_obfuscated_iex.yml` |
| high | Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell Module | ps_module | `rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_obfuscated_iex.yml` |
| high | Invoke-Obfuscation Obfuscated IEX Invocation - Security | security | `rules/windows/builtin/security/win_security_invoke_obfuscation_obfuscated_iex_services_security.yml` |
| high | Invoke-Obfuscation Obfuscated IEX Invocation - System | system | `rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_obfuscated_iex_services.yml` |
| high | Invoke-Obfuscation STDIN+ Launcher - Powershell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_stdin.yml` |
| high | Invoke-Obfuscation STDIN+ Launcher - PowerShell Module | ps_module | `rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_stdin.yml` |
| high | Invoke-Obfuscation STDIN+ Launcher - Security | security | `rules/windows/builtin/security/win_security_invoke_obfuscation_stdin_services_security.yml` |
| high | Invoke-Obfuscation STDIN+ Launcher - System | system | `rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_stdin_services.yml` |
| high | Invoke-Obfuscation VAR+ Launcher - PowerShell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_var.yml` |
| high | Invoke-Obfuscation VAR+ Launcher - PowerShell Module | ps_module | `rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_var.yml` |
| high | Invoke-Obfuscation VAR+ Launcher - Security | security | `rules/windows/builtin/security/win_security_invoke_obfuscation_var_services_security.yml` |
| high | Invoke-Obfuscation VAR+ Launcher - System | system | `rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_var_services.yml` |
| high | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_var.yml` |
| high | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell Module | ps_module | `rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_var.yml` |
| high | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - Security | security | `rules/windows/builtin/security/win_security_invoke_obfuscation_via_var_services_security.yml` |
| high | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - System | system | `rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_var_services.yml` |
| high | Invoke-Obfuscation Via Stdin - Powershell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_stdin.yml` |
| high | Invoke-Obfuscation Via Stdin - PowerShell Module | ps_module | `rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_stdin.yml` |
| high | Invoke-Obfuscation Via Stdin - Security | security | `rules/windows/builtin/security/win_security_invoke_obfuscation_via_stdin_services_security.yml` |
| high | Invoke-Obfuscation Via Stdin - System | system | `rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_stdin_services.yml` |
| high | Invoke-Obfuscation Via Use Clip - Powershell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_clip.yml` |
| high | Invoke-Obfuscation Via Use Clip - PowerShell Module | ps_module | `rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_use_clip.yml` |
| high | Invoke-Obfuscation Via Use Clip - Security | security | `rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_clip_services_security.yml` |
| high | Invoke-Obfuscation Via Use Clip - System | system | `rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_clip_services.yml` |
| high | Invoke-Obfuscation Via Use MSHTA - PowerShell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_mhsta.yml` |
| high | Invoke-Obfuscation Via Use MSHTA - PowerShell Module | ps_module | `rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_use_mhsta.yml` |
| high | Invoke-Obfuscation Via Use MSHTA - Security | security | `rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_mshta_services_security.yml` |
| high | Invoke-Obfuscation Via Use MSHTA - System | system | `rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_mshta_services.yml` |
| high | Invoke-Obfuscation Via Use Rundll32 - PowerShell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_rundll32.yml` |
| high | Invoke-Obfuscation Via Use Rundll32 - PowerShell Module | ps_module | `rules/windows/powershell/powershell_module/posh_pm_invoke_obfuscation_via_use_rundll32.yml` |
| high | Invoke-Obfuscation Via Use Rundll32 - Security | security | `rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_rundll32_services_security.yml` |
| high | Invoke-Obfuscation Via Use Rundll32 - System | system | `rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_rundll32_services.yml` |
| high | Kerberos Manipulation | security | `rules/windows/builtin/security/win_security_susp_kerberos_manipulation.yml` |
| high | KrbRelayUp Service Installation | system | `rules/windows/builtin/system/service_control_manager/win_system_krbrelayup_service_installation.yml` |
| high | Live Memory Dump Using Powershell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_memorydump_getstoragediagnosticinfo.yml` |
| high | Local Privilege Escalation Indicator TabTip | system | `rules/windows/builtin/system/microsoft_windows_distributed_com/win_system_lpe_indicators_tabtip.yml` |
| high | LSASS Access Detected via Attack Surface Reduction | windefend | `rules/windows/builtin/windefend/win_defender_asr_lsass_access.yml` |
| high | Malicious Nishang PowerShell Commandlets | ps_script | `rules/windows/powershell/powershell_script/posh_ps_nishang_malicious_commandlets.yml` |
| high | Malicious PowerShell Commandlets - PoshModule | ps_module | `rules/windows/powershell/powershell_module/posh_pm_malicious_commandlets.yml` |
| high | Malicious PowerShell Commandlets - ScriptBlock | ps_script | `rules/windows/powershell/powershell_script/posh_ps_malicious_commandlets.yml` |
| high | Malicious PowerShell Scripts - PoshModule | ps_module | `rules/windows/powershell/powershell_module/posh_pm_exploit_scripts.yml` |
| high | Malicious ShellIntel PowerShell Commandlets | ps_script | `rules/windows/powershell/powershell_script/posh_ps_shellintel_malicious_commandlets.yml` |
| high | Metasploit Or Impacket Service Installation Via SMB PsExec | security | `rules/windows/builtin/security/win_security_metasploit_or_impacket_smb_psexec_service_install.yml` |
| high | Metasploit SMB Authentication | security | `rules/windows/builtin/security/win_security_metasploit_authentication.yml` |
| high | Meterpreter or Cobalt Strike Getsystem Service Installation - Security | security | `rules/windows/builtin/security/win_security_meterpreter_or_cobaltstrike_getsystem_service_install.yml` |
| high | Meterpreter or Cobalt Strike Getsystem Service Installation - System | system | `rules/windows/builtin/system/service_control_manager/win_system_meterpreter_or_cobaltstrike_getsystem_service_installation.yml` |
| high | Microsoft Defender Tamper Protection Trigger | windefend | `rules/windows/builtin/windefend/win_defender_tamper_protection_trigger.yml` |
| high | Mimikatz DC Sync | security | `rules/windows/builtin/security/win_security_dcsync.yml` |
| high | NetNTLM Downgrade Attack | security | `rules/windows/builtin/security/win_security_net_ntlm_downgrade.yml` |
| high | NTFS Alternate Data Stream | ps_script | `rules/windows/powershell/powershell_script/posh_ps_ntfs_ads_access.yml` |
| high | NTFS Vulnerability Exploitation | system | `rules/windows/builtin/system/ntfs/win_system_ntfs_vuln_exploit.yml` |
| high | Password Change on Directory Service Restore Mode (DSRM) Account | security | `rules/windows/builtin/security/win_security_susp_dsrm_password_change.yml` |
| high | Password Dumper Activity on LSASS | security | `rules/windows/builtin/security/win_security_susp_lsass_dump.yml` |
| high | Password Protected ZIP File Opened (Email Attachment) | security | `rules/windows/builtin/security/win_security_susp_opened_encrypted_zip_outlook.yml` |
| high | Password Protected ZIP File Opened (Suspicious Filenames) | security | `rules/windows/builtin/security/win_security_susp_opened_encrypted_zip_filename.yml` |
| high | Persistence and Execution at Scale via GPO Scheduled Task | security | `rules/windows/builtin/security/win_security_gpo_scheduledtasks.yml` |
| high | PetitPotam Suspicious Kerberos TGT Request | security | `rules/windows/builtin/security/win_security_petitpotam_susp_tgt_request.yml` |
| high | Possible Impacket SecretDump Remote Activity | security | `rules/windows/builtin/security/win_security_impacket_secretdump.yml` |
| high | Possible PetitPotam Coerce Authentication Attempt | security | `rules/windows/builtin/security/win_security_petitpotam_network_share.yml` |
| high | Possible Shadow Credentials Added | security | `rules/windows/builtin/security/win_security_susp_possible_shadow_credentials_added.yml` |
| high | Potential Invoke-Mimikatz PowerShell Script | ps_script | `rules/windows/powershell/powershell_script/posh_ps_potential_invoke_mimikatz.yml` |
| high | Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation | security | `rules/windows/builtin/security/win_security_kerberos_coercion_via_dns_object.yml` |
| high | Potential Persistence Via Security Descriptors - ScriptBlock | ps_script | `rules/windows/powershell/powershell_script/posh_ps_susp_ace_tampering.yml` |
| high | Potential Privilege Escalation via Local Kerberos Relay over LDAP | security | `rules/windows/builtin/security/account_management/win_security_susp_privesc_kerberos_relay_over_ldap.yml` |
| high | Potential RemoteFXvGPUDisablement.EXE Abuse | powershell-classic | `rules/windows/powershell/powershell_classic/posh_pc_remotefxvgpudisablement_abuse.yml` |
| high | Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module | ps_module | `rules/windows/powershell/powershell_module/posh_pm_remotefxvgpudisablement_abuse.yml` |
| high | Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell ScriptBlock | ps_script | `rules/windows/powershell/powershell_script/posh_ps_remotefxvgpudisablement_abuse.yml` |
| high | Potential WinAPI Calls Via PowerShell Scripts | ps_script | `rules/windows/powershell/powershell_script/posh_ps_win_api_susp_access.yml` |
| high | Powershell Add Name Resolution Policy Table Rule | ps_script | `rules/windows/powershell/powershell_script/posh_ps_add_dnsclient_rule.yml` |
| high | PowerShell ADRecon Execution | ps_script | `rules/windows/powershell/powershell_script/posh_ps_adrecon_execution.yml` |
| high | PowerShell Called from an Executable Version Mismatch | ps_classic_start | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` |
| high | PowerShell Credential Prompt | ps_script | `rules/windows/powershell/powershell_script/posh_ps_prompt_credentials.yml` |
| high | Powershell DNSExfiltration | ps_script | `rules/windows/powershell/powershell_script/posh_ps_invoke_dnsexfiltration.yml` |
| high | PowerShell Get-Process LSASS in ScriptBlock | ps_script | `rules/windows/powershell/powershell_script/posh_ps_susp_getprocess_lsass.yml` |
| high | Powershell Install a DLL in System Directory | ps_script | `rules/windows/powershell/powershell_script/posh_ps_copy_item_system_directory.yml` |
| high | PowerShell PSAttack | ps_script | `rules/windows/powershell/powershell_script/posh_ps_psattack.yml` |
| high | PowerShell Scripts Installed as Services | system | `rules/windows/builtin/system/service_control_manager/win_system_powershell_script_installed_as_service.yml` |
| high | PowerShell Scripts Installed as Services - Security | security | `rules/windows/builtin/security/win_security_powershell_script_installed_as_service.yml` |
| high | PowerShell Set-Acl On Windows Folder - PsScript | ps_script | `rules/windows/powershell/powershell_script/posh_ps_set_acl_susp_location.yml` |
| high | PowerShell ShellCode | ps_script | `rules/windows/powershell/powershell_script/posh_ps_shellcode_b64.yml` |
| high | PowerShell Web Access Installation - PsScript | ps_script | `rules/windows/powershell/powershell_script/posh_ps_powershell_web_access_installation.yml` |
| high | Powerview Add-DomainObjectAcl DCSync AD Extend Right | security | `rules/windows/builtin/security/win_security_account_backdoor_dcsync_rights.yml` |
| high | PowerView PowerShell Cmdlets - ScriptBlock | ps_script | `rules/windows/powershell/powershell_script/posh_ps_powerview_malicious_commandlets.yml` |
| high | ProcessHacker Privilege Elevation | system | `rules/windows/builtin/system/service_control_manager/win_system_service_install_pua_proceshacker.yml` |
| high | Protected Storage Service Access | security | `rules/windows/builtin/security/win_security_protected_storage_service_access.yml` |
| high | PSAsyncShell - Asynchronous TCP Reverse Shell | ps_script | `rules/windows/powershell/powershell_script/posh_ps_psasyncshell.yml` |
| high | PSExec and WMI Process Creations Block | windefend | `rules/windows/builtin/windefend/win_defender_asr_psexec_wmi.yml` |
| high | RDP Login from Localhost | security | `rules/windows/builtin/security/account_management/win_security_rdp_localhost_login.yml` |
| high | RDP over Reverse SSH Tunnel WFP | security | `rules/windows/builtin/security/win_security_rdp_reverse_tunnel.yml` |
| high | Reconnaissance Activity | security | `rules/windows/builtin/security/win_security_susp_net_recon_activity.yml` |
| high | Register new Logon Process by Rubeus | security | `rules/windows/builtin/security/win_security_register_new_logon_process_by_rubeus.yml` |
| high | Remote PowerShell Session (PS Module) | ps_module | `rules/windows/powershell/powershell_module/posh_pm_remote_powershell_session.yml` |
| high | Remote PowerShell Sessions Network Connections (WinRM) | security | `rules/windows/builtin/security/win_security_remote_powershell_session.yml` |
| high | Replay Attack Detected | security | `rules/windows/builtin/security/win_security_replay_attack_detected.yml` |
| high | RottenPotato Like Attack Pattern | security | `rules/windows/builtin/security/account_management/win_security_susp_rottenpotato.yml` |
| high | RTCore Suspicious Service Installation | system | `rules/windows/builtin/system/service_control_manager/win_system_susp_rtcore64_service_install.yml` |
| high | SAM Registry Hive Handle Request | security | `rules/windows/builtin/security/win_security_sam_registry_hive_handle_request.yml` |
| high | Security Eventlog Cleared | security | `rules/windows/builtin/security/win_security_audit_log_cleared.yml` |
| high | Service Installation with Suspicious Folder Pattern | system | `rules/windows/builtin/system/service_control_manager/win_system_susp_service_installation_folder_pattern.yml` |
| high | Service Installed By Unusual Client - Security | security | `rules/windows/builtin/security/win_security_service_installation_by_unusal_client.yml` |
| high | Service Installed By Unusual Client - System | system | `rules/windows/builtin/system/service_control_manager/win_system_service_install_sups_unusal_client.yml` |
| high | Sliver C2 Default Service Installation | system | `rules/windows/builtin/system/service_control_manager/win_system_service_install_sliver.yml` |
| high | SMB Create Remote File Admin Share | security | `rules/windows/builtin/security/win_security_smb_file_creation_admin_shares.yml` |
| high | smbexec.py Service Installation | system | `rules/windows/builtin/system/service_control_manager/win_system_hack_smbexec.yml` |
| high | Successful Overpass the Hash Attempt | security | `rules/windows/builtin/security/account_management/win_security_overpass_the_hash.yml` |
| high | Suspicious Get-ADDBAccount Usage | ps_module | `rules/windows/powershell/powershell_module/posh_pm_get_addbaccount.yml` |
| high | Suspicious Kerberos Ticket Request via PowerShell Script - ScriptBlock | ps_script | `rules/windows/powershell/powershell_script/posh_ps_request_kerberos_ticket.yml` |
| high | Suspicious LDAP-Attributes Used | security | `rules/windows/builtin/security/win_security_susp_ldap_dataexchange.yml` |
| high | Suspicious PowerShell Invocations - Generic | ps_script | `rules/windows/powershell/powershell_script/posh_ps_susp_invocation_generic.yml` |
| high | Suspicious PowerShell Invocations - Generic - PowerShell Module | ps_module | `rules/windows/powershell/powershell_module/posh_pm_susp_invocation_generic.yml` |
| high | Suspicious PowerShell Invocations - Specific | ps_script | `rules/windows/powershell/powershell_script/posh_ps_susp_invocation_specific.yml` |
| high | Suspicious PowerShell Invocations - Specific - PowerShell Module | ps_module | `rules/windows/powershell/powershell_module/posh_pm_susp_invocation_specific.yml` |
| high | Suspicious PsExec Execution | security | `rules/windows/builtin/security/win_security_susp_psexec.yml` |
| high | Suspicious Scheduled Task Creation | security | `rules/windows/builtin/security/win_security_susp_scheduled_task_creation.yml` |
| high | Suspicious Scheduled Task Update | security | `rules/windows/builtin/security/win_security_susp_scheduled_task_update.yml` |
| high | Suspicious Service DACL Modification Via Set-Service Cmdlet - PS | ps_script | `rules/windows/powershell/powershell_script/posh_ps_susp_service_dacl_modification_set_service.yml` |
| high | Suspicious Service Installation | system | `rules/windows/builtin/system/service_control_manager/win_system_service_install_susp.yml` |
| high | Suspicious Service Installation Script | system | `rules/windows/builtin/system/service_control_manager/win_system_susp_service_installation_script.yml` |
| high | Suspicious Teams Application Related ObjectAcess Event | security | `rules/windows/builtin/security/win_security_teams_suspicious_objectaccess.yml` |
| high | Suspicious Windows ANONYMOUS LOGON Local Account Created | security | `rules/windows/builtin/security/win_security_susp_local_anon_logon_created.yml` |
| high | SysKey Registry Keys Access | security | `rules/windows/builtin/security/win_security_syskey_registry_access.yml` |
| high | Sysmon Application Crashed | system | `rules/windows/builtin/system/application_popup/win_system_application_sysmon_crash.yml` |
| high | Sysmon Channel Reference Deletion | security | `rules/windows/builtin/security/win_security_sysmon_channel_reference_deletion.yml` |
| high | T1047 Wmiprvse Wbemcomn DLL Hijack | security | `rules/windows/builtin/security/win_security_wmiprvse_wbemcomn_dll_hijack.yml` |
| high | Tamper Windows Defender - PSClassic | ps_classic_provider_start | `rules/windows/powershell/powershell_classic/posh_pc_tamper_windows_defender_set_mp.yml` |
| high | Tamper Windows Defender - ScriptBlockLogging | ps_script | `rules/windows/powershell/powershell_script/posh_ps_tamper_windows_defender_set_mp.yml` |
| high | Tamper Windows Defender Remove-MpPreference - ScriptBlockLogging | ps_script | `rules/windows/powershell/powershell_script/posh_ps_tamper_windows_defender_rem_mp.yml` |
| high | User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess' | security | `rules/windows/builtin/security/win_security_user_couldnt_call_priv_service_lsaregisterlogonprocess.yml` |
| high | Veeam Backup Servers Credential Dumping Script Execution | ps_script | `rules/windows/powershell/powershell_script/posh_ps_veeam_credential_dumping_script.yml` |
| high | Vulnerable Netlogon Secure Channel Connection Allowed | system | `rules/windows/builtin/system/netlogon/win_system_vul_cve_2020_1472.yml` |
| high | Weak Encryption Enabled and Kerberoast | security | `rules/windows/builtin/security/win_security_alert_enable_weak_encryption.yml` |
| high | Win Defender Restored Quarantine File | windefend | `rules/windows/builtin/windefend/win_defender_restored_quarantine_file.yml` |
| high | Windows Defender AMSI Trigger Detected | windefend | `rules/windows/builtin/windefend/win_defender_malware_detected_amsi_source.yml` |
| high | Windows Defender Configuration Changes | windefend | `rules/windows/builtin/windefend/win_defender_suspicious_features_tampering.yml` |
| high | Windows Defender Exploit Guard Tamper | windefend | `rules/windows/builtin/windefend/win_defender_config_change_exploit_guard_tamper.yml` |
| high | Windows Defender Grace Period Expired | windefend | `rules/windows/builtin/windefend/win_defender_antimalware_platform_expired.yml` |
| high | Windows Defender Malware And PUA Scanning Disabled | windefend | `rules/windows/builtin/windefend/win_defender_malware_and_pua_scan_disabled.yml` |
| high | Windows Defender Real-time Protection Disabled | windefend | `rules/windows/builtin/windefend/win_defender_real_time_protection_disabled.yml` |
| high | Windows Defender Threat Detected | windefend | `rules/windows/builtin/windefend/win_defender_threat.yml` |
| high | Windows Defender Virus Scanning Feature Disabled | windefend | `rules/windows/builtin/windefend/win_defender_virus_scan_disabled.yml` |
| high | Windows Filtering Platform Blocked Connection From EDR Agent Binary | security | `rules/windows/builtin/security/object_access/win_security_wfp_endpoint_agent_blocked.yml` |
| high | WMImplant Hack Tool | ps_script | `rules/windows/powershell/powershell_script/posh_ps_wmimplant.yml` |

## process_lolbin (631)

| level | title | category/service | file |
|---|---|---|---|
| critical | DumpStack.log Defender Evasion | process_creation | `rules/windows/process_creation/proc_creation_win_susp_dumpstack_log_evasion.yml` |
| critical | HackTool - DInjector PowerShell Cradle Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_dinjector.yml` |
| critical | HackTool - Dumpert Process Dumper Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_dumpert.yml` |
| critical | HackTool - Empire PowerShell UAC Bypass | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_empire_powershell_uac_bypass.yml` |
| critical | HackTool - F-Secure C3 Load by Rundll32 | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_c3_rundll32_pattern.yml` |
| critical | HackTool - Inveigh Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_inveigh.yml` |
| critical | HackTool - PurpleSharp Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_purplesharp_indicators.yml` |
| critical | HackTool - Rubeus Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_rubeus.yml` |
| critical | HackTool - SafetyKatz Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_safetykatz.yml` |
| critical | HackTool - SecurityXploded Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_secutyxploded.yml` |
| critical | HackTool - SharpUp PrivEsc Tool Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_sharpup.yml` |
| critical | HackTool - Sliver C2 Implant Activity Pattern | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_sliver_c2_execution_pattern.yml` |
| critical | HackTool - SysmonEOP Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_sysmoneop.yml` |
| critical | HackTool - Windows Credential Editor (WCE) Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_wce.yml` |
| critical | Hacktool Execution - Imphash | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_execution_via_imphashes.yml` |
| critical | Persistence Via Sticky Key Backdoor | process_creation | `rules/windows/process_creation/proc_creation_win_cmd_sticky_keys_replace.yml` |
| critical | Potential Credential Dumping Via LSASS Process Clone | process_creation | `rules/windows/process_creation/proc_creation_win_lsass_process_clone.yml` |
| critical | Potential SMB Relay Attack Tool Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_relay_attacks_tools.yml` |
| critical | Renamed Whoami Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_whoami.yml` |
| critical | Sticky Key Like Backdoor Execution | process_creation | `rules/windows/process_creation/proc_creation_win_cmd_sticky_key_like_backdoor_execution.yml` |
| critical | Suspicious Child Process Of Veeam Dabatase | process_creation | `rules/windows/process_creation/proc_creation_win_mssql_veaam_susp_child_processes.yml` |
| critical | Suspicious PowerShell Mailbox Export to Share | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_mailboxexport_share.yml` |
| critical | TrustedPath UAC Bypass Pattern | process_creation | `rules/windows/process_creation/proc_creation_win_uac_bypass_trustedpath.yml` |
| critical | WMI Backdoor Exchange Transport Agent | process_creation | `rules/windows/process_creation/proc_creation_win_wmi_backdoor_exchange_transport_agent.yml` |
| high | AADInternals PowerShell Cmdlets Execution - ProccessCreation | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_aadinternals_cmdlets_execution.yml` |
| high | Abuse of Service Permissions to Hide Services Via Set-Service | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_hide_services_via_set_service.yml` |
| high | Abused Debug Privilege by Arbitrary Parent Processes | process_creation | `rules/windows/process_creation/proc_creation_win_susp_abusing_debug_privilege.yml` |
| high | Add Insecure Download Source To Winget | process_creation | `rules/windows/process_creation/proc_creation_win_winget_add_insecure_custom_source.yml` |
| high | Add SafeBoot Keys Via Reg Utility | process_creation | `rules/windows/process_creation/proc_creation_win_reg_add_safeboot.yml` |
| high | All Backups Deleted Via Wbadmin.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_wbadmin_delete_all_backups.yml` |
| high | Allow Service Access Using Security Descriptor Tampering Via Sc.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_sc_sdset_allow_service_changes.yml` |
| high | Arbitrary File Download Via IMEWDBLD.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_imewbdld_download.yml` |
| high | Attempts of Kerberos Coercion Via DNS SPN Spoofing | process_creation | `rules/windows/process_creation/proc_creation_win_kerberos_coercion_via_dns_spn_spoofing.yml` |
| high | Audit Policy Tampering Via Auditpol | process_creation | `rules/windows/process_creation/proc_creation_win_auditpol_susp_execution.yml` |
| high | Audit Policy Tampering Via NT Resource Kit Auditpol | process_creation | `rules/windows/process_creation/proc_creation_win_auditpol_nt_resource_kit_usage.yml` |
| high | Axios NPM Compromise Indicators - Windows | process_creation | `rules-emerging-threats/2026/Malware/Axios-NPM-Compromise/proc_creation_win_axios_npm_compromise_indicators.yml` |
| high | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | process_creation | `rules/windows/process_creation/proc_creation_win_susp_bad_opsec_sacrificial_processes.yml` |
| high | Base64 Encoded PowerShell Command Detected | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_frombase64string.yml` |
| high | Base64 MZ Header In CommandLine | process_creation | `rules/windows/process_creation/proc_creation_win_susp_inline_base64_mz_header.yml` |
| high | Boot Configuration Tampering Via Bcdedit.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_bcdedit_boot_conf_tamper.yml` |
| high | Bypass UAC via CMSTP | process_creation | `rules/windows/process_creation/proc_creation_win_uac_bypass_cmstp.yml` |
| high | Bypass UAC via Fodhelper.exe | process_creation | `rules/windows/process_creation/proc_creation_win_uac_bypass_fodhelper.yml` |
| high | Bypass UAC via WSReset.exe | process_creation | `rules/windows/process_creation/proc_creation_win_uac_bypass_wsreset.yml` |
| high | Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths | process_creation | `rules/windows/process_creation/proc_creation_win_wusa_cab_files_extraction_from_susp_paths.yml` |
| high | Change Default File Association To Executable Via Assoc | process_creation | `rules/windows/process_creation/proc_creation_win_cmd_assoc_tamper_exe_file_association.yml` |
| high | Chopper Webshell Process Pattern | process_creation | `rules/windows/process_creation/proc_creation_win_webshell_chopper.yml` |
| high | Chromium Browser Headless Execution To Mockbin Like Site | process_creation | `rules/windows/process_creation/proc_creation_win_browsers_chromium_mockbin_abuse.yml` |
| high | Cmd.EXE Missing Space Characters Execution Anomaly | process_creation | `rules/windows/process_creation/proc_creation_win_cmd_no_space_execution.yml` |
| high | CMSTP Execution Process Creation | process_creation | `rules/windows/process_creation/proc_creation_win_cmstp_execution_by_creation.yml` |
| high | CMSTP UAC Bypass via COM Object Access | process_creation | `rules/windows/process_creation/proc_creation_win_uac_bypass_cmstp_com_object_access.yml` |
| high | CobaltStrike Load by Rundll32 | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_load_by_rundll32.yml` |
| high | Commvault QLogin Argument Injection Authentication Bypass (CVE-2025-57791) | process_creation | `rules-emerging-threats/2025/Exploits/CVE-2025-57791/proc_creation_win_exploit_cve_2025_57791.yml` |
| high | Commvault QOperation Path Traversal Webshell Drop (CVE-2025-57790) | process_creation | `rules-emerging-threats/2025/Exploits/CVE-2025-57790/proc_creation_win_exploit_cve_2025_57790.yml` |
| high | Conhost.exe CommandLine Path Traversal | process_creation | `rules/windows/process_creation/proc_creation_win_conhost_path_traversal.yml` |
| high | Control Panel Items | process_creation | `rules/windows/process_creation/proc_creation_win_control_panel_item.yml` |
| high | Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_cmd_copy_dmp_from_share.yml` |
| high | Copy From VolumeShadowCopy Via Cmd.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_cmd_shadowcopy_access.yml` |
| high | Copying Sensitive Files with Credential Data | process_creation | `rules/windows/process_creation/proc_creation_win_esentutl_sensitive_file_copy.yml` |
| high | CreateDump Process Dump | process_creation | `rules/windows/process_creation/proc_creation_win_createdump_lolbin_execution.yml` |
| high | Csc.EXE Execution Form Potentially Suspicious Parent | process_creation | `rules/windows/process_creation/proc_creation_win_csc_susp_parent.yml` |
| high | Cscript/Wscript Uncommon Script Extension Execution | process_creation | `rules/windows/process_creation/proc_creation_win_wscript_cscript_uncommon_extension_exec.yml` |
| high | Curl Download And Execute Combination | process_creation | `rules/windows/process_creation/proc_creation_win_cmd_curl_download_exec_combo.yml` |
| high | Curl File Upload To File Sharing Websites | process_creation | `rules/windows/process_creation/proc_creation_win_curl_upload_file_sharing_websites.yml` |
| high | Delete All Scheduled Tasks | process_creation | `rules/windows/process_creation/proc_creation_win_schtasks_delete_all.yml` |
| high | Delete Important Scheduled Task | process_creation | `rules/windows/process_creation/proc_creation_win_schtasks_delete.yml` |
| high | Deletion of Volume Shadow Copies via WMI with PowerShell | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_shadowcopy_deletion.yml` |
| high | Deny Service Access Using Security Descriptor Tampering Via Sc.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_sc_sdset_deny_service_access.yml` |
| high | Devcon Execution Disabling VMware VMCI Device | process_creation | `rules/windows/process_creation/proc_creation_win_devcon_disable_vmci_driver.yml` |
| high | Devtoolslauncher.exe Executes Specified Binary | process_creation | `rules/windows/process_creation/proc_creation_win_lolbin_devtoolslauncher.yml` |
| high | Disable Important Scheduled Task | process_creation | `rules/windows/process_creation/proc_creation_win_schtasks_disable.yml` |
| high | Disable Windows Defender AV Security Monitoring | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_disable_defender_av_security_monitoring.yml` |
| high | Disable Windows IIS HTTP Logging | process_creation | `rules/windows/process_creation/proc_creation_win_iis_appcmd_http_logging.yml` |
| high | Disabled IE Security Features | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_disable_ie_features.yml` |
| high | Disabled Volume Snapshots | process_creation | `rules/windows/process_creation/proc_creation_win_reg_volsnap_disable.yml` |
| high | Disabling Windows Defender WMI Autologger Session via Reg.exe | process_creation | `rules/windows/process_creation/proc_creation_win_reg_disable_defender_wmi_autologger.yml` |
| high | DLL Sideloading by VMware Xfer Utility | process_creation | `rules/windows/process_creation/proc_creation_win_dll_sideload_vmware_xfer.yml` |
| high | Dllhost.EXE Execution Anomaly | process_creation | `rules/windows/process_creation/proc_creation_win_dllhost_no_cli_execution.yml` |
| high | DNS Exfiltration and Tunneling Tools Execution | process_creation | `rules/windows/process_creation/proc_creation_win_dns_exfiltration_tools_execution.yml` |
| high | DSInternals Suspicious PowerShell Cmdlets | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_dsinternals_cmdlets.yml` |
| high | Dumping of Sensitive Hives Via Reg.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_reg_dumping_sensitive_hives.yml` |
| high | Email Exifiltration Via Powershell | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_email_exfil.yml` |
| high | Enable LM Hash Storage - ProcCreation | process_creation | `rules/windows/process_creation/proc_creation_win_reg_nolmhash.yml` |
| high | ETW Logging Tamper In .NET Processes Via CommandLine | process_creation | `rules/windows/process_creation/proc_creation_win_susp_etw_modification_cmdline.yml` |
| high | ETW Trace Evasion Activity | process_creation | `rules/windows/process_creation/proc_creation_win_susp_etw_trace_evasion.yml` |
| high | Exchange PowerShell Snap-Ins Usage | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_snapins_hafnium.yml` |
| high | Execute Pcwrun.EXE To Leverage Follina | process_creation | `rules/windows/process_creation/proc_creation_win_lolbin_pcwrun_follina.yml` |
| high | Execution Of Non-Existing File | process_creation | `rules/windows/process_creation/proc_creation_win_susp_image_missing.yml` |
| high | Execution of Powershell Script in Public Folder | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_public_folder.yml` |
| high | Execution via stordiag.exe | process_creation | `rules/windows/process_creation/proc_creation_win_stordiag_susp_child_process.yml` |
| high | Execution via WorkFolders.exe | process_creation | `rules/windows/process_creation/proc_creation_win_susp_workfolders.yml` |
| high | Exploitation Activity of CVE-2025-59287 - WSUS Suspicious Child Process | process_creation | `rules-emerging-threats/2025/Exploits/CVE-2025-59287/proc_creation_win_exploit_cve_2025_59287.yml` |
| high | Explorer NOUACCHECK Flag | process_creation | `rules/windows/process_creation/proc_creation_win_explorer_nouaccheck.yml` |
| high | Exports Critical Registry Keys To a File | process_creation | `rules/windows/process_creation/proc_creation_win_regedit_export_critical_keys.yml` |
| high | File Decoded From Base64/Hex Via Certutil.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_certutil_decode.yml` |
| high | File Download And Execution Via IEExec.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_ieexec_download.yml` |
| high | File Download From IP Based URL Via CertOC.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_certoc_download_direct_ip.yml` |
| high | File Download Using Notepad++ GUP Utility | process_creation | `rules/windows/process_creation/proc_creation_win_gup_download.yml` |
| high | File Download Via Bitsadmin To A Suspicious Target Folder | process_creation | `rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_targetfolder.yml` |
| high | File Download Via Windows Defender MpCmpRun.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_mpcmdrun_download_arbitrary_file.yml` |
| high | File Download with Headless Browser | process_creation | `rules/windows/process_creation/proc_creation_win_browsers_chromium_headless_file_download.yml` |
| high | File Encryption/Decryption Via Gpg4win From Suspicious Locations | process_creation | `rules/windows/process_creation/proc_creation_win_gpg4win_susp_location.yml` |
| high | File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell | process_creation | `rules/windows/process_creation/proc_creation_win_explorer_folder_shortcut_via_shell_binary.yml` |
| high | File In Suspicious Location Encoded To Base64 Via Certutil.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_certutil_encode_susp_location.yml` |
| high | File With Suspicious Extension Downloaded Via Bitsadmin | process_creation | `rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_extensions.yml` |
| high | Findstr GPP Passwords | process_creation | `rules/windows/process_creation/proc_creation_win_findstr_gpp_passwords.yml` |
| high | Finger.EXE Execution | process_creation | `rules/windows/process_creation/proc_creation_win_finger_execution.yml` |
| high | Forfiles.EXE Child Process Masquerading | process_creation | `rules/windows/process_creation/proc_creation_win_forfiles_child_process_masquerading.yml` |
| high | Fsutil Suspicious Invocation | process_creation | `rules/windows/process_creation/proc_creation_win_fsutil_usage.yml` |
| high | Grixba Malware Reconnaissance Activity | process_creation | `rules-emerging-threats/2025/Malware/Grixba/proc_creation_win_malware_grixba_recon.yml` |
| high | HackTool - ADCSPwn Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_adcspwn.yml` |
| high | HackTool - Bloodhound/Sharphound Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_bloodhound_sharphound.yml` |
| high | HackTool - Certify Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_certify.yml` |
| high | HackTool - Certipy Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_certipy.yml` |
| high | HackTool - CoercedPotato Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_coercedpotato.yml` |
| high | HackTool - Covenant PowerShell Launcher | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_covenant.yml` |
| high | HackTool - CrackMapExec Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_execution.yml` |
| high | HackTool - CrackMapExec Execution Patterns | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_execution_patterns.yml` |
| high | HackTool - CrackMapExec PowerShell Obfuscation | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_powershell_obfuscation.yml` |
| high | HackTool - CrackMapExec Process Patterns | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_patterns.yml` |
| high | HackTool - CreateMiniDump Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_createminidump.yml` |
| high | HackTool - Default PowerSploit/Empire Scheduled Task Creation | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_powersploit_empire_default_schtasks.yml` |
| high | HackTool - Doppelanger LSASS Dumper Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_doppelganger.yml` |
| high | Hacktool - EDR-Freeze Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_edr_freeze.yml` |
| high | HackTool - EDRSilencer Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_edrsilencer.yml` |
| high | HackTool - Empire PowerShell Launch Parameters | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_empire_powershell_launch.yml` |
| high | HackTool - GMER Rootkit Detector and Remover Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_gmer.yml` |
| high | HackTool - HandleKatz LSASS Dumper Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_handlekatz.yml` |
| high | HackTool - Hashcat Password Cracker Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_hashcat.yml` |
| high | HackTool - HollowReaper Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_hollowreaper.yml` |
| high | HackTool - Htran/NATBypass Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_htran_or_natbypass.yml` |
| high | HackTool - Hydra Password Bruteforce Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_hydra.yml` |
| high | HackTool - Impacket Tools Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_impacket_tools.yml` |
| high | HackTool - Koadic Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_koadic.yml` |
| high | HackTool - KrbRelay Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_krbrelay.yml` |
| high | HackTool - KrbRelayUp Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_krbrelayup.yml` |
| high | HackTool - LocalPotato Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_localpotato.yml` |
| high | HackTool - Mimikatz Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml` |
| high | HackTool - NetExec Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_netexec.yml` |
| high | HackTool - PCHunter Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_pchunter.yml` |
| high | HackTool - Potential Impacket Lateral Movement Activity | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_impacket_lateral_movement.yml` |
| high | HackTool - PowerTool Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_powertool.yml` |
| high | HackTool - PPID Spoofing SelectMyParent Tool Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_selectmyparent.yml` |
| high | HackTool - Pypykatz Credentials Dumping Activity | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_pypykatz.yml` |
| high | HackTool - Quarks PwDump Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_quarks_pwdump.yml` |
| high | HackTool - RedMimicry Winnti Playbook Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_redmimicry_winnti_playbook.yml` |
| high | HackTool - RemoteKrbRelay Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_krbrelay_remote.yml` |
| high | HackTool - SharpChisel Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_sharp_chisel.yml` |
| high | HackTool - SharpDPAPI Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_sharp_dpapi_execution.yml` |
| high | HackTool - SharPersist Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_sharpersist.yml` |
| high | HackTool - SharpEvtMute Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_sharpevtmute.yml` |
| high | HackTool - SharpImpersonation Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_sharp_impersonation.yml` |
| high | HackTool - SharpLdapWhoami Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_sharpldapwhoami.yml` |
| high | HackTool - SharpMove Tool Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_sharpmove.yml` |
| high | HackTool - SharpView Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_sharpview.yml` |
| high | HackTool - SharpWSUS/WSUSpendu Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_sharpwsus_wsuspendu_execution.yml` |
| high | HackTool - SILENTTRINITY Stager Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_silenttrinity_stager.yml` |
| high | HackTool - SOAPHound Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_soaphound_execution.yml` |
| high | HackTool - Stracciatella Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_stracciatella_execution.yml` |
| high | HackTool - TruffleSnout Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_trufflesnout.yml` |
| high | HackTool - UACMe Akagi Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_uacme.yml` |
| high | HackTool - winPEAS Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_winpeas.yml` |
| high | HackTool - WinPwn Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_winpwn.yml` |
| high | HackTool - Wmiexec Default Powershell Command | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_wmiexec_default_powershell.yml` |
| high | HackTool - WSASS Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_wsass.yml` |
| high | HackTool - XORDump Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_xordump.yml` |
| high | Hacktool Execution - PE Metadata | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_execution_via_pe_metadata.yml` |
| high | HKTL - SharpSuccessor Privilege Escalation Tool Execution | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_sharpsuccessor_execution.yml` |
| high | HTML Help HH.EXE Suspicious Child Process | process_creation | `rules/windows/process_creation/proc_creation_win_hh_html_help_susp_child_process.yml` |
| high | Hypervisor-protected Code Integrity (HVCI) Related Registry Tampering Via CommandLine | process_creation | `rules/windows/process_creation/proc_creation_win_hvci_registry_tampering.yml` |
| high | IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols Via CLI | process_creation | `rules/windows/process_creation/proc_creation_win_registry_ie_security_zone_protocol_defaults_downgrade.yml` |
| high | ImagingDevices Unusual Parent/Child Processes | process_creation | `rules/windows/process_creation/proc_creation_win_imagingdevices_unusual_parents.yml` |
| high | Imports Registry Key From an ADS | process_creation | `rules/windows/process_creation/proc_creation_win_regedit_import_keys_ads.yml` |
| high | Installation of WSL Kali-Linux | process_creation | `rules/windows/process_creation/proc_creation_win_wsl_kali_linux_installation.yml` |
| high | Interactive AT Job | process_creation | `rules/windows/process_creation/proc_creation_win_at_interactive_execution.yml` |
| high | Invoke-Obfuscation CLIP+ Launcher | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_clip.yml` |
| high | Invoke-Obfuscation Obfuscated IEX Invocation | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_obfuscated_iex_commandline.yml` |
| high | Invoke-Obfuscation STDIN+ Launcher | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_stdin.yml` |
| high | Invoke-Obfuscation VAR+ Launcher | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_var.yml` |
| high | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_var.yml` |
| high | Invoke-Obfuscation Via Stdin | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_stdin.yml` |
| high | Invoke-Obfuscation Via Use Clip | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_use_clip.yml` |
| high | Invoke-Obfuscation Via Use MSHTA | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_use_mhsta.yml` |
| high | Kalambur Backdoor Curl TOR SOCKS Proxy Execution | process_creation | `rules-emerging-threats/2025/Malware/proc_creation_win_malware_kalambur_curl_socks_tor.yml` |
| high | Kavremover Dropped Binary LOLBIN Usage | process_creation | `rules/windows/process_creation/proc_creation_win_kavremover_uncommon_execution.yml` |
| high | Kernel Memory Dump Via LiveKD | process_creation | `rules/windows/process_creation/proc_creation_win_sysinternals_livekd_kernel_memory_dump.yml` |
| high | LOL-Binary Copied From System Directory | process_creation | `rules/windows/process_creation/proc_creation_win_susp_copy_system_dir_lolbin.yml` |
| high | LSASS Dump Keyword In CommandLine | process_creation | `rules/windows/process_creation/proc_creation_win_susp_lsass_dmp_cli_keywords.yml` |
| high | LSASS Process Reconnaissance Via Findstr.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_findstr_lsass.yml` |
| high | Malicious Base64 Encoded PowerShell Keywords in Command Lines | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_base64_hidden_flag.yml` |
| high | Malicious PowerShell Commandlets - ProcessCreation | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_malicious_cmdlets.yml` |
| high | ManageEngine Endpoint Central Dctask64.EXE Potential Abuse | process_creation | `rules/windows/process_creation/proc_creation_win_dctask64_arbitrary_command_and_dll_execution.yml` |
| high | Mavinject Inject DLL Into Running Process | process_creation | `rules/windows/process_creation/proc_creation_win_lolbin_mavinject_process_injection.yml` |
| high | Microsoft IIS Connection Strings Decryption | process_creation | `rules/windows/process_creation/proc_creation_win_iis_connection_strings_decryption.yml` |
| high | Microsoft IIS Service Account Password Dumped | process_creation | `rules/windows/process_creation/proc_creation_win_iis_appcmd_service_account_password_dumped.yml` |
| high | MMC Executing Files with Reversed Extensions Using RTLO Abuse | process_creation | `rules/windows/process_creation/proc_creation_win_mmc_rlo_abuse_pattern.yml` |
| high | MMC Spawning Windows Shell | process_creation | `rules/windows/process_creation/proc_creation_win_mmc_susp_child_process.yml` |
| high | MMC20 Lateral Movement | process_creation | `rules/windows/process_creation/proc_creation_win_mmc_mmc20_lateral_movement.yml` |
| high | MpiExec Lolbin | process_creation | `rules/windows/process_creation/proc_creation_win_lolbin_mpiexec.yml` |
| high | MSDT Execution Via Answer File | process_creation | `rules/windows/process_creation/proc_creation_win_msdt_answer_file_exec.yml` |
| high | MSHTA Execution with Suspicious File Extensions | process_creation | `rules/windows/process_creation/proc_creation_win_mshta_susp_execution.yml` |
| high | Mshtml.DLL RunHTMLApplication Suspicious Usage | process_creation | `rules/windows/process_creation/proc_creation_win_rundll32_mshtml_runhtmlapplication.yml` |
| high | Mstsc.EXE Execution From Uncommon Parent | process_creation | `rules/windows/process_creation/proc_creation_win_mstsc_run_local_rpd_file_susp_parent.yml` |
| high | Net WebClient Casing Anomalies | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_webclient_casing.yml` |
| high | Network Reconnaissance Activity | process_creation | `rules/windows/process_creation/proc_creation_win_nslookup_domain_discovery.yml` |
| high | New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_dnscmd_install_new_server_level_plugin_dll.yml` |
| high | New User Created Via Net.EXE With Never Expire Option | process_creation | `rules/windows/process_creation/proc_creation_win_net_user_add_never_expire.yml` |
| high | NewActiveScriptEventConsumer Creation Attempt via Wmic.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_wmic_eventconsumer_creation.yml` |
| high | Non-privileged Usage of Reg or Powershell | process_creation | `rules/windows/process_creation/proc_creation_win_susp_non_priv_reg_or_ps.yml` |
| high | NtdllPipe Like Activity Execution | process_creation | `rules/windows/process_creation/proc_creation_win_cmd_ntdllpipe_redirect.yml` |
| high | NTLM Hash Leak Via Curl NTLM Authentication | process_creation | `rules/windows/process_creation/proc_creation_win_curl_ntlm_hash_leak_attempt.yml` |
| high | Obfuscated PowerShell MSI Install via WindowsInstaller COM | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_comobject_msi.yml` |
| high | Obfuscated PowerShell OneLiner Execution | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_download_cradle_obfuscated.yml` |
| high | Odbcconf.EXE Suspicious DLL Location | process_creation | `rules/windows/process_creation/proc_creation_win_odbcconf_exec_susp_locations.yml` |
| high | OneNote.EXE Execution of Malicious Embedded Scripts | process_creation | `rules/windows/process_creation/proc_creation_win_office_onenote_embedded_script_execution.yml` |
| high | OpenWith.exe Executes Specified Binary | process_creation | `rules/windows/process_creation/proc_creation_win_lolbin_openwith.yml` |
| high | Operator Bloopers Cobalt Strike Commands | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_bloopers_cmd.yml` |
| high | Operator Bloopers Cobalt Strike Modules | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_bloopers_modules.yml` |
| high | Outlook EnableUnsafeClientMailRules Setting Enabled | process_creation | `rules/windows/process_creation/proc_creation_win_office_outlook_enable_unsafe_client_mail_rules.yml` |
| high | Phishing Pattern ISO in Archive | process_creation | `rules/windows/process_creation/proc_creation_win_susp_archiver_iso_phishing.yml` |
| high | Ping Hex IP | process_creation | `rules/windows/process_creation/proc_creation_win_ping_hex_ip.yml` |
| high | Possible Privilege Escalation via Weak Service Permissions | process_creation | `rules/windows/process_creation/proc_creation_win_sc_change_sevice_image_path_by_non_admin.yml` |
| high | Potential Adplus.EXE Abuse | process_creation | `rules/windows/process_creation/proc_creation_win_adplus_memory_dump.yml` |
| high | Potential AMSI Bypass Via .NET Reflection | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_amsi_init_failed_bypass.yml` |
| high | Potential Arbitrary Code Execution Via Node.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_node_abuse.yml` |
| high | Potential Arbitrary Command Execution Using Msdt.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_msdt_arbitrary_command_execution.yml` |
| high | Potential Arbitrary File Download Using Office Application | process_creation | `rules/windows/process_creation/proc_creation_win_office_arbitrary_cli_download.yml` |
| high | Potential CobaltStrike Process Patterns | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_process_patterns.yml` |
| high | Potential CommandLine Obfuscation Using Unicode Characters From Suspicious Image | process_creation | `rules/windows/process_creation/proc_creation_win_susp_cli_obfuscation_unicode_img.yml` |
| high | Potential CommandLine Path Traversal Via Cmd.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_cmd_path_traversal.yml` |
| high | Potential Credential Dumping Attempt Using New NetworkProvider - CLI | process_creation | `rules/windows/process_creation/proc_creation_win_registry_new_network_provider.yml` |
| high | Potential Credential Dumping Via WER | process_creation | `rules/windows/process_creation/proc_creation_win_werfault_lsass_shtinkering.yml` |
| high | Potential Crypto Mining Activity | process_creation | `rules/windows/process_creation/proc_creation_win_susp_crypto_mining_monero.yml` |
| high | Potential CVE-2026-33829 Exploitation - Windows Snipping Tool Remote File Path URI | process_creation | `rules-emerging-threats/2026/Exploits/CVE-2026-33829/proc_creation_win_exploit_cve_2026_33829.yml` |
| high | Potential Data Exfiltration Activity Via CommandLine Tools | process_creation | `rules/windows/process_creation/proc_creation_win_susp_data_exfiltration_via_cli.yml` |
| high | Potential Data Stealing Via Chromium Headless Debugging | process_creation | `rules/windows/process_creation/proc_creation_win_browsers_chromium_headless_debugging.yml` |
| high | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 1 | process_creation | `rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_1.yml` |
| high | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 2 | process_creation | `rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_2.yml` |
| high | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 3 | process_creation | `rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_3.yml` |
| high | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 4 | process_creation | `rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_4.yml` |
| high | Potential Defense Evasion Via Rename Of Highly Relevant Binaries | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_binary_highly_relevant.yml` |
| high | Potential Defense Evasion Via Right-to-Left Override | process_creation | `rules/windows/process_creation/proc_creation_win_susp_right_to_left_override.yml` |
| high | Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp | process_creation | `rules/windows/process_creation/proc_creation_win_office_excel_dcom_lateral_movement.yml` |
| high | Potential Exploitation of CrushFTP RCE Vulnerability (CVE-2025-54309) | process_creation | `rules-emerging-threats/2025/Exploits/CVE-2025-54309/proc_creation_win_exploit_cve_2025_54309.yml` |
| high | Potential Exploitation of GoAnywhere MFT Vulnerability | process_creation | `rules-emerging-threats/2025/Exploits/CVE-2025-10035/proc_creation_win_exploit_cve_2025_10035.yml` |
| high | Potential Exploitation of RCE Vulnerability CVE-2025-33053 | process_creation | `rules-emerging-threats/2025/Exploits/CVE-2025-33053/proc_creation_win_exploit_cve_2025_33053.yml` |
| high | Potential File Overwrite Via Sysinternals SDelete | process_creation | `rules/windows/process_creation/proc_creation_win_sysinternals_sdelete.yml` |
| high | Potential LethalHTA Technique Execution | process_creation | `rules/windows/process_creation/proc_creation_win_mshta_lethalhta_technique.yml` |
| high | Potential LSASS Process Dump Via Procdump | process_creation | `rules/windows/process_creation/proc_creation_win_sysinternals_procdump_lsass.yml` |
| high | Potential Manage-bde.wsf Abuse To Proxy Execution | process_creation | `rules/windows/process_creation/proc_creation_win_lolbin_manage_bde.yml` |
| high | Potential Meterpreter/CobaltStrike Activity | process_creation | `rules/windows/process_creation/proc_creation_win_hktl_meterpreter_getsystem.yml` |
| high | Potential Mpclient.DLL Sideloading Via Defender Binaries | process_creation | `rules/windows/process_creation/proc_creation_win_mpcmdrun_dll_sideload_defender.yml` |
| high | Potential MsiExec Masquerading | process_creation | `rules/windows/process_creation/proc_creation_win_msiexec_masquerading.yml` |
| high | Potential MSTSC Shadowing Activity | process_creation | `rules/windows/process_creation/proc_creation_win_mstsc_rdp_hijack_shadowing.yml` |
| high | Potential Notepad++ CVE-2025-49144 Exploitation | process_creation | `rules-emerging-threats/2025/Exploits/CVE-2025-49144/proc_creation_win_exploit_cve_2025_49144.yml` |
| high | Potential NTLM Coercion Via Certutil.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_certutil_ntlm_coercion.yml` |
| high | Potential Persistence Via Logon Scripts - CommandLine | process_creation | `rules/windows/process_creation/proc_creation_win_registry_logon_script.yml` |
| high | Potential Persistence Via Powershell Search Order Hijacking - Task | process_creation | `rules/windows/process_creation/proc_creation_win_schtasks_powershell_persistence.yml` |
| high | Potential PowerShell Command Line Obfuscation | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_cmdline_special_characters.yml` |
| high | Potential PowerShell Execution Policy Tampering - ProcCreation | process_creation | `rules/windows/process_creation/proc_creation_win_registry_set_unsecure_powershell_policy.yml` |
| high | Potential PowerShell Execution Via DLL | process_creation | `rules/windows/process_creation/proc_creation_win_susp_powershell_execution_via_dll.yml` |
| high | Potential PowerShell Obfuscation Via Reversed Commands | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_cmdline_reversed_strings.yml` |
| high | Potential PowerShell Obfuscation Via WCHAR/CHAR | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_obfuscation_via_utf8.yml` |
| high | Potential Powershell ReverseShell Connection | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_reverse_shell_connection.yml` |
| high | Potential Privilege Escalation To LOCAL SYSTEM | process_creation | `rules/windows/process_creation/proc_creation_win_sysinternals_susp_psexec_paexec_flags.yml` |
| high | Potential Privilege Escalation Using Symlink Between Osk and Cmd | process_creation | `rules/windows/process_creation/proc_creation_win_cmd_mklink_osk_cmd.yml` |
| high | Potential Privilege Escalation via Service Permissions Weakness | process_creation | `rules/windows/process_creation/proc_creation_win_registry_privilege_escalation_via_service_key.yml` |
| high | Potential Process Injection Via Msra.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_msra_process_injection.yml` |
| high | Potential Provisioning Registry Key Abuse For Binary Proxy Execution | process_creation | `rules/windows/process_creation/proc_creation_win_registry_provlaunch_provisioning_command.yml` |
| high | Potential PsExec Remote Execution | process_creation | `rules/windows/process_creation/proc_creation_win_sysinternals_psexec_remote_execution.yml` |
| high | Potential RDP Tunneling Via Plink | process_creation | `rules/windows/process_creation/proc_creation_win_plink_susp_tunneling.yml` |
| high | Potential RDP Tunneling Via SSH | process_creation | `rules/windows/process_creation/proc_creation_win_ssh_rdp_tunneling.yml` |
| high | Potential Recon Activity Using DriverQuery.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_driverquery_recon.yml` |
| high | Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_cmdkey_recon.yml` |
| high | Potential Remote SquiblyTwo Technique Execution | process_creation | `rules/windows/process_creation/proc_creation_win_wmic_squiblytwo_bypass.yml` |
| high | Potential Renamed Rundll32 Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_rundll32_dllregisterserver.yml` |
| high | Potential Rundll32 Execution With DLL Stored In ADS | process_creation | `rules/windows/process_creation/proc_creation_win_rundll32_ads_stored_dll_execution.yml` |
| high | Potential SharePoint ToolShell CVE-2025-53770 Exploitation Indicators | process_creation | `rules-emerging-threats/2025/Exploits/CVE-2025-53770/proc_creation_win_exploit_cve_2025_53770_indicators.yml` |
| high | Potential Signing Bypass Via Windows Developer Features | process_creation | `rules/windows/process_creation/proc_creation_win_systemsettingsadminflows_turn_on_dev_features.yml` |
| high | Potential SSH Tunnel Persistence Install Using A Scheduled Task | process_creation | `rules/windows/process_creation/proc_creation_win_schtasks_openssh_tunnelling.yml` |
| high | Potential Suspicious Mofcomp Execution | process_creation | `rules/windows/process_creation/proc_creation_win_mofcomp_execution.yml` |
| high | Potential SysInternals ProcDump Evasion | process_creation | `rules/windows/process_creation/proc_creation_win_sysinternals_procdump_evasion.yml` |
| high | Potential Tampering With RDP Related Registry Keys Via Reg.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_reg_rdp_keys_tamper.yml` |
| high | Potential Tampering With Security Products Via WMIC | process_creation | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` |
| high | Potential WinAPI Calls Via CommandLine | process_creation | `rules/windows/process_creation/proc_creation_win_susp_inline_win_api_access.yml` |
| high | Potential Windows Defender AV Bypass Via Dump64.EXE Rename | process_creation | `rules/windows/process_creation/proc_creation_win_dump64_defender_av_bypass_rename.yml` |
| high | Potential Windows Defender Tampering Via Wmic.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_wmic_namespace_defender.yml` |
| high | Potentially Suspicious ASP.NET Compilation Via AspNetCompiler | process_creation | `rules/windows/process_creation/proc_creation_win_aspnet_compiler_susp_paths.yml` |
| high | Potentially Suspicious Call To Win32_NTEventlogFile Class | process_creation | `rules/windows/process_creation/proc_creation_win_susp_nteventlogfile_usage.yml` |
| high | Potentially Suspicious Child Process Of Regsvr32 | process_creation | `rules/windows/process_creation/proc_creation_win_regsvr32_susp_child_process.yml` |
| high | Potentially Suspicious Child Processes Spawned by ConHost | process_creation | `rules/windows/process_creation/proc_creation_win_conhost_susp_winshell_child_process.yml` |
| high | Potentially Suspicious DLL Registered Via Odbcconf.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_odbcconf_register_dll_regsvr_susp.yml` |
| high | Potentially Suspicious Event Viewer Child Process | process_creation | `rules/windows/process_creation/proc_creation_win_eventvwr_susp_child_process.yml` |
| high | Potentially Suspicious Execution From Parent Process In Public Folder | process_creation | `rules/windows/process_creation/proc_creation_win_susp_execution_from_public_folder_as_parent.yml` |
| high | Potentially Suspicious File Download From File Sharing Domain Via PowerShell.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_download_susp_file_sharing_domains.yml` |
| high | Potentially Suspicious GoogleUpdate Child Process | process_creation | `rules/windows/process_creation/proc_creation_win_googleupdate_susp_child_process.yml` |
| high | Potentially Suspicious Office Document Executed From Trusted Location | process_creation | `rules/windows/process_creation/proc_creation_win_office_exec_from_trusted_locations.yml` |
| high | Potentially Suspicious Regsvr32 HTTP IP Pattern | process_creation | `rules/windows/process_creation/proc_creation_win_regsvr32_http_ip_pattern.yml` |
| high | PowerShell Base64 Encoded FromBase64String Cmdlet | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_base64_frombase64string.yml` |
| high | PowerShell Base64 Encoded IEX Cmdlet | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_base64_iex.yml` |
| high | PowerShell Base64 Encoded Invoke Keyword | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_base64_invoke.yml` |
| high | Powershell Base64 Encoded MpPreference Cmdlet | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_base64_mppreference.yml` |
| high | PowerShell Base64 Encoded Reflective Assembly Load | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_base64_reflection_assembly_load.yml` |
| high | PowerShell Base64 Encoded WMI Classes | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_base64_wmi_classes.yml` |
| high | Powershell Defender Disable Scan Feature | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_defender_disable_feature.yml` |
| high | PowerShell Defender Threat Severity Default Action Set to 'Allow' or 'NoAction' | process_creation | `rules/windows/process_creation/proc_creation_win_defender_default_action_modified.yml` |
| high | PowerShell Download and Execution Cradles | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_download_iex.yml` |
| high | PowerShell Execution With Potential Decryption Capabilities | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_decrypt_pattern.yml` |
| high | PowerShell Get-Process LSASS | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_getprocess_lsass.yml` |
| high | PowerShell SAM Copy | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_sam_access.yml` |
| high | PowerShell Script Change Permission Via Set-Acl | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_set_acl.yml` |
| high | PowerShell Set-Acl On Windows Folder | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_set_acl_susp_location.yml` |
| high | Powershell Token Obfuscation - Process Creation | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_token_obfuscation.yml` |
| high | PowerShell Web Access Feature Enabled Via DISM | process_creation | `rules/windows/process_creation/proc_creation_win_dism_enable_powershell_web_access_feature.yml` |
| high | PPL Tampering Via WerFaultSecure | process_creation | `rules/windows/process_creation/proc_creation_win_werfaultsecure_abuse.yml` |
| high | PrintBrm ZIP Creation of Extraction | process_creation | `rules/windows/process_creation/proc_creation_win_lolbin_printbrm.yml` |
| high | Privilege Escalation via Named Pipe Impersonation | process_creation | `rules/windows/process_creation/proc_creation_win_susp_priv_escalation_via_named_pipe.yml` |
| high | Process Access via TrolleyExpress Exclusion | process_creation | `rules/windows/process_creation/proc_creation_win_citrix_trolleyexpress_procdump.yml` |
| high | Process Execution From A Potentially Suspicious Folder | process_creation | `rules/windows/process_creation/proc_creation_win_susp_execution_path.yml` |
| high | Process Memory Dump Via Comsvcs.DLL | process_creation | `rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml` |
| high | Process Memory Dump via RdrLeakDiag.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_rdrleakdiag_process_dumping.yml` |
| high | Proxy Execution Via Wuauclt.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_wuauclt_dll_loading.yml` |
| high | PsExec Service Child Process Execution as LOCAL SYSTEM | process_creation | `rules/windows/process_creation/proc_creation_win_sysinternals_psexesvc_as_system.yml` |
| high | PsExec/PAExec Escalation to LOCAL SYSTEM | process_creation | `rules/windows/process_creation/proc_creation_win_sysinternals_psexec_paexec_escalate_system.yml` |
| high | PUA - 3Proxy Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_3proxy_execution.yml` |
| high | PUA - AdFind Suspicious Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_adfind_susp_usage.yml` |
| high | PUA - AdvancedRun Suspicious Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_advancedrun_priv_user.yml` |
| high | PUA - Chisel Tunneling Tool Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_chisel.yml` |
| high | PUA - CleanWipe Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_cleanwipe.yml` |
| high | PUA - Crassus Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_crassus.yml` |
| high | PUA - CsExec Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_csexec.yml` |
| high | PUA - DefenderCheck Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_defendercheck.yml` |
| high | PUA - DIT Snapshot Viewer | process_creation | `rules/windows/process_creation/proc_creation_win_pua_ditsnap.yml` |
| high | PUA - Fast Reverse Proxy (FRP) Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_frp.yml` |
| high | PUA - Kernel Driver Utility (KDU) Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_kdu_driver_tool.yml` |
| high | PUA - Memory Dump Mount Via MemProcFS | process_creation | `rules/windows/process_creation/proc_creation_win_pua_memprocfs.yml` |
| high | PUA - Netcat Suspicious Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_netcat.yml` |
| high | PUA - Ngrok Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_ngrok.yml` |
| high | PUA - Nimgrab Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_nimgrab.yml` |
| high | PUA - NirCmd Execution As LOCAL SYSTEM | process_creation | `rules/windows/process_creation/proc_creation_win_pua_nircmd_as_system.yml` |
| high | PUA - NPS Tunneling Tool Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_nps.yml` |
| high | PUA - NSudo Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_nsudo.yml` |
| high | PUA - PingCastle Execution From Potentially Suspicious Parent | process_creation | `rules/windows/process_creation/proc_creation_win_pua_pingcastle_script_parent.yml` |
| high | PUA - Rclone Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_rclone_execution.yml` |
| high | PUA - Restic Backup Tool Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_restic.yml` |
| high | PUA - RunXCmd Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_runxcmd.yml` |
| high | PUA - Seatbelt Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_seatbelt.yml` |
| high | PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_pua_adfind_enumeration.yml` |
| high | PUA - Wsudo Suspicious Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_wsudo_susp_execution.yml` |
| high | PUA- IOX Tunneling Tool Execution | process_creation | `rules/windows/process_creation/proc_creation_win_pua_iox.yml` |
| high | Python Function Execution Security Warning Disabled In Excel | process_creation | `rules/windows/process_creation/proc_creation_win_registry_office_disable_python_security_warnings.yml` |
| high | Python One-Liners with Base64 Decoding | process_creation | `rules/windows/process_creation/proc_creation_win_python_base64_encoded_execution.yml` |
| high | Python Spawning Pretty TTY on Windows | process_creation | `rules/windows/process_creation/proc_creation_win_python_pty_spawn.yml` |
| high | Raccine Uninstall | process_creation | `rules/windows/process_creation/proc_creation_win_susp_disable_raccine.yml` |
| high | Rar Usage with Password and Compression Level | process_creation | `rules/windows/process_creation/proc_creation_win_rar_compression_with_password.yml` |
| high | RDP Connection Allowed Via Netsh.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_netsh_fw_allow_rdp.yml` |
| high | RDP Port Forwarding Rule Added Via Netsh.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_netsh_port_forwarding_3389.yml` |
| high | RedSun - Conhost.exe Spawned by TieringEngineService.exe | process_creation | `rules-emerging-threats/2026/Exploits/RedSun/proc_creation_win_redsun_conhost_via_tiering_engine.yml` |
| high | Reg Add Suspicious Paths | process_creation | `rules/windows/process_creation/proc_creation_win_reg_susp_paths.yml` |
| high | Regedit as Trusted Installer | process_creation | `rules/windows/process_creation/proc_creation_win_regedit_trustedinstaller.yml` |
| high | Registry Export of Third-Party Credentials | process_creation | `rules/windows/process_creation/proc_creation_win_registry_export_of_thirdparty_creds.yml` |
| high | Regsvr32 DLL Execution With Suspicious File Extension | process_creation | `rules/windows/process_creation/proc_creation_win_regsvr32_susp_extensions.yml` |
| high | Regsvr32 Execution From Highly Suspicious Location | process_creation | `rules/windows/process_creation/proc_creation_win_regsvr32_susp_exec_path_2.yml` |
| high | Remote Access Tool - Anydesk Execution From Suspicious Folder | process_creation | `rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_susp_exec.yml` |
| high | Remote Access Tool - AnyDesk Silent Installation | process_creation | `rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_silent_install.yml` |
| high | Remote Access Tool - Renamed MeshAgent Execution - Windows | process_creation | `rules/windows/process_creation/proc_creation_win_remote_access_tools_renamed_meshagent_execution.yml` |
| high | Remote Access Tool - ScreenConnect Server Web Shell Execution | process_creation | `rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_webshell.yml` |
| high | Remote CHM File Download/Execution Via HH.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_hh_chm_remote_download_or_execution.yml` |
| high | Remote XSL Execution Via Msxsl.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_msxsl_remote_execution.yml` |
| high | RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_remotefxvgpudisablement_abuse.yml` |
| high | Remotely Hosted HTA File Executed Via Mshta.EXE | process_creation | `rules/windows/process_creation/proc_creation_win_mshta_http.yml` |
| high | Renamed AdFind Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_adfind.yml` |
| high | Renamed AutoIt Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_autoit.yml` |
| high | Renamed BrowserCore.EXE Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_browsercore.yml` |
| high | Renamed Cloudflared.EXE Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_cloudflared.yml` |
| high | Renamed CreateDump Utility Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_createdump.yml` |
| high | Renamed Gpg.EXE Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_gpg4win.yml` |
| high | Renamed Jusched.EXE Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_jusched.yml` |
| high | Renamed Mavinject.EXE Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_mavinject.yml` |
| high | Renamed MegaSync Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_megasync.yml` |
| high | Renamed Msdt.EXE Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_msdt.yml` |
| high | Renamed NetSupport RAT Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_netsupport_rat.yml` |
| high | Renamed NirCmd.EXE Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_nircmd.yml` |
| high | Renamed Office Binary Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_office_processes.yml` |
| high | Renamed PAExec Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_paexec.yml` |
| high | Renamed PingCastle Binary Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_pingcastle.yml` |
| high | Renamed Plink Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_plink.yml` |
| high | Renamed ProcDump Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_sysinternals_procdump.yml` |
| high | Renamed PsExec Service Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_sysinternals_psexec_service.yml` |
| high | Renamed Schtasks Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_schtasks_execution.yml` |
| high | Renamed SysInternals DebugView Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_sysinternals_debugview.yml` |
| high | Renamed Sysinternals Sdelete Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_sysinternals_sdelete.yml` |
| high | Renamed Visual Studio Code Tunnel Execution | process_creation | `rules/windows/process_creation/proc_creation_win_vscode_tunnel_renamed_execution.yml` |
| high | Renamed Vmnat.exe Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_vmnat.yml` |
| high | Renamed ZOHO Dctask64 Execution | process_creation | `rules/windows/process_creation/proc_creation_win_renamed_dctask64.yml` |
| high | RestrictedAdminMode Registry Value Tampering - ProcCreation | process_creation | `rules/windows/process_creation/proc_creation_win_reg_lsa_disable_restricted_admin.yml` |
| high | Root Certificate Installed From Susp Locations | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_import_cert_susp_locations.yml` |
| high | Run PowerShell Script from ADS | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_run_script_from_ads.yml` |
| high | Run PowerShell Script from Redirected Input Stream | process_creation | `rules/windows/process_creation/proc_creation_win_powershell_run_script_from_input_stream.yml` |
| high | Rundll32 Execution Without CommandLine Parameters | process_creation | `rules/windows/process_creation/proc_creation_win_rundll32_no_params.yml` |
| high | Rundll32 Execution Without Parameters | process_creation | `rules/windows/process_creation/proc_creation_win_rundll32_without_parameters.yml` |
| ... | 另有 231 条见 JSON | | |

## file_path_ioc (104)

| level | title | category/service | file |
|---|---|---|---|
| critical | HackTool - Dumpert Process Dumper Default File | file_event | `rules/windows/file/file_event/file_event_win_hktl_dumpert.yml` |
| critical | HackTool - Inveigh Execution Artefacts | file_event | `rules/windows/file/file_event/file_event_win_hktl_inveigh_artefacts.yml` |
| critical | HackTool - Mimikatz Kirbi File Creation | file_event | `rules/windows/file/file_event/file_event_win_hktl_mimikatz_files.yml` |
| critical | HackTool - QuarksPwDump Dump File | file_event | `rules/windows/file/file_event/file_event_win_hktl_quarkspw_filedump.yml` |
| critical | Potential DCOM InternetExplorer.Application DLL Hijack | file_event | `rules/windows/file/file_event/file_event_win_dcom_iertutil_dll_hijack.yml` |
| critical | Potential SharePoint ToolShell CVE-2025-53770 Exploitation - File Create | file_event | `rules-emerging-threats/2025/Exploits/CVE-2025-53770/file_event_win_exploit_cve_2025_53770.yml` |
| critical | RedSun - TieringEngineService.exe Staged in RS-Prefixed Temp Dir | file_event | `rules-emerging-threats/2026/Exploits/RedSun/file_event_win_exploit_redsun_indicators.yml` |
| critical | Wmiexec Default Output File | file_event | `rules/windows/file/file_event/file_event_win_wmiexec_default_filename.yml` |
| critical | Wmiprvse Wbemcomn DLL Hijack - File | file_event | `rules/windows/file/file_event/file_event_win_wmiprvse_wbemcomn_dll_hijack.yml` |
| high | .RDP File Created By Uncommon Application | file_event | `rules/windows/file/file_event/file_event_win_rdp_file_susp_creation.yml` |
| high | Adwind RAT / JRAT File Artifact | file_event | `rules/windows/file/file_event/file_event_win_mal_adwind.yml` |
| high | Axios NPM Compromise File Creation Indicators - Windows | file_event | `rules-emerging-threats/2026/Malware/Axios-NPM-Compromise/file_event_win_axios_npm_compromise_indicators.yml` |
| high | BloodHound Collection Files | file_event | `rules/windows/file/file_event/file_event_win_bloodhound_collection.yml` |
| high | Creation Exe for Service with Unquoted Path | file_event | `rules/windows/file/file_event/file_event_win_creation_unquoted_service_path.yml` |
| high | Cred Dump Tools Dropped Files | file_event | `rules/windows/file/file_event/file_event_win_cred_dump_tools_dropped_files.yml` |
| high | DLL Search Order Hijackig Via Additional Space in Path | file_event | `rules/windows/file/file_event/file_event_win_dll_sideloading_space_path.yml` |
| high | DPAPI Backup Keys And Certificate Export Activity IOC | file_event | `rules/windows/file/file_event/file_event_win_susp_dpapi_backup_and_cert_export_ioc.yml` |
| high | Exchange PowerShell Cmdlet History Deleted | file_delete | `rules/windows/file/file_delete/file_delete_win_delete_exchange_powershell_logs.yml` |
| high | File Creation In Suspicious Directory By Msdt.EXE | file_event | `rules/windows/file/file_event/file_event_win_msdt_susp_directories.yml` |
| high | File With Uncommon Extension Created By An Office Application | file_event | `rules/windows/file/file_event/file_event_win_office_susp_file_extension.yml` |
| high | FunkLocker Ransomware File Creation | file_event | `rules-emerging-threats/2025/Malware/file_event_win_malware_funklocker_ransomware_extension.yml` |
| high | HackTool - CrackMapExec File Indicators | file_event | `rules/windows/file/file_event/file_event_win_hktl_crackmapexec_indicators.yml` |
| high | HackTool - Impacket File Indicators | file_event | `rules/windows/file/file_event/file_event_win_impacket_file_indicators.yml` |
| high | HackTool - NetExec File Indicators | file_event | `rules/windows/file/file_event/file_event_win_hktl_netexec_file_indicators.yml` |
| high | HackTool - NPPSpy Hacktool Usage | file_event | `rules/windows/file/file_event/file_event_win_hktl_nppspy.yml` |
| high | HackTool - Potential Remote Credential Dumping Activity Via CrackMapExec Or Impacket-Secretsdump | file_event | `rules/windows/file/file_event/file_event_win_hktl_remote_cred_dump.yml` |
| high | HackTool - Powerup Write Hijack DLL | file_event | `rules/windows/file/file_event/file_event_win_hktl_powerup_dllhijacking.yml` |
| high | HackTool - RemoteKrbRelay SMB Relay Secrets Dump Module Indicators | file_event | `rules/windows/file/file_event/file_event_win_hktl_krbrelay_remote_ioc.yml` |
| high | HackTool - SafetyKatz Dump Indicator | file_event | `rules/windows/file/file_event/file_event_win_hktl_safetykatz.yml` |
| high | HackTool - Typical HiveNightmare SAM File Export | file_event | `rules/windows/file/file_event/file_event_win_hktl_hivenightmare_file_exports.yml` |
| high | Hijack Legit RDP Session to Move Laterally | file_event | `rules/windows/file/file_event/file_event_win_tsclient_filewrite_startup.yml` |
| high | ISO File Created Within Temp Folders | file_event | `rules/windows/file/file_event/file_event_win_iso_file_mount.yml` |
| high | Legitimate Application Dropped Archive | file_event | `rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_archive.yml` |
| high | Legitimate Application Dropped Executable | file_event | `rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_exe.yml` |
| high | Legitimate Application Dropped Script | file_event | `rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_script.yml` |
| high | Legitimate Application Writing Files In Uncommon Location | file_event | `rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_in_uncommon_location.yml` |
| high | LiveKD Driver Creation By Uncommon Process | file_event | `rules/windows/file/file_event/file_event_win_sysinternals_livekd_driver_susp_creation.yml` |
| high | LiveKD Kernel Memory Dump File Created | file_event | `rules/windows/file/file_event/file_event_win_sysinternals_livekd_default_dump_name.yml` |
| high | LSASS Process Dump Artefact In CrashDumps Folder | file_event | `rules/windows/file/file_event/file_event_win_lsass_shtinkering.yml` |
| high | LSASS Process Memory Dump Creation Via Taskmgr.EXE | file_event | `rules/windows/file/file_event/file_event_win_taskmgr_lsass_dump.yml` |
| high | LSASS Process Memory Dump Files | file_event | `rules/windows/file/file_event/file_event_win_lsass_default_dump_file_names.yml` |
| high | Malicious DLL File Dropped in the Teams or OneDrive Folder | file_event | `rules/windows/file/file_event/file_event_win_iphlpapi_dll_sideloading.yml` |
| high | Malicious PowerShell Scripts - FileCreation | file_event | `rules/windows/file/file_event/file_event_win_powershell_exploit_scripts.yml` |
| high | NTDS Exfiltration Filename Patterns | file_event | `rules/windows/file/file_event/file_event_win_ntds_exfil_tools.yml` |
| high | NTDS.DIT Creation By Uncommon Parent Process | file_event | `rules/windows/file/file_event/file_event_win_ntds_dit_uncommon_parent_process.yml` |
| high | NTDS.DIT Creation By Uncommon Process | file_event | `rules/windows/file/file_event/file_event_win_ntds_dit_uncommon_process.yml` |
| high | Octopus Scanner Malware | file_event | `rules/windows/file/file_event/file_event_win_mal_octopus_scanner.yml` |
| high | Office Macro File Creation From Suspicious Process | file_event | `rules/windows/file/file_event/file_event_win_office_macro_files_from_susp_process.yml` |
| high | PCRE.NET Package Temp Files | file_event | `rules/windows/file/file_event/file_event_win_pcre_net_temp_file.yml` |
| high | PDF File Created By RegEdit.EXE | file_event | `rules/windows/file/file_event/file_event_win_regedit_print_as_pdf.yml` |
| high | Potential File Extension Spoofing Using Right-to-Left Override | file_event | `rules/windows/file/file_event/file_event_win_susp_right_to_left_override_extension_spoofing.yml` |
| high | Potential Persistence Via Microsoft Office Add-In | file_event | `rules/windows/file/file_event/file_event_win_office_addin_persistence.yml` |
| high | Potential Persistence Via Microsoft Office Startup Folder | file_event | `rules/windows/file/file_event/file_event_win_office_startup_persistence.yml` |
| high | Potential Persistence Via Outlook Form | file_event | `rules/windows/file/file_event/file_event_win_office_outlook_newform.yml` |
| high | Potential Privilege Escalation Attempt Via .Exe.Local Technique | file_event | `rules/windows/file/file_event/file_event_win_system32_local_folder_privilege_escalation.yml` |
| high | Potential RipZip Attack on Startup Folder | file_event | `rules/windows/file/file_event/file_event_win_ripzip_attack.yml` |
| high | Potential SAM Database Dump | file_event | `rules/windows/file/file_event/file_event_win_sam_dump.yml` |
| high | Potential Startup Shortcut Persistence Via PowerShell.EXE | file_event | `rules/windows/file/file_event/file_event_win_powershell_startup_shortcuts.yml` |
| high | Potential Winnti Dropper Activity | file_event | `rules/windows/file/file_event/file_event_win_redmimicry_winnti_filedrop.yml` |
| high | Prefetch File Deleted | file_delete | `rules/windows/file/file_delete/file_delete_win_delete_prefetch.yml` |
| high | Process Explorer Driver Creation By Non-Sysinternals Binary | file_event | `rules/windows/file/file_event/file_event_win_sysinternals_procexp_driver_susp_creation.yml` |
| high | PSEXEC Remote Execution File Artefact | file_event | `rules/windows/file/file_event/file_event_win_sysinternals_psexec_service_key.yml` |
| high | Renamed VsCode Code Tunnel Execution - File Indicator | file_event | `rules/windows/file/file_event/file_event_win_vscode_tunnel_renamed_execution.yml` |
| high | Suspicious ASPX File Drop by Exchange | file_event | `rules/windows/file/file_event/file_event_win_exchange_webshell_drop.yml` |
| high | Suspicious Binaries and Scripts in Public Folder | file_event | `rules/windows/file/file_event/file_event_win_susp_public_folder_extension.yml` |
| high | Suspicious Binary Writes Via AnyDesk | file_event | `rules/windows/file/file_event/file_event_win_anydesk_writing_susp_binaries.yml` |
| high | Suspicious Creation with Colorcpl | file_event | `rules/windows/file/file_event/file_event_win_susp_colorcpl.yml` |
| high | Suspicious Desktopimgdownldr Target File | file_event | `rules/windows/file/file_event/file_event_win_susp_desktopimgdownldr_file.yml` |
| high | Suspicious DotNET CLR Usage Log Artifact | file_event | `rules/windows/file/file_event/file_event_win_net_cli_artefact.yml` |
| high | Suspicious Double Extension Files | file_event | `rules/windows/file/file_event/file_event_win_susp_double_extension.yml` |
| high | Suspicious Executable File Creation | file_event | `rules/windows/file/file_event/file_event_win_susp_executable_creation.yml` |
| high | Suspicious File Created by ArcSOC.exe | file_event | `rules/windows/file/file_event/file_event_win_arcsoc_susp_file_created.yml` |
| high | Suspicious File Created in Outlook Temporary Directory | file_event | `rules/windows/file/file_event/file_event_win_office_outlook_susp_file_creation_in_temp_dir.yml` |
| high | Suspicious File Created Via OneNote Application | file_event | `rules/windows/file/file_event/file_event_win_office_onenote_susp_dropped_files.yml` |
| high | Suspicious File Creation Activity From Fake Recycle.Bin Folder | file_event | `rules/windows/file/file_event/file_event_win_susp_recycle_bin_fake_exec.yml` |
| high | Suspicious File Creation In Uncommon AppData Folder | file_event | `rules/windows/file/file_event/file_event_win_new_files_in_uncommon_appdata_folder.yml` |
| high | Suspicious File Write to SharePoint Layouts Directory | file_event | `rules/windows/file/file_event/file_event_win_susp_filewrite_in_sharepoint_layouts_dir.yml` |
| high | Suspicious Get-Variable.exe Creation | file_event | `rules/windows/file/file_event/file_event_win_susp_get_variable.yml` |
| high | Suspicious Interactive PowerShell as SYSTEM | file_event | `rules/windows/file/file_event/file_event_win_susp_system_interactive_powershell.yml` |
| high | Suspicious MSExchangeMailboxReplication ASPX Write | file_event | `rules/windows/file/file_event/file_event_win_susp_exchange_aspx_write.yml` |
| high | Suspicious Outlook Macro Created | file_event | `rules/windows/file/file_event/file_event_win_office_outlook_susp_macro_creation.yml` |
| high | Suspicious Scheduled Task Write to System32 Tasks | file_event | `rules/windows/file/file_event/file_event_win_susp_task_write.yml` |
| high | Suspicious Startup Folder Persistence | file_event | `rules/windows/file/file_event/file_event_win_susp_startup_folder_persistence.yml` |
| high | UAC Bypass Abusing Winsat Path Parsing - File | file_event | `rules/windows/file/file_event/file_event_win_uac_bypass_winsat.yml` |
| high | UAC Bypass Using .NET Code Profiler on MMC | file_event | `rules/windows/file/file_event/file_event_win_uac_bypass_dotnet_profiler.yml` |
| high | UAC Bypass Using Consent and Comctl32 - File | file_event | `rules/windows/file/file_event/file_event_win_uac_bypass_consent_comctl32.yml` |
| high | UAC Bypass Using EventVwr | file_event | `rules/windows/file/file_event/file_event_win_uac_bypass_eventvwr.yml` |
| high | UAC Bypass Using IDiagnostic Profile - File | file_event | `rules/windows/file/file_event/file_event_win_uac_bypass_idiagnostic_profile.yml` |
| high | UAC Bypass Using IEInstal - File | file_event | `rules/windows/file/file_event/file_event_win_uac_bypass_ieinstal.yml` |
| high | UAC Bypass Using MSConfig Token Modification - File | file_event | `rules/windows/file/file_event/file_event_win_uac_bypass_msconfig_gui.yml` |
| high | UAC Bypass Using NTFS Reparse Point - File | file_event | `rules/windows/file/file_event/file_event_win_uac_bypass_ntfs_reparse_point.yml` |
| high | UAC Bypass Using Windows Media Player - File | file_event | `rules/windows/file/file_event/file_event_win_uac_bypass_wmp.yml` |
| high | UEFI Persistence Via Wpbbin - FileCreation | file_event | `rules/windows/file/file_event/file_event_win_wpbbin_persistence.yml` |
| high | Uncommon File Created by Notepad++ Updater Gup.EXE | file_event | `rules/windows/file/file_event/file_event_win_gup_uncommon_file_creation.yml` |
| high | Uncommon File Created In Office Startup Folder | file_event | `rules/windows/file/file_event/file_event_win_office_uncommon_file_startup.yml` |
| high | Uncommon File Creation By Mysql Daemon Process | file_event | `rules/windows/file/file_event/file_event_win_mysqld_uncommon_file_creation.yml` |
| high | Unusual File Deletion by Dns.exe | file_delete | `rules/windows/file/file_delete/file_delete_win_unusual_deletion_by_dns_exe.yml` |
| high | Unusual File Modification by dns.exe | file_change | `rules/windows/file/file_change/file_change_win_unusual_modification_by_dns_exe.yml` |
| high | WerFault LSASS Process Memory Dump | file_event | `rules/windows/file/file_event/file_event_win_lsass_werfault_dump.yml` |
| high | Windows Binaries Write Suspicious Extensions | file_event | `rules/windows/file/file_event/file_event_win_shell_write_susp_files_extensions.yml` |
| high | Windows Shell/Scripting Application File Write to Suspicious Folder | file_event | `rules/windows/file/file_event/file_event_win_shell_write_susp_directory.yml` |
| high | WinRAR Creating Files in Startup Locations | file_event | `rules/windows/file/file_event/file_event_win_winrar_file_creation_in_startup_folder.yml` |
| high | WMI Persistence - Script Event Consumer File Write | file_event | `rules/windows/file/file_event/file_event_win_wmi_persistence_script_event_consumer_write.yml` |
| high | WScript or CScript Dropper - File | file_event | `rules/windows/file/file_event/file_event_win_cscript_wscript_dropper.yml` |

## registry_persist (140)

| level | title | category/service | file |
|---|---|---|---|
| critical | Potential Credential Dumping Via LSASS SilentProcessExit Technique | registry_event | `rules/windows/registry/registry_event/registry_event_silentprocessexit_lsass.yml` |
| critical | Registry Entries For Azorult Malware | registry_event | `rules/windows/registry/registry_event/registry_event_mal_azorult.yml` |
| critical | Sticky Key Like Backdoor Usage - Registry | registry_event | `rules/windows/registry/registry_event/registry_event_stickykey_like_backdoor.yml` |
| critical | Windows Credential Editor Registry | registry_event | `rules/windows/registry/registry_event/registry_event_hack_wce_reg.yml` |
| high | Add Debugger Entry To Hangs Key For Persistence | registry_set | `rules/windows/registry/registry_set/registry_set_hangs_debugger_persistence.yml` |
| high | AMSI Disabled via Registry Modification | registry_set | `rules/windows/registry/registry_set/registry_set_amsi_disable.yml` |
| high | Antivirus Filter Driver Disallowed On Dev Drive - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_devdrv_disallow_antivirus_filter.yml` |
| high | Bypass UAC Using DelegateExecute | registry_set | `rules/windows/registry/registry_set/registry_set_bypass_uac_using_delegateexecute.yml` |
| high | Bypass UAC Using Event Viewer | registry_set | `rules/windows/registry/registry_set/registry_set_bypass_uac_using_eventviewer.yml` |
| high | Bypass UAC Using SilentCleanup Task | registry_set | `rules/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task.yml` |
| high | Change the Fax Dll | registry_set | `rules/windows/registry/registry_set/registry_set_fax_dll_persistance.yml` |
| high | Change User Account Associated with the FAX Service | registry_set | `rules/windows/registry/registry_set/registry_set_fax_change_service_user.yml` |
| high | Change Winevt Channel Access Permission Via Registry | registry_set | `rules/windows/registry/registry_set/registry_set_change_winevt_channelaccess.yml` |
| high | CMSTP Execution Registry Event | registry_event | `rules/windows/registry/registry_event/registry_event_cmstp_execution_by_registry.yml` |
| high | COM Hijack via Sdclt | registry_set | `rules/windows/registry/registry_set/registry_set_comhijack_sdclt.yml` |
| high | COM Object Hijacking Via Modification Of Default System CLSID Default Value | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_com_hijacking_builtin.yml` |
| high | Creation of a Local Hidden User Account by Registry | registry_event | `rules/windows/registry/registry_event/registry_event_add_local_hidden_user.yml` |
| high | Custom File Open Handler Executes PowerShell | registry_set | `rules/windows/registry/registry_set/registry_set_custom_file_open_handler_powershell_execution.yml` |
| high | Default RDP Port Changed to Non Standard Port | registry_set | `rules/windows/registry/registry_set/registry_set_change_rdp_port.yml` |
| high | DHCP Callout DLL Installation | registry_set | `rules/windows/registry/registry_set/registry_set_dhcp_calloutdll.yml` |
| high | Directory Service Restore Mode(DSRM) Registry Value Tampering | registry_set | `rules/windows/registry/registry_set/registry_set_dsrm_tampering.yml` |
| high | Disable Macro Runtime Scan Scope | registry_set | `rules/windows/registry/registry_set/registry_set_disable_macroruntimescanscope.yml` |
| high | Disable PUA Protection on Windows Defender | registry_set | `rules/windows/registry/registry_set/registry_set_disabled_pua_protection_on_microsoft_defender.yml` |
| high | Disable Security Events Logging Adding Reg Key MiniNt | registry_event | `rules/windows/registry/registry_event/registry_event_disable_security_events_logging_adding_reg_key_minint.yml` |
| high | Disable Windows Defender Functionalities Via Registry Keys | registry_set | `rules/windows/registry/registry_set/registry_set_windows_defender_tamper.yml` |
| high | Disable Windows Event Logging Via Registry | registry_set | `rules/windows/registry/registry_set/registry_set_disable_winevt_logging.yml` |
| high | Disabled Windows Defender Eventlog | registry_set | `rules/windows/registry/registry_set/registry_set_disabled_microsoft_defender_eventlog.yml` |
| high | DLL Load via LSASS | registry_event | `rules/windows/registry/registry_event/registry_event_susp_lsass_dll_load.yml` |
| high | Driver Added To Disallowed Images In HVCI - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_hvci_disallowed_images.yml` |
| high | Enable LM Hash Storage | registry_set | `rules/windows/registry/registry_set/registry_set_system_lsa_nolmhash.yml` |
| high | Esentutl Volume Shadow Copy Service Keys | registry_event | `rules/windows/registry/registry_event/registry_event_esentutl_volume_shadow_copy_service_keys.yml` |
| high | ETW Logging Disabled In .NET Processes - Sysmon Registry | registry_set | `rules/windows/registry/registry_set/registry_set_dot_net_etw_tamper.yml` |
| high | Execution DLL of Choice Using WAB.EXE | registry_set | `rules/windows/registry/registry_set/registry_set_wab_dllpath_reg_change.yml` |
| high | FileFix - Command Evidence in TypedPaths | registry_set | `rules/windows/registry/registry_set/registry_set_filefix_typedpath_commands.yml` |
| high | Folder Removed From Exploit Guard ProtectedFolders List - Registry | registry_delete | `rules/windows/registry/registry_delete/registry_delete_exploit_guard_protected_folders.yml` |
| high | Hide Schedule Task Via Index Value Tamper | registry_set | `rules/windows/registry/registry_set/registry_set_hide_scheduled_task_via_index_tamper.yml` |
| high | Hiding User Account Via SpecialAccounts Registry Key | registry_set | `rules/windows/registry/registry_set/registry_set_special_accounts.yml` |
| high | HybridConnectionManager Service Installation - Registry | registry_event | `rules/windows/registry/registry_event/registry_event_hybridconnectionmgr_svc_installation.yml` |
| high | Hypervisor Enforced Paging Translation Disabled | registry_set | `rules/windows/registry/registry_set/registry_set_deviceguard_hypervisorenforcedpagingtranslation_disabled.yml` |
| high | IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols | registry_set | `rules/windows/registry/registry_set/registry_set_ie_security_zone_protocol_defaults_downgrade.yml` |
| high | Lolbas OneDriveStandaloneUpdater.exe Proxy Download | registry_set | `rules/windows/registry/registry_set/registry_set_lolbin_onedrivestandaloneupdater.yml` |
| high | Lsass Full Dump Request Via DumpType Registry Settings | registry_set | `rules/windows/registry/registry_set/registry_set_lsass_usermode_dumping.yml` |
| high | Macro Enabled In A Potentially Suspicious Document | registry_set | `rules/windows/registry/registry_set/registry_set_office_trust_record_susp_location.yml` |
| high | Microsoft Office Protected View Disabled | registry_set | `rules/windows/registry/registry_set/registry_set_office_disable_protected_view_features.yml` |
| high | Modify User Shell Folders Startup Value | registry_set | `rules/windows/registry/registry_set/registry_set_susp_user_shell_folders.yml` |
| high | Narrator's Feedback-Hub Persistence | registry_event | `rules/windows/registry/registry_event/registry_event_narrator_feedback_persistance.yml` |
| high | NET NGenAssemblyUsageLog Registry Key Tamper | registry_set | `rules/windows/registry/registry_set/registry_set_net_cli_ngenassemblyusagelog.yml` |
| high | NetNTLM Downgrade Attack - Registry | registry_event | `rules/windows/registry/registry_event/registry_event_net_ntlm_downgrade.yml` |
| high | New DNS ServerLevelPluginDll Installed | registry_set | `rules/windows/registry/registry_set/registry_set_dns_server_level_plugin_dll.yml` |
| high | New File Association Using Exefile | registry_set | `rules/windows/registry/registry_set/registry_set_file_association_exefile.yml` |
| high | New Netsh Helper DLL Registered From A Suspicious Location | registry_set | `rules/windows/registry/registry_set/registry_set_netsh_help_dll_persistence_susp_location.yml` |
| high | New RUN Key Pointing to Suspicious Folder | registry_set | `rules/windows/registry/registry_set/registry_set_susp_run_key_img_folder.yml` |
| high | New TimeProviders Registered With Uncommon DLL Name | registry_set | `rules/windows/registry/registry_set/registry_set_timeproviders_dllname.yml` |
| high | Office Macros Warning Disabled | registry_set | `rules/windows/registry/registry_set/registry_set_office_vba_warnings_tamper.yml` |
| high | Outlook EnableUnsafeClientMailRules Setting Enabled - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_office_outlook_enable_unsafe_client_mail_rules.yml` |
| high | Outlook Macro Execution Without Warning Setting Enabled | registry_set | `rules/windows/registry/registry_set/registry_set_office_outlook_enable_macro_execution.yml` |
| high | Persistence Via Hhctrl.ocx | registry_set | `rules/windows/registry/registry_set/registry_set_hhctrl_persistence.yml` |
| high | Potential AMSI COM Server Hijacking | registry_set | `rules/windows/registry/registry_set/registry_set_amsi_com_hijack.yml` |
| high | Potential Attachment Manager Settings Associations Tamper | registry_set | `rules/windows/registry/registry_set/registry_set_policies_associations_tamper.yml` |
| high | Potential Attachment Manager Settings Attachments Tamper | registry_set | `rules/windows/registry/registry_set/registry_set_policies_attachments_tamper.yml` |
| high | Potential AutoLogger Sessions Tampering | registry_set | `rules/windows/registry/registry_set/registry_set_disable_autologger_sessions.yml` |
| high | Potential ClickFix Execution Pattern - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_potential_clickfix_execution.yml` |
| high | Potential CobaltStrike Service Installations - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_cobaltstrike_service_installs.yml` |
| high | Potential EventLog File Location Tampering | registry_set | `rules/windows/registry/registry_set/registry_set_evtx_file_key_tamper.yml` |
| high | Potential Persistence Via App Paths Default Property | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_app_paths.yml` |
| high | Potential Persistence Via AutodialDLL | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_autodial_dll.yml` |
| high | Potential Persistence Via CHM Helper DLL | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_chm.yml` |
| high | Potential Persistence Via DLLPathOverride | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_natural_language.yml` |
| high | Potential Persistence Via Excel Add-in - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_xll.yml` |
| high | Potential Persistence Via GlobalFlags | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_globalflags.yml` |
| high | Potential Persistence Via LSA Extensions | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_lsa_extension.yml` |
| high | Potential Persistence Via Mpnotify | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_mpnotify.yml` |
| high | Potential Persistence Via MyComputer Registry Keys | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_mycomputer.yml` |
| high | Potential Persistence Via Outlook Home Page | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_outlook_homepage.yml` |
| high | Potential Persistence Via Outlook LoadMacroProviderOnBoot Setting | registry_set | `rules/windows/registry/registry_set/registry_set_office_outlook_enable_load_macro_provider_on_boot.yml` |
| high | Potential Persistence Via Outlook Today Page | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_outlook_todaypage.yml` |
| high | Potential Persistence Via Shim Database In Uncommon Location | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_shim_database_uncommon_location.yml` |
| high | Potential Persistence Via TypedPaths | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_typed_paths.yml` |
| high | Potential Provisioning Registry Key Abuse For Binary Proxy Execution - REG | registry_set | `rules/windows/registry/registry_set/registry_set_provisioning_command_abuse.yml` |
| high | Potential PSFactoryBuffer COM Hijacking | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_comhijack_psfactorybuffer.yml` |
| high | Potential Qakbot Registry Activity | registry_event | `rules/windows/registry/registry_event/registry_event_malware_qakbot_registry.yml` |
| high | Potential Ransomware Activity Using LegalNotice Message | registry_set | `rules/windows/registry/registry_set/registry_set_legalnotice_susp_message.yml` |
| high | Potential Registry Persistence Attempt Via Windows Telemetry | registry_set | `rules/windows/registry/registry_set/registry_set_telemetry_persistence.yml` |
| high | Potential Signing Bypass Via Windows Developer Features - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_turn_on_dev_features.yml` |
| high | Potential WerFault ReflectDebugger Registry Value Abuse | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_reflectdebugger.yml` |
| high | Potentially Suspicious Command Executed Via Run Dialog Box - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_runmru_susp_command_execution.yml` |
| high | Potentially Suspicious ODBC Driver Registered | registry_set | `rules/windows/registry/registry_set/registry_set_odbc_driver_registered_susp.yml` |
| high | PowerShell as a Service in Registry | registry_set | `rules/windows/registry/registry_set/registry_set_powershell_as_service.yml` |
| high | PowerShell Logging Disabled Via Registry Key Tampering | registry_set | `rules/windows/registry/registry_set/registry_set_powershell_logging_disabled.yml` |
| high | Python Function Execution Security Warning Disabled In Excel - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_office_disable_python_security_warnings.yml` |
| high | RDP Sensitive Settings Changed | registry_set | `rules/windows/registry/registry_set/registry_set_terminal_server_tampering.yml` |
| high | RedMimicry Winnti Playbook Registry Manipulation | registry_event | `rules/windows/registry/registry_event/registry_event_redmimicry_winnti_reg.yml` |
| high | Registry Disable System Restore | registry_set | `rules/windows/registry/registry_set/registry_set_disable_system_restore.yml` |
| high | Registry Modification for OCI DLL Redirection | registry_set | `rules/windows/registry/registry_set/registry_set_potential_oci_dll_redirection.yml` |
| high | Registry Persistence Mechanisms in Recycle Bin | registry_event | `rules/windows/registry/registry_event/registry_event_persistence_recycle_bin.yml` |
| high | Registry Persistence via Explorer Run Key | registry_set | `rules/windows/registry/registry_set/registry_set_susp_reg_persist_explorer_run.yml` |
| high | Registry Persistence via Service in Safe Mode | registry_set | `rules/windows/registry/registry_set/registry_set_add_load_service_in_safe_mode.yml` |
| high | Removal Of AMSI Provider Registry Keys | registry_delete | `rules/windows/registry/registry_delete/registry_delete_removal_amsi_registry_key.yml` |
| high | RestrictedAdminMode Registry Value Tampering | registry_set | `rules/windows/registry/registry_set/registry_set_lsa_disablerestrictedadmin.yml` |
| high | RunMRU Registry Key Deletion - Registry | registry_delete | `rules/windows/registry/registry_delete/registry_delete_runmru.yml` |
| high | Running Chrome VPN Extensions via the Registry 2 VPN Extension | registry_set | `rules/windows/registry/registry_set/registry_set_chrome_extension.yml` |
| high | Scheduled TaskCache Change by Uncommon Program | registry_set | `rules/windows/registry/registry_set/registry_set_taskcache_entry.yml` |
| high | Security Event Logging Disabled via MiniNt Registry Key - Registry Set | registry_set | `rules/windows/registry/registry_set/registry_set_create_minint_key.yml` |
| high | Security Support Provider (SSP) Added to LSA Configuration | registry_event | `rules/windows/registry/registry_event/registry_event_ssp_added_lsa_config.yml` |
| high | Service Binary in Suspicious Folder | registry_set | `rules/windows/registry/registry_set/registry_set_creation_service_susp_folder.yml` |
| high | Shell Open Registry Keys Manipulation | registry_event | `rules/windows/registry/registry_event/registry_event_shell_open_keys_manipulation.yml` |
| high | Suspicious Application Allowed Through Exploit Guard | registry_set | `rules/windows/registry/registry_set/registry_set_exploit_guard_susp_allowed_apps.yml` |
| high | Suspicious Camera and Microphone Access | registry_event | `rules/windows/registry/registry_event/registry_event_susp_mic_cam_access.yml` |
| high | Suspicious Environment Variable Has Been Registered | registry_set | `rules/windows/registry/registry_set/registry_set_suspicious_env_variables.yml` |
| high | Suspicious Execution Of Renamed Sysinternals Tools - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_pua_sysinternals_renamed_execution_via_eula.yml` |
| high | Suspicious Path In Keyboard Layout IME File Registry Value | registry_set | `rules/windows/registry/registry_set/registry_set_ime_suspicious_paths.yml` |
| high | Suspicious Printer Driver Empty Manufacturer | registry_set | `rules/windows/registry/registry_set/registry_set_susp_printer_driver.yml` |
| high | Suspicious Run Key from Download | registry_event | `rules/windows/registry/registry_event/registry_event_susp_download_run_key.yml` |
| high | Suspicious Shim Database Patching Activity | registry_set | `rules/windows/registry/registry_set/registry_set_persistence_shim_database_susp_application.yml` |
| high | Suspicious Space Characters in RunMRU Registry Path - ClickFix | registry_set | `rules/windows/registry/registry_set/registry_set_susp_runmru_space_character.yml` |
| high | Suspicious Space Characters in TypedPaths Registry Path - FileFix | registry_set | `rules/windows/registry/registry_set/registry_set_susp_typedpaths_space_characters.yml` |
| high | Sysmon Driver Altitude Change | registry_set | `rules/windows/registry/registry_set/registry_set_change_sysmon_driver_altitude.yml` |
| high | Tamper With Sophos AV Registry Keys | registry_set | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` |
| high | Terminal Server Client Connection History Cleared - Registry | registry_delete | `rules/windows/registry/registry_delete/registry_delete_mstsc_history_cleared.yml` |
| high | Trust Access Disable For VBApplications | registry_set | `rules/windows/registry/registry_set/registry_set_office_access_vbom_tamper.yml` |
| high | UAC Bypass Abusing Winsat Path Parsing - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_uac_bypass_winsat.yml` |
| high | UAC Bypass Using Windows Media Player - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_uac_bypass_wmp.yml` |
| high | UAC Bypass via Event Viewer | registry_set | `rules/windows/registry/registry_set/registry_set_uac_bypass_eventvwr.yml` |
| high | UAC Bypass via Sdclt | registry_set | `rules/windows/registry/registry_set/registry_set_uac_bypass_sdclt.yml` |
| high | UAC Bypass Via Wsreset | registry_event | `rules/windows/registry/registry_event/registry_event_bypass_via_wsreset.yml` |
| high | Uncommon Extension In Keyboard Layout IME File Registry Value | registry_set | `rules/windows/registry/registry_set/registry_set_ime_non_default_extension.yml` |
| high | Uncommon Microsoft Office Trusted Location Added | registry_set | `rules/windows/registry/registry_set/registry_set_office_trusted_location_uncommon.yml` |
| high | Usage of Renamed Sysinternals Tools - RegistrySet | registry_set | `rules/windows/registry/registry_set/registry_set_renamed_sysinternals_eula_accepted.yml` |
| high | VBScript Payload Stored in Registry | registry_set | `rules/windows/registry/registry_set/registry_set_vbs_payload_stored.yml` |
| high | Wdigest CredGuard Registry Modification | registry_event | `rules/windows/registry/registry_event/registry_event_disable_wdigest_credential_guard.yml` |
| high | Wdigest Enable UseLogonCredential | registry_set | `rules/windows/registry/registry_set/registry_set_wdigest_enable_uselogoncredential.yml` |
| high | Windows Credential Guard Disabled - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_credential_guard_disabled.yml` |
| high | Windows Credential Guard Related Registry Value Deleted - Registry | registry_delete | `rules/windows/registry/registry_delete/registry_delete_disable_credential_guard.yml` |
| high | Windows Defender Service Disabled - Registry | registry_set | `rules/windows/registry/registry_set/registry_set_disable_windows_defender_service.yml` |
| high | Windows Defender Threat Severity Default Action Modified | registry_event | `rules/windows/registry/registry_event/registry_event_defender_threat_action_modified.yml` |
| high | Windows Event Log Access Tampering Via Registry | registry_set | `rules/windows/registry/registry_set/registry_set_disable_windows_event_log_access.yml` |
| high | Windows Hypervisor Enforced Code Integrity Disabled | registry_set | `rules/windows/registry/registry_set/registry_set_deviceguard_hypervisorenforcedcodeintegrity_disabled.yml` |
| high | Windows Vulnerable Driver Blocklist Disabled | registry_set | `rules/windows/registry/registry_set/registry_set_vulnerable_driver_blocklist_disable.yml` |
| high | WINEKEY Registry Modification | registry_event | `rules/windows/registry/registry_event/registry_event_runkey_winekey.yml` |
| high | Winlogon Notify Key Logon Persistence | registry_set | `rules/windows/registry/registry_set/registry_set_winlogon_notify_key.yml` |

## driver_ioc (10)

| level | title | category/service | file |
|---|---|---|---|
| high | CodeIntegrity - Blocked Driver Load With Revoked Certificate | codeintegrity-operational | `rules/windows/builtin/code_integrity/win_codeintegrity_revoked_driver_blocked.yml` |
| high | CodeIntegrity - Revoked Kernel Driver Loaded | codeintegrity-operational | `rules/windows/builtin/code_integrity/win_codeintegrity_revoked_driver_loaded.yml` |
| high | CodeIntegrity - Unsigned Kernel Module Loaded | codeintegrity-operational | `rules/windows/builtin/code_integrity/win_codeintegrity_unsigned_driver_loaded.yml` |
| high | Driver Load From A Temporary Directory | driver_load | `rules/windows/driver_load/driver_load_win_susp_temp_use.yml` |
| high | Malicious Driver Load | driver_load | `rules/windows/driver_load/driver_load_win_mal_drivers.yml` |
| high | PUA - Process Hacker Driver Load | driver_load | `rules/windows/driver_load/driver_load_win_pua_process_hacker.yml` |
| high | Vulnerable Driver Load | driver_load | `rules/windows/driver_load/driver_load_win_vuln_drivers.yml` |
| high | Vulnerable HackSys Extreme Vulnerable Driver Load | driver_load | `rules/windows/driver_load/driver_load_win_vuln_hevd_driver.yml` |
| high | Vulnerable WinRing0 Driver Load | driver_load | `rules/windows/driver_load/driver_load_win_vuln_winring0_driver.yml` |
| high | WinDivert Driver Load | driver_load | `rules/windows/driver_load/driver_load_win_windivert.yml` |

## eventlog_or_review (41)

| level | title | category/service | file |
|---|---|---|---|
| critical | Audit CVE Event | application | `rules/windows/builtin/application/microsoft-windows_audit_cve/win_audit_cve.yml` |
| critical | Certificate Request Export to Exchange Webserver | msexchange-management | `rules/windows/builtin/msexchange/win_exchange_proxyshell_certificate_generation.yml` |
| critical | Mailbox Export to Exchange Webserver | msexchange-management | `rules/windows/builtin/msexchange/win_exchange_proxyshell_mailbox_export.yml` |
| critical | ProxyLogon MSExchange OabVirtualDirectory | msexchange-management | `rules/windows/builtin/msexchange/win_exchange_proxylogon_oabvirtualdir.yml` |
| critical | Suspicious Cobalt Strike DNS Beaconing - DNS Client | dns-client | `rules/windows/builtin/dns_client/win_dns_client_mal_cobaltstrike.yml` |
| high | All Rules Have Been Deleted From The Windows Firewall Configuration | firewall-as | `rules/windows/builtin/firewall_as/win_firewall_as_delete_all_rules.yml` |
| high | AppX Located in Known Staging Directory Added to Deployment Pipeline | appxdeployment-server | `rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_appx_package_in_staging_directory.yml` |
| high | Atera Agent Installation | application | `rules/windows/builtin/application/msiinstaller/win_software_atera_rmm_agent_install.yml` |
| high | BITS Transfer Job Download From Direct IP | bits-client | `rules/windows/builtin/bits_client/win_bits_client_new_transfer_via_ip_address.yml` |
| high | BITS Transfer Job Download From File Sharing Domains | bits-client | `rules/windows/builtin/bits_client/win_bits_client_new_transfer_via_file_sharing_domains.yml` |
| high | BITS Transfer Job Download To Potential Suspicious Folder | bits-client | `rules/windows/builtin/bits_client/win_bits_client_new_trasnfer_susp_local_folder.yml` |
| high | CodeIntegrity - Blocked Image Load With Revoked Certificate | codeintegrity-operational | `rules/windows/builtin/code_integrity/win_codeintegrity_revoked_image_blocked.yml` |
| high | CodeIntegrity - Blocked Image/Driver Load For Policy Violation | codeintegrity-operational | `rules/windows/builtin/code_integrity/win_codeintegrity_enforced_policy_block.yml` |
| high | CodeIntegrity - Disallowed File For Protected Processes Has Been Blocked | codeintegrity-operational | `rules/windows/builtin/code_integrity/win_codeintegrity_blocked_protected_process_file.yml` |
| high | CodeIntegrity - Revoked Image Loaded | codeintegrity-operational | `rules/windows/builtin/code_integrity/win_codeintegrity_revoked_image_loaded.yml` |
| high | CodeIntegrity - Unmet WHQL Requirements For Loaded Kernel Module | codeintegrity-operational | `rules/windows/builtin/code_integrity/win_codeintegrity_whql_failure.yml` |
| high | CodeIntegrity - Unsigned Image Loaded | codeintegrity-operational | `rules/windows/builtin/code_integrity/win_codeintegrity_unsigned_image_loaded.yml` |
| high | DNS Query for Anonfiles.com Domain - DNS Client | dns-client | `rules/windows/builtin/dns_client/win_dns_client_anonymfiles_com.yml` |
| high | Exchange Set OabVirtualDirectory ExternalUrl Property | msexchange-management | `rules/windows/builtin/msexchange/win_exchange_set_oabvirtualdirectory_externalurl.yml` |
| high | Failed MSExchange Transport Agent Installation | msexchange-management | `rules/windows/builtin/msexchange/win_exchange_transportagent_failed.yml` |
| high | HTTP Logging Disabled On IIS Server | iis-configuration | `rules/windows/builtin/iis-configuration/win_iis_logging_http_disabled.yml` |
| high | HybridConnectionManager Service Running | microsoft-servicebus-client | `rules/windows/builtin/servicebus/win_hybridconnectionmgr_svc_running.yml` |
| high | Loading Diagcab Package From Remote Path | diagnosis-scripted | `rules/windows/builtin/diagnosis/scripted/win_diagnosis_scripted_load_remote_diagcab.yml` |
| high | LSASS Process Crashed - Application | application | `rules/windows/builtin/application/application_error/win_application_error_lsass_crash.yml` |
| high | Microsoft Defender Blocked from Loading Unsigned DLL | security-mitigations | `rules/windows/builtin/security_mitigations/win_security_mitigations_defender_load_unsigned_dll.yml` |
| high | Microsoft Malware Protection Engine Crash | application | `rules/windows/builtin/application/application_error/win_application_error_msmpeng_crash.yml` |
| high | Microsoft Malware Protection Engine Crash - WER | application | `rules/windows/builtin/application/windows_error_reporting/win_application_msmpeng_crash_wer.yml` |
| high | Mimikatz Use | - | `rules/windows/builtin/win_alert_mimikatz_keywords.yml` |
| high | MSSQL Add Account To Sysadmin Role | application | `rules/windows/builtin/application/mssqlserver/win_mssql_add_sysadmin_account.yml` |
| high | MSSQL Disable Audit Settings | application | `rules/windows/builtin/application/mssqlserver/win_mssql_disable_audit_settings.yml` |
| high | MSSQL SPProcoption Set | application | `rules/windows/builtin/application/mssqlserver/win_mssql_sp_procoption_set.yml` |
| high | MSSQL XPCmdshell Option Change | application | `rules/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_change.yml` |
| high | MSSQL XPCmdshell Suspicious Execution | application | `rules/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_audit_log.yml` |
| high | New Firewall Rule Added In Windows Firewall Exception List For Potential Suspicious Application | firewall-as | `rules/windows/builtin/firewall_as/win_firewall_as_add_rule_susp_folder.yml` |
| high | Ngrok Usage with Remote Desktop Service | terminalservices-localsessionmanager | `rules/windows/builtin/terminalservices/win_terminalservices_rdp_ngrok.yml` |
| high | Query Tor Onion Address - DNS Client | dns-client | `rules/windows/builtin/dns_client/win_dns_client_tor_onion.yml` |
| high | Relevant Anti-Virus Signature Keywords In Application Log | application | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` |
| high | Remote AppX Package Downloaded from File Sharing or CDN Domain | appxdeployment-server | `rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_appx_downloaded_from_file_sharing_domains.yml` |
| high | Remove Exported Mailbox from Exchange Webserver | msexchange-management | `rules/windows/builtin/msexchange/win_exchange_proxyshell_remove_mailbox_export.yml` |
| high | Restricted Software Access By SRP | application | `rules/windows/builtin/application/microsoft_windows_software_restriction_policies/win_software_restriction_policies_block.yml` |
| high | Unsigned Binary Loaded From Suspicious Location | security-mitigations | `rules/windows/builtin/security_mitigations/win_security_mitigations_unsigned_dll_from_susp_location.yml` |
