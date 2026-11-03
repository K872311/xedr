//go:build windows

package main

// winevtChannel：与 PowerShell 订阅脚本一致的通道与 XPath（压噪）。
type winevtChannel struct {
	ID      string
	Channel string
	XPath   string
}

func winevtChannelDefs() []winevtChannel {
	return []winevtChannel{
		{
			ID: "security", Channel: "Security",
			XPath: `*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4688 or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4697 or EventID=4698 or EventID=4702 or EventID=1102)]]`,
		},
		{
			ID: "system", Channel: "System",
			XPath: `*[System[(EventID=7045 or EventID=7036 or EventID=7040)]]`,
		},
		{
			ID: "sysmon", Channel: "Microsoft-Windows-Sysmon/Operational",
			XPath: `*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=7 or EventID=8 or EventID=10 or EventID=11 or EventID=13 or EventID=15 or EventID=17 or EventID=22 or EventID=23 or EventID=25 or EventID=26)]]`,
		},
		{
			ID: "defender", Channel: "Microsoft-Windows-Windows Defender/Operational",
			XPath: `*[System[(EventID=1116 or EventID=1117 or EventID=1150 or EventID=5001)]]`,
		},
		{
			ID: "taskscheduler", Channel: "Microsoft-Windows-TaskScheduler/Operational",
			XPath: `*[System[(EventID=106 or EventID=140 or EventID=141 or EventID=200 or EventID=201)]]`,
		},
		{
			ID: "powershell", Channel: "Microsoft-Windows-PowerShell/Operational",
			XPath: `*[System[(EventID=4103 or EventID=4104)]]`,
		},
		{
			ID: "firewall", Channel: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
			XPath: `*[System[(EventID=2004 or EventID=2005 or EventID=2006 or EventID=2010 or EventID=2011)]]`,
		},
		{
			ID: "codeintegrity", Channel: "Microsoft-Windows-CodeIntegrity/Operational",
			XPath: `*[System[(EventID=3033 or EventID=3063 or EventID=3076 or EventID=3077)]]`,
		},
		{
			ID: "terminalservices", Channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
			XPath: `*[System[(EventID=21 or EventID=22 or EventID=23 or EventID=24 or EventID=25)]]`,
		},
		{
			ID: "smbclient", Channel: "Microsoft-Windows-SmbClient/Security",
			XPath: `*[System[(EventID=31001 or EventID=31002 or EventID=31003 or EventID=31004)]]`,
		},
		{
			ID: "bits", Channel: "Microsoft-Windows-Bits-Client/Operational",
			XPath: `*[System[(EventID=3 or EventID=4 or EventID=59 or EventID=60)]]`,
		},
		{
			ID: "applocker", Channel: "Microsoft-Windows-AppLocker/EXE and DLL",
			XPath: `*[System[(EventID=8001 or EventID=8002 or EventID=8003 or EventID=8004)]]`,
		},
	}
}

// winevtChannelManifest 返回已启用通道 ID（含策略过滤后）。
func winevtChannelManifest() []string {
	defs := winevtChannelDefsFiltered()
	out := make([]string, 0, len(defs))
	for _, d := range defs {
		out = append(out, d.ID)
	}
	return out
}
