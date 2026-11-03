// Windows Event Detection Rules
// Auto-generated from Hayabusa Sigma rules
// Focus: Compromise Detection (失陷检测)

package detection

// Severity levels
type Severity string
const (
    SeverityCritical Severity = "critical"    // 严重
    SeverityHigh     Severity = "high"        // 高
    SeverityMedium   Severity = "medium"      // 中
    SeverityLow      Severity = "low"         // 低
    SeverityInfo     Severity = "informational" // 信息
)

// DetectionOperator defines how to compare field values
type DetectionOperator string
const (
    OpEq        DetectionOperator = "eq"        // 等于
    OpContains  DetectionOperator = "contains"  // 包含
    OpStartsWith DetectionOperator = "startswith" // 以...开始
    OpEndsWith  DetectionOperator = "endswith"  // 以...结束
    OpRegex     DetectionOperator = "re"        // 正则匹配
    OpIn        DetectionOperator = "in"        // 在列表中
    OpGt        DetectionOperator = "gt"        // 大于
    OpFieldRef  DetectionOperator = "fieldref"  // 字段引用
)

// DetectionCriterion is a single detection condition
type DetectionCriterion struct {
    Field    string            // Field name to check
    Operator DetectionOperator // Comparison operator
    Value    interface{}       // Value to compare against
}

// DetectionRule defines a Windows event detection rule
type DetectionRule struct {
    ID                  string               // Rule UUID
    Filename            string               // Source YAML filename
    TitleEN             string               // English title
    TitleCN             string               // Chinese title (翻译)
    DescriptionEN       string               // English description
    DescriptionCN       string               // Chinese description (翻译)
    EventIDs            []string             // Windows Event IDs
    Channel             string               // Event log channel
    Severity            Severity             // Severity level
    SeverityCN          string               // Chinese severity (严重/高/中/低/信息)
    IsCompromiseDetection bool               // Critical for compromise detection
    MITRETactics        []string             // MITRE ATT&CK tactics
    MITRETechniques     []string             // MITRE ATT&CK techniques
    DetectionCriteria   []DetectionCriterion // Detection conditions
    ConditionExpr       string               // Boolean expression (e.g., "selection AND NOT filter")
    FalsePositives      []string             // Known false positives
    References          []string             // References
    Status              string               // Rule status (stable/test/experimental)
    Category            string               // Event category
    Author              string               // Rule author
}

// EventIDToRules maps Event IDs to their detection rules
var EventIDToRules = map[string][]DetectionRule{
	"4": {
		{
			ID: "af127790-5563-473e-8d3a-43b3509572b1",
			TitleEN: "NTFS volume mounted",
			TitleCN: "NTFS volume mounted",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"6": {
		{
			ID: "4f321a68-176a-4f1d-873a-8793bc49e3b0",
			TitleEN: "Win RM Session Created",
			TitleCN: "Win RM Session Created",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"12": {
		{
			ID: "a225cc36-bfdc-4e7a-ad01-f544b90e2d2a",
			TitleEN: "Computer Startup",
			TitleCN: "Computer Startup",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "8da41a05-364b-4e3c-95d9-397abb82eac4",
			TitleEN: "Computer Startup In Safe Mode",
			TitleCN: "Computer Startup In Safe Mode",
			Severity: "medium",
			IsCompromiseDetection: false,
		},
		{
			ID: "f9915ff9-17ce-4524-9851-cc4bdd9bb35e",
			TitleEN: "ISO Mounted",
			TitleCN: "ISO Mounted",
			Severity: "low",
			IsCompromiseDetection: false,
		},
		{
			ID: "d00c370c-c6c2-474f-9d41-a250644852b5",
			TitleEN: "VHD Mounted",
			TitleCN: "VHD Mounted",
			Severity: "low",
			IsCompromiseDetection: false,
		},
		{
			ID: "2c544083-e209-4a8d-ad28-4f1427353d2e",
			TitleEN: "VHDX Mounted",
			TitleCN: "VHDX Mounted",
			Severity: "low",
			IsCompromiseDetection: false,
		},
	},
	"21": {
		{
			ID: "b107551c-409d-44b8-bb0d-3b007c269881",
			TitleEN: "RDP Logon",
			TitleCN: "RDP登录",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"22": {
		{
			ID: "320e2cb0-a56a-476f-a299-79dc45644fee",
			TitleEN: "RDP Sess Start (Noisy)",
			TitleCN: "RDP Sess Start (Noisy)",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"23": {
		{
			ID: "e14a729f-f4f8-427b-a238-dfbde9c1614b",
			TitleEN: "RDP Logoff",
			TitleCN: "RDP注销",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"24": {
		{
			ID: "3fc6234f-93a5-4d48-b618-30e2c69c0a86",
			TitleEN: "RDP Disconnect",
			TitleCN: "RDP断开连接",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"25": {
		{
			ID: "8fe4a60b-2af3-43d6-95e2-8f13caccc179",
			TitleEN: "RDP Reconnect",
			TitleCN: "RDP Reconnect",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"59": {
		{
			ID: "18e6fa4a-353d-42b6-975c-bb05dbf4a004",
			TitleEN: "Bits Job Created",
			TitleCN: "Bits Job Created",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"104": {
		{
			ID: "f481a1f3-969e-4187-b3a5-b47c272bfebd",
			TitleEN: "Important Log File Cleared",
			TitleCN: "重要日志文件被清除",
			Severity: "high",
			IsCompromiseDetection: true,
		},
		{
			ID: "ed90ed4f-0d93-4f1a-99a2-4b9003b750a7",
			TitleEN: "Log File Cleared",
			TitleCN: "Log File Cleared",
			Severity: "medium",
			IsCompromiseDetection: false,
		},
	},
	"106": {
		{
			ID: "33599dfb-f3e4-4298-8d3f-59407f65f4e7",
			TitleEN: "Task Created",
			TitleCN: "计划任务创建",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"140": {
		{
			ID: "aba04101-e439-4e2f-b051-4be561993c31",
			TitleEN: "Task Updated",
			TitleCN: "Task Updated",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"141": {
		{
			ID: "ff6ada24-c7f0-4ae5-a7a6-f20ddb7b591f",
			TitleEN: "Task Deleted",
			TitleCN: "计划任务删除",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"200": {
		{
			ID: "d1923809-955b-47c4-b3e5-37c0e461919c",
			TitleEN: "Task Executed",
			TitleCN: "Task Executed",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"260": {
		{
			ID: "cd6eb342-9dcd-450d-b448-bebd97cb6e89",
			TitleEN: "Recursive DNS Request",
			TitleCN: "Recursive DNS Request",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"261": {
		{
			ID: "6db38b96-3772-4cbf-a8ad-c65d8ac5134e",
			TitleEN: "Recursive DNS Response",
			TitleCN: "Recursive DNS Response",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "6dbed1df-f08a-47ab-9a58-999c0787d034",
			TitleEN: "RDP Conn (Noisy)",
			TitleCN: "RDP Conn (Noisy)",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"300": {
		{
			ID: "8cab5688-ca77-483d-a295-56dd6c1db944",
			TitleEN: "Office App PopUp",
			TitleCN: "Office App PopUp",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"302": {
		{
			ID: "27648a93-cfc0-4903-beb2-9395e784a484",
			TitleEN: "RDS GTW Logon",
			TitleCN: "RDS GTW Logon",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "24a04758-729d-4c43-9bd5-cccd31db80d0",
			TitleEN: "RDS GTW Logon Error",
			TitleCN: "RDS GTW Logon Error",
			Severity: "low",
			IsCompromiseDetection: false,
		},
	},
	"303": {
		{
			ID: "e5f74909-58a9-45ec-b70d-21c654dca4f3",
			TitleEN: "RDS GTW Logoff",
			TitleCN: "RDS GTW Logoff",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"400": {
		{
			ID: "ac2ae63b-83e6-4d06-aeaf-07409bda92c9",
			TitleEN: "PwSh Engine Started",
			TitleCN: "PwSh Engine Started",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "bc082394-73e6-4d00-a9af-e7b524ef5085",
			TitleEN: "PwSh 2.0 Downgrade Attack",
			TitleCN: "PwSh 2.0 Downgrade Attack",
			Severity: "medium",
			IsCompromiseDetection: false,
		},
	},
	"1001": {
		{
			ID: "082fbbf5-bb05-468c-ad9c-ef2a383bb293",
			TitleEN: "BSOD",
			TitleCN: "系统蓝屏",
			Severity: "medium",
			IsCompromiseDetection: false,
		},
	},
	"1006": {
		{
			ID: "a6a0d64-75d1-433a-b415-4123bab080ec",
			TitleEN: "Device Conn",
			TitleCN: "Device Conn",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"1022": {
		{
			ID: "ef118d4d-ef83-40a7-bb27-2bb3945473ee",
			TitleEN: "MSI Install",
			TitleCN: "MSI Install",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"1024": {
		{
			ID: "512e70f5-bf70-4de1-9375-2174999a7f8d",
			TitleEN: "RDP Conn Attempt",
			TitleCN: "RDP Conn Attempt",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"1033": {
		{
			ID: "ef118d4d-ef83-40a7-bb27-2bb3945473ee",
			TitleEN: "MSI Install",
			TitleCN: "MSI Install",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"1102": {
		{
			ID: "1a850b71-6aef-4f31-a509-f31b2c778476",
			TitleEN: "RDP Attempt",
			TitleCN: "RDP Attempt",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "c2f690ac-53f8-4745-8cfe-7127dda28c74",
			TitleEN: "Log Cleared",
			TitleCN: "日志被清除",
			Severity: "high",
			IsCompromiseDetection: true,
		},
	},
	"1116": {
		{
			ID: "810bfd3a-9fb3-44e0-9016-8cdf785fddbf",
			TitleEN: "Defender Alert (Severe)",
			TitleCN: "Defender Alert (Severe)",
			Severity: "critical",
			IsCompromiseDetection: true,
		},
		{
			ID: "1e11c0f0-aecd-45d8-9229-da679c0265ea",
			TitleEN: "Defender Alert (High)",
			TitleCN: "Defender Alert (High)",
			Severity: "high",
			IsCompromiseDetection: true,
		},
		{
			ID: "61056ed8-7be5-46e4-9015-c5f6bc8b93a1",
			TitleEN: "Defender Alert (Low)",
			TitleCN: "Defender Alert (Low)",
			Severity: "low",
			IsCompromiseDetection: false,
		},
		{
			ID: "3f5005fc-e354-4b0b-b1a1-3eec1d336023",
			TitleEN: "Defender Alert (Moderate)",
			TitleCN: "Defender Alert (Moderate)",
			Severity: "medium",
			IsCompromiseDetection: false,
		},
	},
	"1149": {
		{
			ID: "e91c514e-08c5-4c42-96d7-ab1f5668a2f7",
			TitleEN: "RDP Logon",
			TitleCN: "RDP登录",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"2003": {
		{
			ID: "b39b18a5-cece-4e7d-a438-827d0b0e8a82",
			TitleEN: "USB Plugged In",
			TitleCN: "USB Plugged In",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4103": {
		{
			ID: "d3fb8f7b-88b0-4ff4-bf9b-ca286ce19031",
			TitleEN: "PwSh Pipeline Exec",
			TitleCN: "PwSh Pipeline Exec",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4104": {
		{
			ID: "0f3b1343-65a5-4879-b512-9d61b0e4e3ba",
			TitleEN: "PwSh Scriptblock",
			TitleCN: "PwSh Scriptblock",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "73be1519-4648-4ed7-b305-605504afc242",
			TitleEN: "Potentially Malicious PwSh",
			TitleCN: "潜在恶意PowerShell",
			Severity: "medium",
			IsCompromiseDetection: true,
		},
	},
	"4611": {
		{
			ID: "41ca6049-dd12-462c-a772-7bba78d8e2f0",
			TitleEN: "Abnormal Logon Proc Registered With LSA",
			TitleCN: "Abnormal Logon Proc Registered With LSA",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "614c150b-905d-4071-9b8e-0425e370c493",
			TitleEN: "Logon Proc Registered With LSA",
			TitleCN: "Logon Proc Registered With LSA",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4624": {
		{
			ID: "9fa273cc-bcb2-4789-85e3-14ca253ac7f4",
			TitleEN: "Logon (System) - Bootup",
			TitleCN: "Logon (System) - Bootup",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "a4e05f05-ff88-48b9-8524-a88c1c32fe19",
			TitleEN: "Logon (RemoteInteractive (RDP)) *Creds in memory*",
			TitleCN: "Logon (RemoteInteractive (RDP)) *Creds in memory*",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "fbbe9d3f-ed1f-49a9-9446-726e349f5fba",
			TitleEN: "Logon (CachedInteractive) *Creds in memory*",
			TitleCN: "Logon (CachedInteractive) *Creds in memory*",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "f4b46dd3-63d6-4c75-a54c-9f6bd095cd6f",
			TitleEN: "Logon (CachedRemoteInteractive) *Creds in memory*",
			TitleCN: "Logon (CachedRemoteInteractive) *Creds in memory*",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "e50e3952-06d9-44a8-ab07-7a41c9801d78",
			TitleEN: "Logon (CachedUnlock) *Creds in memory*",
			TitleCN: "Logon (CachedUnlock) *Creds in memory*",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4625": {
		{
			ID: "8afa97ce-a217-4f7c-aced-3e320a57756d",
			TitleEN: "Logon Failure (User Does Not Exist)",
			TitleCN: "Logon Failure (User Does Not Exist)",
			Severity: "low",
			IsCompromiseDetection: false,
		},
		{
			ID: "a85096da-be85-48d7-8ad5-2f957cd74daa",
			TitleEN: "Logon Failure (Unknown Reason)",
			TitleCN: "Logon Failure (Unknown Reason)",
			Severity: "low",
			IsCompromiseDetection: false,
		},
		{
			ID: "e87bd730-df45-4ae9-85de-6c75369c5d29",
			TitleEN: "Logon Failure (Wrong Password)",
			TitleCN: "Logon Failure (Wrong Password)",
			Severity: "low",
			IsCompromiseDetection: false,
		},
		{
			ID: "4574194d-e7ca-4356-a95c-21b753a1787e",
			TitleEN: "User Guessing",
			TitleCN: "用户名猜测攻击",
			Severity: "medium",
			IsCompromiseDetection: true,
		},
		{
			ID: "b2c74582-0d44-49fe-8faa-014dcdafee62",
			TitleEN: "Failed Logon - Non-Existent User",
			TitleCN: "登录失败",
			Severity: "medium",
			IsCompromiseDetection: true,
		},
	},
	"4634": {
		{
			ID: "7309e070-56b9-408b-a2f4-f1840f8f1ebf",
			TitleEN: "Logoff",
			TitleCN: "Logoff",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "84288799-8b61-4d98-bad0-4043c40cf992",
			TitleEN: "Logoff (Noisy)",
			TitleCN: "Logoff (Noisy)",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4647": {
		{
			ID: "6bad16f1-02c4-4075-b414-3cd16944bc65",
			TitleEN: "Logoff (User Initiated)",
			TitleCN: "Logoff (User Initiated)",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4648": {
		{
			ID: "8c1899fe-493d-4faf-aae1-0853a33a3278",
			TitleEN: "Explicit Logon Attempt",
			TitleCN: "显式登录尝试",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "a5b3ebf0-141a-4264-b2ff-400c0d515fca",
			TitleEN: "Explicit Logon Attempt (Noisy)",
			TitleCN: "显式登录尝试",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "ffd622af-d049-449f-af5a-0492fdcc3a58",
			TitleEN: "PW Spray",
			TitleCN: "密码喷射攻击",
			Severity: "medium",
			IsCompromiseDetection: true,
		},
		{
			ID: "ab1accc0-b6e2-4841-8dfb-5902581392c3",
			TitleEN: "Failed Logon - Incorrect Password",
			TitleCN: "登录失败",
			Severity: "medium",
			IsCompromiseDetection: true,
		},
		{
			ID: "7616e857-8e41-4976-bc21-811d122b9fc9",
			TitleEN: "Explicit Logon Attempt (Susp Proc) - Possible Mimikatz PrivEsc",
			TitleCN: "显式登录尝试",
			Severity: "high",
			IsCompromiseDetection: true,
		},
	},
	"4672": {
		{
			ID: "fdd0b325-8b89-469c-8b0c-e5ddfe39b62e",
			TitleEN: "Admin Logon",
			TitleCN: "Admin Logon",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4673": {
		{
			ID: "5b6e58ee-c231-4a54-9eee-af2577802e08",
			TitleEN: "Process Ran With High Privilege",
			TitleCN: "Process Ran With High Privilege",
			Severity: "medium",
			IsCompromiseDetection: false,
		},
	},
	"4674": {
		{
			ID: "15db3cc7-30bd-47a0-bd75-66208ce8e3fe",
			TitleEN: "Possible Hidden Service Created",
			TitleCN: "Possible Hidden Service Created",
			Severity: "medium",
			IsCompromiseDetection: false,
		},
	},
	"4688": {
		{
			ID: "ac933178-c222-430d-8dcf-17b4f3a2fed8",
			TitleEN: "Proc Exec",
			TitleCN: "Proc Exec",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "6c34b782-a5b5-4298-80f3-1918caf1f558",
			TitleEN: "Possible LOLBIN",
			TitleCN: "可能的LOLBIN滥用",
			Severity: "low",
			IsCompromiseDetection: false,
		},
		{
			ID: "75744b7f-7e4a-47fe-afbe-1ee74ec2448e",
			TitleEN: "Susp CmdLine (Possible Meterpreter getsystem)",
			TitleCN: "Susp CmdLine (Possible Meterpreter getsystem)",
			Severity: "medium",
			IsCompromiseDetection: true,
		},
		{
			ID: "6be7f3fc-8917-11ec-a8a3-0242ac120002",
			TitleEN: "Possible RDP Hijacking",
			TitleCN: "可能的RDP劫持",
			Severity: "medium",
			IsCompromiseDetection: true,
		},
	},
	"4697": {
		{
			ID: "95fe88c9-5b9d-4454-97b4-957918b84208",
			TitleEN: "Svc Installed",
			TitleCN: "服务安装",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4698": {
		{
			ID: "60d768ca-33e8-4f34-b967-14fd7aa18a22",
			TitleEN: "Task Created",
			TitleCN: "计划任务创建",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4699": {
		{
			ID: "de5ed02e-e7b5-47a0-a35c-06a907c988e4",
			TitleEN: "Task Deleted",
			TitleCN: "计划任务删除",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4720": {
		{
			ID: "70b8b1bd-c107-4b1a-8b1e-5b0f9f57930a",
			TitleEN: "Hidden User Account Created",
			TitleCN: "隐藏用户账户创建",
			Severity: "high",
			IsCompromiseDetection: true,
		},
		{
			ID: "13edce80-2b02-4469-8de4-a3e37271dcdb",
			TitleEN: "Local User Account Created",
			TitleCN: "Local User Account Created",
			Severity: "low",
			IsCompromiseDetection: false,
		},
	},
	"4723": {
		{
			ID: "3b3046f3-a51c-4378-b059-c716aaa865b4",
			TitleEN: "User Password Changed",
			TitleCN: "User Password Changed",
			Severity: "medium",
			IsCompromiseDetection: false,
		},
	},
	"4724": {
		{
			ID: "0b78aca4-35f0-4bec-acce-c5743ff26614",
			TitleEN: "Password Reset By Admin",
			TitleCN: "Password Reset By Admin",
			Severity: "medium",
			IsCompromiseDetection: true,
		},
	},
	"4728": {
		{
			ID: "4bb89c86-a138-42a0-baaf-fc2f777a4506",
			TitleEN: "User Added To Global Domain Admins Grp",
			TitleCN: "用户添加到全局域管理员组",
			Severity: "high",
			IsCompromiseDetection: true,
		},
		{
			ID: "2f04e44e-1c79-4343-b4ab-ba670ee10aa0",
			TitleEN: "User Added To Non-Admin Global Grp",
			TitleCN: "User Added To Non-Admin Global Grp",
			Severity: "low",
			IsCompromiseDetection: false,
		},
		{
			ID: "0db443ba-561c-4a04-b349-d74ce1c5fc8b",
			TitleEN: "User Added To Global Security Grp",
			TitleCN: "User Added To Global Security Grp",
			Severity: "medium",
			IsCompromiseDetection: true,
		},
	},
	"4732": {
		{
			ID: "611e2e76-a28f-4255-812c-eb8836b2f5bb",
			TitleEN: "User Added To Local Admin Grp",
			TitleCN: "用户添加到本地管理员组",
			Severity: "high",
			IsCompromiseDetection: true,
		},
		{
			ID: "bc58e432-959f-464d-812e-d60ce5d46fa1",
			TitleEN: "User Added To Local Domain Admins Grp",
			TitleCN: "用户添加到本地域管理员组",
			Severity: "high",
			IsCompromiseDetection: true,
		},
	},
	"4741": {
		{
			ID: "42a0a842-2b82-4b2d-8e44-5580fb6c38db",
			TitleEN: "Computer Account Created",
			TitleCN: "Computer Account Created",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4768": {
		{
			ID: "d9f336ea-bb16-4a35-8a9c-183216b8d59c",
			TitleEN: "Kerberos TGT Requested",
			TitleCN: "Kerberos TGT Requested",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "dee2a01e-5d7c-45b4-aec3-ad9722f2165a",
			TitleEN: "Possible AS-REP Roasting (RC4 Kerberos Ticket Req)",
			TitleCN: "可能的AS-REP Roasting攻击",
			Severity: "medium",
			IsCompromiseDetection: false,
		},
	},
	"4769": {
		{
			ID: "da6257f3-cf49-464a-96fc-c84a7ce20636",
			TitleEN: "Kerberos Service Ticket Requested",
			TitleCN: "Kerberos Service Ticket Requested",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "f19849e7-b5ba-404b-a731-9b624d7f6d19",
			TitleEN: "Possible Kerberoasting (RC4 Kerberos Ticket Req)",
			TitleCN: "可能的Kerberoasting攻击",
			Severity: "medium",
			IsCompromiseDetection: false,
		},
	},
	"4776": {
		{
			ID: "4fbe94b0-577a-4f77-9b13-250e27d440fa",
			TitleEN: "NTLM Auth",
			TitleCN: "NTLM Auth",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4778": {
		{
			ID: "db23f704-61c8-4c95-a5b7-4db61c89f41d",
			TitleEN: "RDP Session Reconnect",
			TitleCN: "RDP Session Reconnect",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4779": {
		{
			ID: "f3532729-5536-42b4-ad74-d061b61a3891",
			TitleEN: "RDP Session Disconnect",
			TitleCN: "RDP Session Disconnect",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"4825": {
		{
			ID: "f97a152e-753c-4975-9375-19087fb66f8c",
			TitleEN: "RDP Denied",
			TitleCN: "RDP Denied",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"5038": {
		{
			ID: "0c871345-668e-4b71-bdad-61e42ecc31e3",
			TitleEN: "Code Integrity Error (Invalid Image Hash)",
			TitleCN: "Code Integrity Error (Invalid Image Hash)",
			Severity: "low",
			IsCompromiseDetection: false,
		},
	},
	"5136": {
		{
			ID: "22ee9fb7-64ca-4eed-92de-d1dbef1170b8",
			TitleEN: "Dir Svc Obj Modified",
			TitleCN: "Dir Svc Obj Modified",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"5140": {
		{
			ID: "15d042c1-07c6-4e16-ae7d-e0e556ccd9a8",
			TitleEN: "NetShare Access",
			TitleCN: "NetShare Access",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"5145": {
		{
			ID: "8c6ec2b2-8dad-4996-9aba-d659afc1b919",
			TitleEN: "NetShare File Access",
			TitleCN: "NetShare File Access",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"5156": {
		{
			ID: "d0a61a11-57c9-4afc-b940-3f19b60db08e",
			TitleEN: "Net Conn",
			TitleCN: "Net Conn",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"5157": {
		{
			ID: "b793a8e6-28a4-4fb8-816e-17a99e4e7b40",
			TitleEN: "Net Conn Blocked",
			TitleCN: "Net Conn Blocked",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"5379": {
		{
			ID: "d478c070-8f84-4e65-9f45-cc432a000e93",
			TitleEN: "Credential Manager Accessed",
			TitleCN: "Credential Manager Accessed",
			Severity: "low",
			IsCompromiseDetection: false,
		},
		{
			ID: "d8e3afc5-fa0a-4063-a4af-55e014eb1936",
			TitleEN: "Credential Manager Enumerated",
			TitleCN: "Credential Manager Enumerated",
			Severity: "low",
			IsCompromiseDetection: false,
		},
	},
	"5857": {
		{
			ID: "547aec97-2635-474a-a36c-7a3a46b07fde",
			TitleEN: "WMI Provider Started",
			TitleCN: "WMI Provider Started",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"5860": {
		{
			ID: "d96164c4-9e15-4d48-964f-153ac0dab6e9",
			TitleEN: "Temporary WMI Event Consumer",
			TitleCN: "Temporary WMI Event Consumer",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"5861": {
		{
			ID: "ac9f0a2a-e9c5-4d19-b69e-e3d518ca6797",
			TitleEN: "Permanent WMI Event Consumer",
			TitleCN: "Permanent WMI Event Consumer",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "ab4852ca-3e27-4dbb-af6b-5f8458d5717a",
			TitleEN: "WMI Filter To Consumer Binding_Command Execution",
			TitleCN: "WMI过滤器到消费者绑定",
			Severity: "medium",
			IsCompromiseDetection: true,
		},
	},
	"6005": {
		{
			ID: "11dc7d25-01c9-4b07-9d91-8e07b60d8fd3",
			TitleEN: "Event Log Svc Started",
			TitleCN: "Event Log Svc Started",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"6006": {
		{
			ID: "b6d53116-36b2-4413-a99b-e6708f9c3027",
			TitleEN: "Event Log Svc Stopped",
			TitleCN: "Event Log Svc Stopped",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"6008": {
		{
			ID: "517c0b15-d2bf-48a3-926c-f7b4a96dcec3",
			TitleEN: "Unexpected Shutdown",
			TitleCN: "Unexpected Shutdown",
			Severity: "low",
			IsCompromiseDetection: false,
		},
	},
	"6009": {
		{
			ID: "b27292f1a-18b3-4433-b340-151874a7d4e8",
			TitleEN: "Computer Startup",
			TitleCN: "Computer Startup",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"6013": {
		{
			ID: "982fdd1f-38fe-4243-bea3-6032fc01b723",
			TitleEN: "Computer Uptime/Timezone",
			TitleCN: "Computer Uptime/Timezone",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"6281": {
		{
			ID: "d4757f63-cc0e-448e-8b5b-6cb02aeb918a",
			TitleEN: "Code Integrity Error (Invalid Image Page Hash)",
			TitleCN: "Code Integrity Error (Invalid Image Page Hash)",
			Severity: "low",
			IsCompromiseDetection: false,
		},
	},
	"6410": {
		{
			ID: "c2eb9d20-ef9d-4b2d-bffe-d0a5d9616f30",
			TitleEN: "Code Integrity Proble (Possible Modification)",
			TitleCN: "Code Integrity Proble (Possible Modification)",
			Severity: "low",
			IsCompromiseDetection: false,
		},
	},
	"7031": {
		{
			ID: "d869bf31-92b3-4e21-a447-708f10156e7c",
			TitleEN: "Service Crashed",
			TitleCN: "Service Crashed",
			Severity: "low",
			IsCompromiseDetection: false,
		},
	},
	"7034": {
		{
			ID: "f5dc6a6d-fdf1-441a-a10c-aa10e2908aa4",
			TitleEN: "Service Crashed",
			TitleCN: "Service Crashed",
			Severity: "low",
			IsCompromiseDetection: false,
		},
	},
	"7040": {
		{
			ID: "ab3507cf-5231-4af6-ab1d-5d3b3ad467b5",
			TitleEN: "Event Log Service Startup Type Changed To Disabled",
			TitleCN: "Event Log Service Startup Type Changed To Disabled",
			Severity: "medium",
			IsCompromiseDetection: false,
		},
	},
	"7045": {
		{
			ID: "cc429813-21db-4019-b520-2f19648e1ef1",
			TitleEN: "Suspicious Service Name",
			TitleCN: "可疑服务名称",
			Severity: "high",
			IsCompromiseDetection: true,
		},
		{
			ID: "dbbfd9f3-9508-478b-887e-03ddb9236909",
			TitleEN: "Suspicious Service Path",
			TitleCN: "可疑服务路径",
			Severity: "high",
			IsCompromiseDetection: true,
		},
		{
			ID: "64c5d39d-10a7-44f4-b5d6-fd0d93d0a69f",
			TitleEN: "Svc Installed",
			TitleCN: "服务安装",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "0694c340-3a46-40ac-acfc-c3444ae6572c",
			TitleEN: "PSExec Lateral Movement",
			TitleCN: "PSExec Lateral Movement",
			Severity: "high",
			IsCompromiseDetection: true,
		},
		{
			ID: "76355548-fa5a-4310-9610-0de4b11f4688",
			TitleEN: "Possible Metasploit Svc Installed",
			TitleCN: "服务安装",
			Severity: "medium",
			IsCompromiseDetection: true,
		},
	},
	"8001": {
		{
			ID: "90dd0797-f481-453d-a97e-dd78436893f9",
			TitleEN: "Wifi AP Conn",
			TitleCN: "Wifi AP Conn",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"16385": {
		{
			ID: "420d5d28-78ed-4e43-844a-94ce69db378c",
			TitleEN: "CryptoDPAPI Decrypt",
			TitleCN: "CryptoDPAPI Decrypt",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
	"20001": {
		{
			ID: "9eaea7e6-6567-4ad0-bcc9-fe568dd27909",
			TitleEN: "New Non-USB PnP Device",
			TitleCN: "New Non-USB PnP Device",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
		{
			ID: "f5c0b936-bec8-418a-a79a-89833468fea2",
			TitleEN: "New USB PnP Device",
			TitleCN: "New USB PnP Device",
			Severity: "informational",
			IsCompromiseDetection: false,
		},
	},
}
