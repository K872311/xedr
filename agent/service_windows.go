//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName = "ForensicAgent"
	serviceDisp = "ForensicAgent"
	serviceDesc = "终端态势采集服务（无界面、无托盘，后台静默运行）"
)

func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type agentService struct {
	cfg     Config
	cfgPath string
}

func (m *agentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmds = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	// 内部自恢复：runAgent 异常退出后自动重跑，避免重启后偶发掉线一直停着
	go func() {
		backoff := 3 * time.Second
		for {
			err := runAgent(ctx, m.cfg, m.cfgPath)
			if ctx.Err() != nil {
				done <- nil
				return
			}
			if err != nil {
				log.Printf("agent 退出将重试: %v（%s）", err, backoff)
			} else {
				log.Printf("agent 正常结束，%s 后重启循环", backoff)
			}
			select {
			case <-ctx.Done():
				done <- nil
				return
			case <-time.After(backoff):
			}
			if backoff < time.Minute {
				backoff *= 2
			}
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmds}
	for {
		select {
		case <-done:
			changes <- svc.Status{State: svc.StopPending}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				if isSelfProtect() && c.Cmd == svc.Stop {
					log.Printf("自保护：忽略 Stop（可用策略关闭 self_protect 或强制结束进程）")
					changes <- svc.Status{State: svc.Running, Accepts: cmds}
					continue
				}
				log.Printf("服务收到停止命令")
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(25 * time.Second):
				}
				return false, 0
			default:
				log.Printf("忽略控制命令: %v", c.Cmd)
			}
		}
	}
}

func runAsService(cfg Config, cfgPath string) error {
	return svc.Run(serviceName, &agentService{cfg: cfg, cfgPath: cfgPath})
}

func installService(cfgPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	if cfgPath == "" {
		cfgPath = filepath.Join(filepath.Dir(exe), "agent.json")
	}
	cfgPath, err = filepath.Abs(cfgPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(cfgPath); err != nil {
		return fmt.Errorf("配置不存在: %s（请先写好 server_url / token）", cfgPath)
	}
	// 预检配置，避免装上服务却因缺 token 起不来
	raw, _ := os.ReadFile(cfgPath)
	var probe struct {
		ServerURL string `json:"server_url"`
		Token     string `json:"token"`
	}
	_ = json.Unmarshal(raw, &probe)
	if strings.TrimSpace(probe.ServerURL) == "" || strings.TrimSpace(probe.Token) == "" {
		return fmt.Errorf("配置缺少 server_url 或 token: %s", cfgPath)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接服务管理器失败（需管理员）: %w", err)
	}
	defer m.Disconnect()

	binPath := `"` + exe + `" -config "` + cfgPath + `"`
	cfg := mgr.Config{
		DisplayName:      serviceDisp,
		Description:      serviceDesc,
		StartType:        mgr.StartAutomatic,
		BinaryPathName:   binPath,
		ServiceStartName: "", // LocalSystem
		ErrorControl:     mgr.ErrorNormal,
		// 依赖网络栈，开机后网络就绪再跑（比 DelayedAutoStart 更稳）
		Dependencies:     []string{"Tcpip", "Dhcp"},
		DelayedAutoStart: false,
	}

	created := false
	s, err := m.OpenService(serviceName)
	if err != nil {
		s, err = m.CreateService(serviceName, exe, cfg, "-config", cfgPath)
		if err != nil {
			return fmt.Errorf("CreateService: %w", err)
		}
		created = true
	}
	defer s.Close()

	// 已存在则更新路径/自启/依赖（升级覆盖）
	if !created {
		if e := s.UpdateConfig(cfg); e != nil {
			log.Printf("UpdateConfig: %v", e)
		}
	}

	// 失败自动拉起：15s / 15s / 30s
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400)
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)

	st, _ := s.Query()
	if st.State == svc.Stopped || st.State == svc.StopPending {
		if err := s.Start(); err != nil {
			return fmt.Errorf("已安装但启动失败: %w", err)
		}
	}
	log.Printf("已安装并确保运行 %s auto-start+recovery exe=%s config=%s", serviceName, exe, cfgPath)
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接服务管理器失败（需管理员）: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("服务不存在: %s", serviceName)
	}
	defer s.Close()

	_, _ = s.Control(svc.Stop)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		st, e := s.Query()
		if e != nil || st.State == svc.Stopped {
			break
		}
		time.Sleep(400 * time.Millisecond)
	}
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Printf("已卸载服务 %s\n", serviceName)
	return nil
}

func startServiceCmd() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return err
	}
	fmt.Println("服务已启动")
	return nil
}

func stopServiceCmd() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}
	fmt.Printf("停止中，当前状态=%v\n", st.State)
	return nil
}

func serviceStatus() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		fmt.Printf("服务未安装\n")
		return nil
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return err
	}
	cfg, err := s.Config()
	state := "unknown"
	switch st.State {
	case svc.Stopped:
		state = "Stopped"
	case svc.StartPending:
		state = "StartPending"
	case svc.StopPending:
		state = "StopPending"
	case svc.Running:
		state = "Running"
	case svc.ContinuePending:
		state = "ContinuePending"
	case svc.PausePending:
		state = "PausePending"
	case svc.Paused:
		state = "Paused"
	}
	fmt.Printf("服务: %s\n显示名: %s\n状态: %s\n路径: %s\n", serviceName, cfg.DisplayName, state, cfg.BinaryPathName)
	return nil
}
