package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// 被 SCM 拉起时直接进服务主循环（配置来自安装时写入的 -config）
	if isWindowsService() {
		closeBoot := setupBootLogger()
		defer closeBoot()
		log.Printf("service start exe=%s cwd=%s args=%v", exeDir(), mustGetwd(), os.Args)
		cfg, cfgPath, err := loadConfig(true)
		if err != nil {
			alt := filepath.Join(exeDir(), "agent.json")
			log.Printf("service config primary fail: %v；尝试 %s", err, alt)
			c2, e2 := loadConfigFile(alt)
			if e2 != nil {
				msg := "service config fatal: " + err.Error() + " / " + e2.Error()
				log.Print(msg)
				noteAgentError(msg)
				os.Exit(1)
			}
			cfg, cfgPath = c2, alt
		}
		setupFileLog(cfg.StateDir)
		log.Printf("service config ok path=%s server=%s", cfgPath, cfg.ServerURL)
		if err := runAsService(cfg, cfgPath); err != nil {
			log.Printf("service fatal: %v", err)
			noteAgentError("service fatal: " + err.Error())
			os.Exit(1)
		}
		return
	}

	cmd, err := peelCommand()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	switch cmd {
	case "help", "-h", "--help":
		printUsage()
		return
	case "uninstall":
		if err := uninstallService(); err != nil {
			fatal(err)
		}
		return
	case "start":
		if err := startServiceCmd(); err != nil {
			fatal(err)
		}
		return
	case "stop":
		if err := stopServiceCmd(); err != nil {
			fatal(err)
		}
		return
	case "status":
		if err := serviceStatus(); err != nil {
			fatal(err)
		}
		return
	case "write-example":
		writeExampleConfig("agent.example.json")
		return
	case "build-info", "version":
		out := ""
		if len(os.Args) > 1 {
			out = os.Args[1]
		}
		if err := printBuildInfo(out); err != nil {
			fatal(err)
		}
		return
	}

	needConfig := cmd == "install" || cmd == "run" || cmd == "once" || cmd == ""
	if !needConfig {
		printUsage()
		os.Exit(2)
	}

	cfg, cfgPath, err := loadConfig(false)
	if err != nil {
		noteAgentError("config: " + err.Error())
		fmt.Fprintln(os.Stderr, err)
		printUsage()
		os.Exit(2)
	}
	if cmd == "once" {
		cfg.Once = true
	}

	switch cmd {
	case "install":
		setupFileLog(cfg.StateDir)
		if err := installService(cfgPath); err != nil {
			log.Printf("install failed: %v", err)
			fatal(err)
		}
		return
	case "run", "once", "":
		setupFileLog(cfg.StateDir)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sig
			log.Println("收到退出信号")
			cancel()
		}()
		if err := runAgent(ctx, cfg, cfgPath); err != nil {
			fatal(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n", cmd)
		printUsage()
		os.Exit(2)
	}
}

func peelCommand() (string, error) {
	args := os.Args[1:]
	if len(args) == 0 {
		return "run", nil
	}
	a0 := args[0]
	if strings.HasPrefix(a0, "-") {
		// 兼容旧用法: -once / -write-example
		return "run", nil
	}
	cmd := strings.ToLower(strings.TrimSpace(a0))
	os.Args = append([]string{os.Args[0]}, args[1:]...)
	return cmd, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func printUsage() {
	exe := "forensic-agent.exe"
	if p, err := os.Executable(); err == nil {
		exe = filepath.Base(p)
	}
	fmt.Printf(`%s — 终端实时 Agent（安装为 Windows 服务后常驻回传）

命令（管理员）:
  install   [-config agent.json]   安装并启动 Windows 服务 ForensicAgent
  uninstall                        停止并卸载服务
  start | stop | status            控制服务

前台调试:
  run       [-config agent.json]   控制台运行（不装服务）
  once      [-config agent.json]   只采集上报一轮

其它:
  write-example                    写出 agent.example.json

配置 agent.json 必填:
  server_url   EDR 后台地址，如 http://10.0.0.8:8100
  token        平台登录 Bearer Token

示例:
  %s write-example
  :: 编辑 agent.json 填入 server_url / token
  %s install -config agent.json
  %s status
`, exe, exe, exe, exe)
}

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		p, _ = os.Executable()
	}
	return filepath.Dir(p)
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "?"
	}
	return wd
}
