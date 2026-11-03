//go:build windows

package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"time"
)

func collectDiagnosticsBundle(cfg Config) (map[string]any, error) {
	pm := globalPolicyManager
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, content string) {
		w, err := zw.Create(name)
		if err != nil {
			return
		}
		_, _ = w.Write([]byte(redactSensitive(content)))
	}
	addBytes := func(name string, raw []byte) {
		w, err := zw.Create(name)
		if err != nil {
			return
		}
		_, _ = w.Write(raw)
	}

	verYAML := fmt.Sprintf(
		"version: %q\ncommit: %q\nbuild_time: %q\nsnapshot: false\n",
		agentVersion, buildID, buildTime,
	)
	add("version.txt", verYAML)
	add("package.version", agentVersion+"\n")

	host := hostMetadata()
	info := map[string]any{
		"agent_id": cfg.AgentID, "hostname": hostname(), "version": agentVersion,
		"build_id": buildID, "build_time": buildTime, "upgradeable": true,
		"host": host, "server_url": cfg.ServerURL,
	}
	ib, _ := json.MarshalIndent(redactMap(info), "", "  ")
	add("agent-info.yaml", string(ib))

	if rawCfg, err := os.ReadFile(filepath.Join(cfg.StateDir, "agent.json")); err == nil {
		add("local-config.yaml", string(rawCfg))
	}
	envLines := []string{}
	for _, e := range os.Environ() {
		if strings.Contains(strings.ToLower(e), "secret") || strings.Contains(strings.ToLower(e), "password") {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				envLines = append(envLines, parts[0]+"=**REDACTED**")
				continue
			}
		}
		envLines = append(envLines, e)
	}
	add("environment.yaml", strings.Join(envLines, "\n")+"\n")

	state := buildStateYAML(pm, cfg)
	add("state.yaml", mapToSimpleYAML(state))

	exp := buildComponentsExpected()
	act := buildComponentsActual()
	eb, _ := json.MarshalIndent(exp, "", "  ")
	ab, _ := json.MarshalIndent(act, "", "  ")
	add("components-expected.yaml", string(eb))
	add("components-actual.yaml", string(ab))

	varsDoc := map[string]any{"host": host, "composable": hostMetadata()}
	vb, _ := json.MarshalIndent(varsDoc, "", "  ")
	add("variables.yaml", string(vb))

	if pm != nil {
		pol := map[string]any{"policy_state": pm.state(), "integrations": integrationsSnapshot()}
		pb, _ := json.MarshalIndent(redactMap(pol), "", "  ")
		add("computed-config.yaml", string(pb))
	}

	if st := captureStatusSnapshot(); st != nil {
		b, _ := json.MarshalIndent(st, "", "  ")
		add("capture_status.json", string(b))
	}

	logPath := filepath.Join(cfg.StateDir, "agent.log")
	if tail, err := tailFile(logPath, 512*1024); err == nil && tail != "" {
		add("logs/forensic-agent/agent.log.tail", tail)
	}

	var heapBuf bytes.Buffer
	gzW := gzip.NewWriter(&heapBuf)
	_ = pprof.WriteHeapProfile(gzW)
	_ = gzW.Close()
	addBytes("heap.pprof.gz", heapBuf.Bytes())

	var gorBuf bytes.Buffer
	gzG := gzip.NewWriter(&gorBuf)
	_ = pprof.Lookup("goroutine").WriteTo(gzG, 0)
	_ = gzG.Close()
	addBytes("goroutine.pprof.gz", gorBuf.Bytes())

	_ = zw.Close()
	raw := buf.Bytes()
	if len(raw) > 8*1024*1024 {
		raw = raw[:8*1024*1024]
	}
	return map[string]any{
		"ok":             true,
		"filename":       fmt.Sprintf("forensic-agent-diag-%s.zip", time.Now().Format("20060102-150405")),
		"size":           len(raw),
		"content_base64": base64.StdEncoding.EncodeToString(raw),
	}, nil
}

func tailFile(path string, max int) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	start := int64(0)
	if fi.Size() > int64(max) {
		start = fi.Size() - int64(max)
	}
	_, _ = f.Seek(start, 0)
	buf := make([]byte, fi.Size()-start)
	n, _ := f.Read(buf)
	return string(buf[:n]), nil
}

func integrationsSnapshot() map[string]bool {
	intMu.RLock()
	defer intMu.RUnlock()
	out := map[string]bool{}
	for k, v := range integrations {
		out[k] = v
	}
	return out
}
