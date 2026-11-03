//go:build windows

package main

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	hostMetricsMu sync.Mutex
	hostMetrics   map[string]any
	hostMetricsAt time.Time
)

// hostMetricsSnapshot Metricbeat 主机指标子集：卷磁盘用量 + 连接表采样（非全量 Beat pipeline 指标）。
func hostMetricsSnapshot() map[string]any {
	hostMetricsMu.Lock()
	defer hostMetricsMu.Unlock()
	if hostMetrics != nil && time.Since(hostMetricsAt) < 45*time.Second {
		out := map[string]any{}
		for k, v := range hostMetrics {
			out[k] = v
		}
		return out
	}
	out := map[string]any{
		"disks":              probeDiskVolumes(),
		"connections_sample": probeConnectionsSample(),
		"net_io":             probeNetIOCounters(),
	}
	hostMetrics, hostMetricsAt = out, time.Now()
	cp := map[string]any{}
	for k, v := range out {
		cp[k] = v
	}
	return cp
}

func probeDiskVolumes() []map[string]any {
	var out []map[string]any
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getDisk := kernel32.NewProc("GetDiskFreeSpaceExW")
	for c := 'A'; c <= 'Z'; c++ {
		root := string(c) + `:\`
		p, _ := windows.UTF16PtrFromString(root)
		var free, total, totFree uint64
		r, _, _ := getDisk.Call(
			uintptr(unsafe.Pointer(p)),
			uintptr(unsafe.Pointer(&free)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&totFree)),
		)
		if r == 0 {
			continue
		}
		usedPct := 0.0
		if total > 0 {
			usedPct = float64(total-free) * 100 / float64(total)
		}
		out = append(out, map[string]any{
			"mount": root, "total_bytes": total, "free_bytes": free,
			"used_pct": round1(usedPct),
		})
	}
	return out
}

func probeConnectionsSample() map[string]any {
	items, err := collectNetwork()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{"count": len(items), "note": "socket_table_not_nic_bytes"}
}

func probeNetIOCounters() map[string]any {
	iphlp := windows.NewLazySystemDLL("iphlpapi.dll")
	getTCP := iphlp.NewProc("GetTcpStatisticsEx")
	type mibTCPStats struct {
		RtoAlgorithm, RtoMin, RtoMax, MaxConn                   uint32
		ActiveOpens, PassiveOpens, AttemptFails, EstabResets        uint32
		CurrEstab, InSegs, OutSegs, RetransSegs                 uint32
		InErrs, OutRsts, NumConns                               uint32
	}
	var st mibTCPStats
	const afInet = 2
	out := map[string]any{"ok": false}
	if r, _, _ := getTCP.Call(uintptr(unsafe.Pointer(&st)), afInet); r == 0 {
		out["ok"] = true
		out["tcp_in_segs"] = st.InSegs
		out["tcp_out_segs"] = st.OutSegs
		out["tcp_retrans"] = st.RetransSegs
		out["tcp_curr_estab"] = st.CurrEstab
	}
	// 网卡字节：GetIfTable 汇总 InOctets/OutOctets（非完整 Metricbeat）
	if bytes := probeIfOctets(iphlp); bytes != nil {
		for k, v := range bytes {
			out[k] = v
		}
	}
	out["note"] = "tcp_stats_ex_ipv4+if_table_octets"
	return out
}

func probeIfOctets(iphlp *windows.LazyDLL) map[string]any {
	getIfTable := iphlp.NewProc("GetIfTable")
	var size uint32
	r, _, _ := getIfTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	// ERROR_INSUFFICIENT_BUFFER = 122
	if size == 0 || (r != 0 && r != 122) {
		return nil
	}
	buf := make([]byte, size)
	r, _, _ = getIfTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 || len(buf) < 4 {
		return nil
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	// MIB_IFROW：wszName[256] WCHAR + 固定 DWORD 字段；InOctets 偏移约 552，行宽 860。
	const (
		mibIfRowSize = 860
		offInOctets  = 552
		offOutOctets = 556
	)
	var inSum, outSum uint64
	var nOK int
	for i := uint32(0); i < num && i < 64; i++ {
		base := 4 + int(i)*mibIfRowSize
		if base+offOutOctets+4 > len(buf) {
			break
		}
		inO := *(*uint32)(unsafe.Pointer(&buf[base+offInOctets]))
		outO := *(*uint32)(unsafe.Pointer(&buf[base+offOutOctets]))
		inSum += uint64(inO)
		outSum += uint64(outO)
		nOK++
	}
	if nOK == 0 {
		return nil
	}
	return map[string]any{
		"nic_in_bytes": inSum, "nic_out_bytes": outSum, "nic_ifaces": nOK,
	}
}
