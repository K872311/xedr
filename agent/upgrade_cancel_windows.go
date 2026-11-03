//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func cancelUpgrade(cfg Config, params map[string]any) (map[string]any, error) {
	_ = params
	setUpgradePhase("CANCELLED", "", "cancel_upgrade")
	defer func() {
		time.AfterFunc(3*time.Second, clearUpgradePhase)
	}()
	p := upgradePendingPath(cfg)
	_ = os.Remove(p)
	_ = os.Remove(upgradeHealthyPath(cfg))
	self, err := os.Executable()
	if err != nil {
		return map[string]any{"ok": true, "cancelled": true, "msg": "已清除升级挂起；无法定位 exe"}, nil
	}
	bak := self + ".bak"
	if _, err := os.Stat(bak); err != nil {
		return map[string]any{
			"ok": true, "cancelled": true, "pending_cleared": true,
			"msg": "已取消进行中的升级挂起；无 .bak 可回滚（若已替换需 rollback_upgrade）",
			"hint": "失败时可下发 rollback_upgrade",
		}, nil
	}
	return map[string]any{
		"ok": true, "cancelled": true, "pending_cleared": true, "bak": bak,
		"msg":  "已取消升级挂起；如需回退到上一版本请执行 rollback_upgrade",
		"hint": "rollback_upgrade",
		"self": filepath.Base(self),
	}, nil
}

func cancelUpgradeHint(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("升级失败：%v；可尝试 cancel_upgrade 或 rollback_upgrade", err)
}
