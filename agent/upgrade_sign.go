package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// 由 scripts/build_agent.py -ldflags -X 注入服务端升级公钥（raw 32 字节的 base64）。
// 为空时：若指令未带签名则仅校验 sha256（兼容旧包）；若带了签名则仍尝试验证（需 params 或配置提供公钥）。
var upgradePubKeyB64 = ""

// upgradeSignMessage 与后端 agent_edr.upgrade_sign_message 保持一致。
func upgradeSignMessage(sha256Hex, version string, size int64) []byte {
	return []byte(fmt.Sprintf("FA-UPGRADE-V1\n%s\n%s\n%d",
		strings.ToLower(strings.TrimSpace(sha256Hex)),
		strings.TrimSpace(version),
		size))
}

func parseEd25519Pub(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("空公钥")
	}
	var raw []byte
	var err error
	if strings.HasPrefix(s, "hex:") {
		raw, err = hex.DecodeString(strings.TrimPrefix(s, "hex:"))
	} else {
		raw, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(s)
		}
		if err != nil {
			raw, err = hex.DecodeString(s)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("公钥解码失败: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("公钥长度 %d，期望 %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func pinnedUpgradePubKeys(cfg Config) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	cands := []string{upgradePubKeyB64, cfg.UpgradePubKey}
	for _, c := range cands {
		pk, err := parseEd25519Pub(c)
		if err == nil {
			out = append(out, pk)
		}
	}
	return out
}

func paramStr(params map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := params[k]
		if !ok || v == nil {
			continue
		}
		s := strings.TrimSpace(fmt.Sprint(v))
		if s != "" && s != "<nil>" {
			return s
		}
	}
	return ""
}

// verifyUpgradeSignature 校验升级包 Ed25519 签名。
// 已钉扎公钥时：必须带有效签名；未钉扎时：有签名则验（需 params.pubkey），无签名则放行（仅靠 sha256）。
func verifyUpgradeSignature(cfg Config, params map[string]any, sha256Hex, version string, size int64) error {
	sigB64 := paramStr(params, "sig_ed25519", "sig")
	pks := pinnedUpgradePubKeys(cfg)
	if len(pks) == 0 {
		if sigB64 == "" {
			return nil
		}
		// 指令自带 pubkey（仅开发兜底；生产应钉扎）
		pubStr := paramStr(params, "pubkey")
		if pubStr == "" {
			return fmt.Errorf("有签名但无可用公钥")
		}
		pk, err := parseEd25519Pub(pubStr)
		if err != nil {
			return fmt.Errorf("有签名但无可用公钥: %w", err)
		}
		pks = append(pks, pk)
	}
	if sigB64 == "" {
		return fmt.Errorf("已配置升级公钥，拒绝未签名升级包")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		sig, err = base64.RawStdEncoding.DecodeString(sigB64)
	}
	if err != nil {
		return fmt.Errorf("签名解码失败: %w", err)
	}
	msg := upgradeSignMessage(sha256Hex, version, size)
	for _, pk := range pks {
		if ed25519.Verify(pk, msg, sig) {
			return nil
		}
	}
	return fmt.Errorf("Ed25519 签名校验失败")
}
