package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestUpgradeSignRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sha := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	ver := "0.12.0"
	var size int64 = 12345
	msg := upgradeSignMessage(sha, ver, size)
	sig := ed25519.Sign(priv, msg)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	cfg := Config{UpgradePubKey: pubB64}
	params := map[string]any{"sig_ed25519": sigB64}
	if err := verifyUpgradeSignature(cfg, params, sha, ver, size); err != nil {
		t.Fatal(err)
	}
	if err := verifyUpgradeSignature(cfg, params, sha, ver, size+1); err == nil {
		t.Fatal("篡改 size 应失败")
	}
	cfgPin := Config{UpgradePubKey: pubB64}
	if err := verifyUpgradeSignature(cfgPin, map[string]any{}, sha, ver, size); err == nil {
		t.Fatal("已钉扎公钥时无签名应拒绝")
	}
	// 未钉扎 + 无签名 → 兼容放行
	if err := verifyUpgradeSignature(Config{}, map[string]any{}, sha, ver, size); err != nil {
		t.Fatal(err)
	}
}
