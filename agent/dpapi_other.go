//go:build !windows

package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const secretPrefix = "plain:"

// 非 Windows 仅用于开发/测试：base64 并不提供保密性，依赖文件权限 0600。
func protectSecret(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	return secretPrefix + base64.StdEncoding.EncodeToString([]byte(plain)), nil
}

func unprotectSecret(blob string) (string, error) {
	blob = strings.TrimSpace(blob)
	if blob == "" {
		return "", nil
	}
	if !strings.HasPrefix(blob, secretPrefix) {
		return "", fmt.Errorf("未知凭据格式")
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(blob, secretPrefix))
	return string(b), err
}
