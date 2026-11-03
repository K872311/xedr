//go:build windows

package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const secretPrefix = "dpapi:"

// protectSecret 用 DPAPI 机器作用域加密：服务账户(LocalSystem)与安装时的管理员都能解，
// 但拷到别的机器无法解密；agent.json 被他人读到也拿不到明文凭据。
func protectSecret(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	in := windows.DataBlob{Size: uint32(len(plain)), Data: unsafe.SliceData([]byte(plain))}
	var out windows.DataBlob
	desc, _ := windows.UTF16PtrFromString("ForensicAgent")
	if err := windows.CryptProtectData(&in, desc, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", fmt.Errorf("CryptProtectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	blob := unsafe.Slice(out.Data, out.Size)
	return secretPrefix + base64.StdEncoding.EncodeToString(blob), nil
}

func unprotectSecret(blob string) (string, error) {
	blob = strings.TrimSpace(blob)
	if blob == "" {
		return "", nil
	}
	if !strings.HasPrefix(blob, secretPrefix) {
		return "", fmt.Errorf("未知凭据格式")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(blob, secretPrefix))
	if err != nil || len(raw) == 0 {
		return "", fmt.Errorf("凭据损坏")
	}
	in := windows.DataBlob{Size: uint32(len(raw)), Data: &raw[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return string(unsafe.Slice(out.Data, out.Size)), nil
}
