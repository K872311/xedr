//go:build windows

package main

import "os"

func init() {
	elevatedFn = func() bool {
		e, _ := queryTokenMeta(uint32(os.Getpid()))
		return e == "true"
	}
}
