package main

import (
	"log"
	"strings"
)

var ruleFIMSyncFn func([]string)

func applyRuleFIMPaths(paths []string, syncFIM func()) {
	if len(paths) == 0 {
		return
	}
	if ruleFIMSyncFn != nil {
		ruleFIMSyncFn(paths)
	}
	if syncFIM != nil {
		syncFIM()
	}
}

func setRuleFIMPathsFromSync(paths []string, current *[]string) {
	rp := append([]string(nil), paths...)
	if len(rp) > 20 {
		rp = rp[:20]
	}
	if strings.Join(rp, ";") == strings.Join(*current, ";") {
		return
	}
	*current = rp
	log.Printf("规则监控目录(sync): %v", *current)
}
