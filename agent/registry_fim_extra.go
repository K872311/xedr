package main

import "sync"

var (
	regFIMExtraMu sync.RWMutex
	regFIMExtras  []string
)

func setRegistryFIMExtras(paths []string) {
	regFIMExtraMu.Lock()
	regFIMExtras = append([]string(nil), paths...)
	regFIMExtraMu.Unlock()
	applyRegistryFIMSync(globalRegWatcher)
}

func registryFIMExtras() []string {
	regFIMExtraMu.RLock()
	defer regFIMExtraMu.RUnlock()
	return append([]string(nil), regFIMExtras...)
}
