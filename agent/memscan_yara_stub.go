//go:build !yara

package main

func reloadYaraCompiledRules(dir string) error {
	yaraEngineOK = false
	return nil
}

func scanYaraOnRegion(chunk []byte, baseAddr uintptr, pid uint32, procName string) []map[string]any {
	return nil
}
