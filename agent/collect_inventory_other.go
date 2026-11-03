//go:build !windows

package main

func collectSoftware() ([]any, error) { return nil, nil }
func collectHotfix() ([]any, error)   { return nil, nil }
func collectListen() ([]any, error)    { return collectNetwork() }
