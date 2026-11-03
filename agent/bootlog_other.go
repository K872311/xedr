//go:build !windows

package main

func setupBootLogger() func() { return func() {} }

func noteAgentError(msg string) {}
