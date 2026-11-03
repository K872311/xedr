package main

// captureETWStatusFn 由 agent_loop 注入，避免 capture 包与 etwWatcher 循环依赖。
var captureETWStatusFn func() (mode string, ok bool)
