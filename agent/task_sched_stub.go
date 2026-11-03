//go:build !windows

package main

func parseScheduledTaskFile(path string) scheduledTaskParsed { return scheduledTaskParsed{} }

func parseTaskXMLContent(xml string) scheduledTaskParsed { return scheduledTaskParsed{} }

func enrichFIMScheduledTaskEvent(ev map[string]any, taskFilePath string) {}
