//go:build windows

package main

import "testing"

func TestParseTaskXMLContent(t *testing.T) {
	xml := `<?xml version="1.0"?>
<Task>
  <Actions>
    <Exec>
      <Command>C:\Users\Public\RwcKd9\V3jydX.exe</Command>
      <WorkingDirectory>C:\Users\Public\RwcKd9\</WorkingDirectory>
    </Exec>
  </Actions>
</Task>`
	p := parseTaskXMLContent(xml)
	if len(p.Actions) != 1 {
		t.Fatalf("actions=%d", len(p.Actions))
	}
	if p.Actions[0].Command != `C:\Users\Public\RwcKd9\V3jydX.exe` {
		t.Fatalf("command=%q", p.Actions[0].Command)
	}
}
