//go:build windows

package main

import (
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// collectBrowser 采集 Chrome / Edge / Firefox 近期访问记录（复制 History 再查，避免锁库）。
func collectBrowser() ([]any, error) {
	var out []any
	out = append(out, collectChromiumHistory("chrome", filepath.Join(os.Getenv("LOCALAPPDATA"), `Google\Chrome\User Data`))...)
	out = append(out, collectChromiumHistory("edge", filepath.Join(os.Getenv("LOCALAPPDATA"), `Microsoft\Edge\User Data`))...)
	out = append(out, collectFirefoxHistory()...)
	return truncateItems(out), nil
}

func collectChromiumHistory(browser, userData string) []any {
	if userData == "" {
		return nil
	}
	profiles, _ := os.ReadDir(userData)
	var out []any
	for _, p := range profiles {
		name := p.Name()
		if !p.IsDir() {
			continue
		}
		low := strings.ToLower(name)
		if low != "default" && !strings.HasPrefix(low, "profile") {
			continue
		}
		hist := filepath.Join(userData, name, "History")
		if _, err := os.Stat(hist); err != nil {
			continue
		}
		rows := queryChromiumHistory(browser, name, hist, 120)
		out = append(out, rows...)
		if len(out) >= 400 {
			break
		}
	}
	return out
}

func queryChromiumHistory(browser, profile, histPath string, limit int) []any {
	tmp, err := copyDBForRead(histPath)
	if err != nil {
		return nil
	}
	defer os.Remove(tmp)
	db, err := sql.Open("sqlite", tmp+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return nil
	}
	defer db.Close()
	// Chrome 时间戳：自 1601-01-01 UTC 起的微秒
	q := `
SELECT u.url, u.title, u.visit_count, v.visit_time
FROM urls u
JOIN visits v ON v.url = u.id
ORDER BY v.visit_time DESC
LIMIT ?`
	rows, err := db.Query(q, limit)
	if err != nil {
		// 仅 urls 表兜底
		rows, err = db.Query(`SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?`, limit)
		if err != nil {
			return nil
		}
	}
	defer rows.Close()
	var out []any
	for rows.Next() {
		var url, title string
		var visits int
		var vt int64
		if rows.Scan(&url, &title, &visits, &vt) != nil {
			continue
		}
		if url == "" || strings.HasPrefix(strings.ToLower(url), "chrome://") || strings.HasPrefix(strings.ToLower(url), "edge://") {
			continue
		}
		item := map[string]any{
			"browser":     browser,
			"profile":     profile,
			"url":         url,
			"title":       title,
			"visit_count": visits,
			"visited_at":  chromiumTime(vt),
			"domain":      urlHost(url),
		}
		out = append(out, item)
	}
	return out
}

func collectFirefoxHistory() []any {
	root := filepath.Join(os.Getenv("APPDATA"), `Mozilla\Firefox\Profiles`)
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []any
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		places := filepath.Join(root, e.Name(), "places.sqlite")
		if _, err := os.Stat(places); err != nil {
			continue
		}
		out = append(out, queryFirefoxHistory(e.Name(), places, 120)...)
		if len(out) >= 400 {
			break
		}
	}
	return out
}

func queryFirefoxHistory(profile, placesPath string, limit int) []any {
	tmp, err := copyDBForRead(placesPath)
	if err != nil {
		return nil
	}
	defer os.Remove(tmp)
	db, err := sql.Open("sqlite", tmp+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return nil
	}
	defer db.Close()
	rows, err := db.Query(`
SELECT p.url, p.title, p.visit_count, h.visit_date
FROM moz_places p
JOIN moz_historyvisits h ON h.place_id = p.id
WHERE p.url LIKE 'http%'
ORDER BY h.visit_date DESC
LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []any
	for rows.Next() {
		var url, title string
		var visits int
		var vt int64
		if rows.Scan(&url, &title, &visits, &vt) != nil {
			continue
		}
		item := map[string]any{
			"browser":     "firefox",
			"profile":     profile,
			"url":         url,
			"title":       title,
			"visit_count": visits,
			"visited_at":  firefoxTime(vt),
			"domain":      urlHost(url),
		}
		out = append(out, item)
	}
	return out
}

func copyDBForRead(src string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	tmp, err := os.CreateTemp("", "fa-hist-*.db")
	if err != nil {
		return "", err
	}
	path := tmp.Name()
	_, err = io.Copy(tmp, in)
	_ = tmp.Close()
	if err != nil {
		os.Remove(path)
		return "", err
	}
	// WAL 旁路：尽量带上 -wal/-shm 的最新页（失败忽略）
	for _, suf := range []string{"-wal", "-shm"} {
		if b, e := os.ReadFile(src + suf); e == nil && len(b) > 0 {
			_ = os.WriteFile(path+suf, b, 0600)
		}
	}
	return path, nil
}

func chromiumTime(usec int64) string {
	if usec <= 0 {
		return ""
	}
	// Windows epoch 1601 → Unix
	sec := (usec / 1e6) - 11644473600
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).Local().Format("2006-01-02T15:04:05")
}

func firefoxTime(usec int64) string {
	if usec <= 0 {
		return ""
	}
	return time.Unix(usec/1e6, 0).Local().Format("2006-01-02T15:04:05")
}

func urlHost(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, "]"); i >= 0 && strings.HasPrefix(s, "[") {
		s = s[1:i]
	} else if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(strings.TrimSpace(s))
}
