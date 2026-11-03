//go:build windows

package main

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	evtSubscribeActionError   = 0
	evtSubscribeActionDeliver = 1
	evtSubscribeToFuture      = 1
	evtRenderEventXML         = 1
	evtRenderBookmark         = 2
)

var (
	modWevtapi = windows.NewLazySystemDLL("wevtapi.dll")

	procEvtSubscribe      = modWevtapi.NewProc("EvtSubscribe")
	procEvtClose          = modWevtapi.NewProc("EvtClose")
	procEvtRender         = modWevtapi.NewProc("EvtRender")
	procEvtCreateBookmark = modWevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark = modWevtapi.NewProc("EvtUpdateBookmark")
	procEvtQuery          = modWevtapi.NewProc("EvtQuery")
)

const evtQueryChannelPath = 0x1

func winevtTryNative(ctx context.Context, bookmarkDir string, push func(map[string]any)) error {
	if err := modWevtapi.Load(); err != nil {
		return err
	}
	_ = os.MkdirAll(bookmarkDir, 0700)
	defs := winevtAvailableChannels(winevtChannelDefsFiltered())
	if len(defs) == 0 {
		return errors.New("no event channels")
	}
	var names []string
	for _, d := range defs {
		names = append(names, d.ID)
	}
	push(map[string]any{
		"etype": "winevent_status", "summary": "事件通道(native): " + stringsJoin(names, ","),
		"severity": "info", "ts": time.Now().Format("2006-01-02T15:04:05"),
		"detail":   map[string]any{"sources": names, "backend": "wevtapi"},
	})

	var wg sync.WaitGroup
	for _, ch := range defs {
		wg.Add(1)
		go func(c winevtChannel) {
			defer wg.Done()
			winevtRunChannel(ctx, bookmarkDir, c, push)
		}(ch)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("all channel subscriptions ended")
}

func winevtAvailableChannels(defs []winevtChannel) []winevtChannel {
	var out []winevtChannel
	for _, d := range defs {
		if winevtChannelOK(d.Channel) {
			out = append(out, d)
		}
	}
	return out
}

func winevtChannelOK(channel string) bool {
	p, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return false
	}
	q, _ := windows.UTF16PtrFromString("*")
	h, _, _ := procEvtQuery.Call(0, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(q)), evtQueryChannelPath)
	if h == 0 {
		return false
	}
	procEvtClose.Call(h)
	return true
}

func winevtRunChannel(ctx context.Context, bookmarkDir string, ch winevtChannel, push func(map[string]any)) {
	for {
		if ctx.Err() != nil {
			return
		}
		err := winevtSubscribeOnce(ctx, bookmarkDir, ch, push)
		if err != nil && ctx.Err() == nil {
			log.Printf("winevent[%s]: %v", ch.ID, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		} else {
			return
		}
	}
}

func winevtSubscribeOnce(ctx context.Context, bookmarkDir string, ch winevtChannel, push func(map[string]any)) error {
	deliver := make(chan uintptr, 128)
	var dropped uint32
	cb := syscall.NewCallback(func(action, _ /*ctx*/, evt uintptr) uintptr {
		if action != evtSubscribeActionDeliver || evt == 0 {
			return 1
		}
		select {
		case deliver <- evt:
		default:
			atomic.AddUint32(&dropped, 1)
			procEvtClose.Call(evt)
		}
		return 1
	})

	chPtr, err := windows.UTF16PtrFromString(ch.Channel)
	if err != nil {
		return err
	}
	xpPtr, err := windows.UTF16PtrFromString(ch.XPath)
	if err != nil {
		return err
	}

	bookmark := winevtLoadBookmark(bookmarkDir, ch.ID)
	defer winevtCloseHandle(bookmark)

	sub, _, e1 := procEvtSubscribe.Call(
		0,
		0,
		uintptr(unsafe.Pointer(chPtr)),
		uintptr(unsafe.Pointer(xpPtr)),
		bookmark,
		0,
		cb,
		evtSubscribeToFuture,
	)
	if sub == 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return e1
		}
		return errors.New("EvtSubscribe failed")
	}
	defer winevtCloseHandle(sub)

	saveTick := time.NewTicker(15 * time.Second)
	defer saveTick.Stop()
	eventsSinceSave := 0

	for {
		select {
		case <-ctx.Done():
			if bookmark != 0 && eventsSinceSave > 0 {
				winevtSaveBookmark(bookmarkDir, ch.ID, bookmark)
			}
			return ctx.Err()
		case <-saveTick.C:
			if bookmark != 0 && eventsSinceSave > 0 {
				winevtSaveBookmark(bookmarkDir, ch.ID, bookmark)
				eventsSinceSave = 0
			}
			if d := atomic.SwapUint32(&dropped, 0); d > 0 {
				log.Printf("winevent[%s]: dropped %d events (queue full)", ch.ID, d)
			}
		case h := <-deliver:
			xmlText, err := winevtRenderEventXML(h)
			if bookmark != 0 {
				_, _, _ = procEvtUpdateBookmark.Call(bookmark, h)
				eventsSinceSave++
			}
			procEvtClose.Call(h)
			if err != nil {
				continue
			}
			if ev := winevtParseXML(xmlText, ch.Channel); ev != nil {
				push(ev)
			}
		}
	}
}

func winevtLoadBookmark(dir, id string) uintptr {
	path := filepath.Join(dir, id+".xml")
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		h, _, _ := procEvtCreateBookmark.Call(0)
		return h
	}
	// 文件为 UTF-8 书签 XML
	p, err := windows.UTF16PtrFromString(string(raw))
	if err != nil {
		h, _, _ := procEvtCreateBookmark.Call(0)
		return h
	}
	h, _, _ := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(p)))
	if h == 0 {
		h, _, _ = procEvtCreateBookmark.Call(0)
	}
	return h
}

func winevtSaveBookmark(dir, id string, bookmark uintptr) {
	if bookmark == 0 {
		return
	}
	xmlText, err := winevtRenderBookmark(bookmark)
	if err != nil || xmlText == "" {
		return
	}
	path := filepath.Join(dir, id+".xml")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(xmlText), 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func winevtRenderBookmark(bookmark uintptr) (string, error) {
	return winevtRender(bookmark, evtRenderBookmark)
}

func winevtRenderEventXML(evt uintptr) (string, error) {
	return winevtRender(evt, evtRenderEventXML)
}

func winevtRender(handle uintptr, flags uint32) (string, error) {
	var used, props uint32
	r0, _, err := procEvtRender.Call(0, handle, uintptr(flags), 0, 0, uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if r0 == 0 && err != nil && err != syscall.ERROR_INSUFFICIENT_BUFFER {
		return "", err
	}
	if used == 0 {
		used = 65536
	}
	buf := make([]uint16, (used+1)/2)
	for tries := 0; tries < 3; tries++ {
		r0, _, err = procEvtRender.Call(
			0, handle, uintptr(flags),
			uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)),
		)
		if r0 != 0 {
			return windows.UTF16ToString(buf[:used/2]), nil
		}
		if err == syscall.ERROR_INSUFFICIENT_BUFFER {
			buf = make([]uint16, (used+1)/2)
			continue
		}
		if err != nil && err != syscall.Errno(0) {
			return "", err
		}
		break
	}
	return "", errors.New("EvtRender failed")
}

func winevtCloseHandle(h uintptr) {
	if h != 0 {
		procEvtClose.Call(h)
	}
}

func stringsJoin(a []string, sep string) string {
	if len(a) == 0 {
		return ""
	}
	s := a[0]
	for i := 1; i < len(a); i++ {
		s += sep + a[i]
	}
	return s
}
