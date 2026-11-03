//go:build windows

package main

import (
	"strings"
)

// enrichProcessExt 写入 Defend 风格的 process_ext（实体链 + 签名/信誉启发式）。
func enrichProcessExt(detail map[string]any, at int64) *procEntity {
	if detail == nil {
		return nil
	}
	ent := procEntities.annotate(detail, at)
	if ent == nil {
		return nil
	}
	ext := procEntities.buildExt(ent)
	detail["process_ext"] = ext
	if pn := asString(ext["parent_name"]); pn != "" && asString(detail["parent_name"]) == "" {
		detail["parent_name"] = pn
	}
	if peid := asString(ext["parent_entity_id"]); peid != "" && asString(detail["parent_entity_id"]) == "" {
		detail["parent_entity_id"] = peid
	}
	return ent
}

func (t *entityTable) buildExt(e *procEntity) map[string]any {
	if e == nil {
		return nil
	}
	t.ensureSignature(e)
	ext := map[string]any{
		"entity_id": e.ID,
		"pid":       e.PID,
		"name":      e.Name,
		"path":      e.Image,
		"boot_id":   t.boot,
	}
	if e.ParentID != "" {
		ext["parent_entity_id"] = e.ParentID
	}
	if e.PPID != 0 {
		ext["ppid"] = e.PPID
	}
	chain := t.ancestryLocked(e, 5)
	if len(chain) > 0 {
		ext["ancestry"] = chain
		if len(chain) >= 2 {
			ext["parent_name"] = asString(chain[1]["name"])
			ext["parent_path"] = asString(chain[1]["path"])
		}
		if len(chain) >= 3 {
			ext["grandparent_name"] = asString(chain[2]["name"])
		}
	}
	rep := "unknown"
	trusted := false
	if e.SigKnown {
		if e.SigTrusted {
			rep, trusted = "trusted", true
		} else if peSignedExplicitBad(e.SigStatus) {
			rep = "unsigned"
		} else {
			rep = "untrusted"
		}
	}
	ext["reputation"] = rep
	ext["code_signature"] = map[string]any{
		"trusted": trusted,
		"status":  e.SigStatus,
		"subject_name": e.SigSigner,
	}
	if e.SigSigner != "" {
		ext["signer"] = e.SigSigner
	}
	return ext
}

func peCacheLoad(path string) (peMeta, bool) {
	pm, ok := peCache.Load(strings.ToLower(path))
	if !ok {
		return peMeta{}, false
	}
	m, ok := pm.(peMeta)
	return m, ok
}

func (t *entityTable) ancestryLocked(e *procEntity, maxDepth int) []map[string]any {
	if e == nil || maxDepth <= 0 {
		return nil
	}
	var out []map[string]any
	cur := e
	for i := 0; i < maxDepth && cur != nil; i++ {
		out = append(out, map[string]any{
			"entity_id": cur.ID,
			"pid":       cur.PID,
			"name":      cur.Name,
			"path":      cur.Image,
		})
		if cur.ParentID == "" {
			break
		}
		cur = t.byID[cur.ParentID]
	}
	return out
}
