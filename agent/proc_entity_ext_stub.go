//go:build !windows

package main

func enrichProcessExt(detail map[string]any, at int64) *procEntity {
	if detail == nil {
		return nil
	}
	return procEntities.annotate(detail, at)
}
