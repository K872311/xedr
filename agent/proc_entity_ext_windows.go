//go:build windows

package main

func (t *entityTable) ensureSignature(e *procEntity) {
	if e == nil || e.SigLoaded || e.Image == "" {
		return
	}
	valid, st, known := peSignedCached(e.Image)
	e.SigLoaded = true
	e.SigKnown = known
	e.SigStatus = st
	e.SigTrusted = known && valid
	e.SigSigner = ""
	if known && valid {
		if pm, ok := peCacheLoad(e.Image); ok {
			e.SigSigner = pm.Signer
		}
	}
}
