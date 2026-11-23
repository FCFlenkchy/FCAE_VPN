//go:build fcae_urnetwork

package main

import (
	"sync"
	"time"
)

// urRates has exactly one sampling owner; readers never advance its baseline.
type urRates struct {
	mu             sync.Mutex
	at             time.Time
	rx, tx         uint64
	rxRate, txRate uint64
}

func (r *urRates) sample(rx, tx uint64, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	elapsed := now.Sub(r.at).Seconds()
	if !r.at.IsZero() && elapsed > 0 && rx >= r.rx && tx >= r.tx {
		r.rxRate = uint64(float64(rx-r.rx) / elapsed)
		r.txRate = uint64(float64(tx-r.tx) / elapsed)
	} else {
		r.rxRate, r.txRate = 0, 0
	}
	r.at, r.rx, r.tx = now, rx, tx
}

func (r *urRates) get() (uint64, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rxRate, r.txRate
}
