// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sync"
)

// liveCIDs records the connection identifiers held by endpoints in this
// process that have not been closed, failed or garbage collected. The
// default allocator avoids them: they are the collisions it can know
// about (RFC 9668 §4.1.1, §4.1.2). It cannot know OSCORE contexts that
// outlive their endpoint, or sessions in other processes.
var liveCIDs = cidRegistry{held: map[string]int{}}

type cidRegistry struct {
	mu   sync.Mutex
	held map[string]int
}

// cidHold is one endpoint's hold on an identifier. release is
// idempotent.
type cidHold struct {
	once sync.Once
	id   string
}

func (h *cidHold) release() {
	if h == nil {
		return
	}
	h.once.Do(func() {
		liveCIDs.mu.Lock()
		defer liveCIDs.mu.Unlock()
		if liveCIDs.held[h.id]--; liveCIDs.held[h.id] <= 0 {
			delete(liveCIDs.held, h.id)
		}
	})
}

// holdLocked records a hold on id; r.mu must be held.
func (r *cidRegistry) holdLocked(id []byte) *cidHold {
	r.held[string(id)]++
	return &cidHold{id: string(id)}
}

func (r *cidRegistry) hold(id []byte) *cidHold {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.holdLocked(id)
}

// allocate draws a random identifier that differs from avoid and from
// every identifier held in this process, and holds it. It prefers the
// 48 identifiers sent as one-byte CBOR integers, then other one-byte
// identifiers, then longer ones, up to 4 bytes (well inside the OSCORE
// Recipient ID limit of every suite).
func (r *cidRegistry) allocate(rnd io.Reader, avoid []byte) ([]byte, *cidHold, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	free := func(id []byte) bool {
		return r.held[string(id)] == 0 && (avoid == nil || !bytes.Equal(id, avoid))
	}
	for n := 0; n <= 4; n++ {
		size := max(n, 1)
		b := make([]byte, size)
		for range 64 {
			if _, err := io.ReadFull(rnd, b); err != nil {
				return nil, nil, fmt.Errorf("%w: reading connection identifier: %w", ErrStateViolation, err)
			}
			if n == 0 {
				// Map onto the 48 one-byte integer encodings
				// (0x00-0x17, 0x20-0x37).
				v := b[0] % 48
				if v >= 24 {
					v += 8
				}
				b[0] = v
			}
			if free(b) {
				id := slices.Clone(b)
				return id, r.holdLocked(id), nil
			}
		}
	}
	return nil, nil, fmt.Errorf("%w: could not choose a free connection identifier; set AllocateConnectionID", ErrStateViolation)
}

// pickCID returns the configured connection identifier, the caller's
// allocator's choice, or one from the default allocator; it is never
// equal to avoid (the peer's identifier).
func (s *session) pickCID(configured, avoid []byte) ([]byte, error) {
	var id []byte
	switch {
	case configured != nil:
		id = slices.Clone(configured)
		s.setCIDHold(liveCIDs.hold(id))
	case s.allocCID != nil:
		got, err := s.allocCID(slices.Clone(ConnectionID(avoid)))
		if err != nil {
			return nil, fmt.Errorf("%w: AllocateConnectionID: %w", ErrStateViolation, err)
		}
		if got == nil {
			return nil, fmt.Errorf("%w: AllocateConnectionID returned no identifier", ErrStateViolation)
		}
		id = slices.Clone([]byte(got))
	default:
		got, h, err := liveCIDs.allocate(s.randReader(), avoid)
		if err != nil {
			return nil, err
		}
		id = got
		s.setCIDHold(h)
	}
	if avoid != nil && bytes.Equal(id, avoid) {
		return nil, fmt.Errorf("%w: %w: connection identifier equals the peer's", ErrStateViolation, ErrConnectionIDCollision)
	}
	return id, nil
}

// setCIDHold keeps h until the session is closed, fails, or is garbage
// collected.
func (s *session) setCIDHold(h *cidHold) {
	s.cidHold.release()
	s.cidHold = h
	runtime.AddCleanup(s, func(h *cidHold) { h.release() }, h)
}
