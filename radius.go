// Package radius2fa implements an in-process RADIUS two-phase
// authentication library with request retransmission handling and
// one-time second-factor consumption.
package radius2fa

import (
	"bytes"
	"encoding/binary"
	"sync"
	"time"
)

// validity is how long a generated State stays claimable.
const validity = 120 * time.Second

// retention is how long a completed request's result is replayed.
const retention = 120 * time.Second

// Clock is a monotonic time source injected at construction.
type Clock interface {
	Now() time.Time
}

// VerifyPasswordFunc validates the first-factor proof for a user.
type VerifyPasswordFunc func(user, proof string) bool

// ConsumeFactorFunc consumes a one-time second factor for a user.
// A true result means the factor is irreversibly consumed.
type ConsumeFactorFunc func(user, proof string) bool

// Request is a RADIUS access request (no wire encoding).
type Request struct {
	NAS                  string
	Identifier           byte
	RequestAuthenticator [16]byte
	User                 string
	Proof                string
	State                []byte // nil for first-phase requests
}

// Result is the outcome of Handle.
type Result int

const (
	Reject Result = iota
	Accept
	Challenge
)

// Response carries the Handle outcome; State is set for Challenge.
type Response struct {
	Result Result
	State  []byte
}

// requestKey identifies a request: NAS + Identifier + RequestAuthenticator.
type requestKey struct {
	nas string
	id  byte
	ra  [16]byte
}

// record tracks one request key through execution and result retention.
type record struct {
	user      string
	proof     string
	state     []byte // request payload State, nil for phase one
	done      chan struct{}
	completed bool
	result    Response
	expiresAt time.Time // meaningful only once completed
}

// stateInfo is a generated challenge State bound to NAS and user.
type stateInfo struct {
	value    []byte
	nas      string
	user     string
	deadline time.Time
	claimed  bool
}

// Server is the two-phase authentication state machine.
type Server struct {
	mu             sync.Mutex
	now            func() time.Time
	verifyPassword VerifyPasswordFunc
	consumeFactor  ConsumeFactorFunc
	records        map[requestKey]*record
	states         map[string]*stateInfo
	counter        uint64
}

// New constructs a Server with injected clock and callbacks.
func New(clock Clock, vp VerifyPasswordFunc, cf ConsumeFactorFunc) *Server {
	return &Server{
		now:            clock.Now,
		verifyPassword: vp,
		consumeFactor:  cf,
		records:        make(map[requestKey]*record),
		states:         make(map[string]*stateInfo),
	}
}

// Handle processes one request and returns Challenge, Accept or Reject.
func (s *Server) Handle(req Request) Response {
	key := requestKey{nas: req.NAS, id: req.Identifier, ra: req.RequestAuthenticator}

	s.mu.Lock()
	if rec, ok := s.records[key]; ok {
		if rec.user != req.User || rec.proof != req.Proof ||
			!bytes.Equal(rec.state, req.State) {
			// Same key, different payload: reject without
			// touching or waiting on the original request.
			s.mu.Unlock()
			return Response{Result: Reject}
		}
		if rec.completed {
			if s.now().Before(rec.expiresAt) {
				res := rec.result
				s.mu.Unlock()
				return res
			}
			// Expired result: drop and reprocess as new.
			delete(s.records, key)
		} else {
			// Exact retransmission of an in-flight request:
			// share the single execution and its final result.
			done := rec.done
			s.mu.Unlock()
			<-done
			s.mu.Lock()
			res := rec.result
			s.mu.Unlock()
			return res
		}
	}

	if req.State == nil {
		return s.handlePhase1(key, req)
	}
	return s.handlePhase2(key, req)
}

// handlePhase1 runs password verification; s.mu is held on entry.
func (s *Server) handlePhase1(key requestKey, req Request) Response {
	rec := &record{user: req.User, proof: req.Proof, done: make(chan struct{})}
	s.records[key] = rec
	s.mu.Unlock()

	ok := s.verifyPassword(req.User, req.Proof)

	s.mu.Lock()
	defer s.mu.Unlock()
	var res Response
	if ok {
		st := s.newState(req.NAS, req.User)
		res = Response{Result: Challenge, State: st.value}
	} else {
		res = Response{Result: Reject}
	}
	s.finish(rec, res)
	return res
}

// handlePhase2 claims the State and consumes the factor; s.mu held on entry.
func (s *Server) handlePhase2(key requestKey, req Request) Response {
	st, ok := s.states[string(req.State)]
	if !ok || st.nas != req.NAS || st.user != req.User ||
		st.claimed || !s.now().Before(st.deadline) {
		// Unknown state, wrong binding, already consumed or
		// expired: reject without consuming the state.
		s.mu.Unlock()
		return Response{Result: Reject}
	}
	st.claimed = true // consumed regardless of factor outcome

	rec := &record{
		user:  req.User,
		proof: req.Proof,
		state: append([]byte(nil), req.State...),
		done:  make(chan struct{}),
	}
	s.records[key] = rec
	s.mu.Unlock()

	ok = s.consumeFactor(req.User, req.Proof)

	s.mu.Lock()
	defer s.mu.Unlock()
	res := Response{Result: Reject}
	if ok {
		res = Response{Result: Accept}
	}
	s.finish(rec, res)
	return res
}

// finish stores the final result and wakes retransmission waiters.
// s.mu must be held.
func (s *Server) finish(rec *record, res Response) {
	rec.completed = true
	rec.result = res
	rec.expiresAt = s.now().Add(retention)
	close(rec.done)
}

// newState creates a unique State bound to nas/user, valid from now.
// s.mu must be held.
func (s *Server) newState(nas, user string) *stateInfo {
	s.counter++
	value := make([]byte, 16)
	binary.BigEndian.PutUint64(value[8:], s.counter)
	copy(value[:8], []byte("radius2f"))
	st := &stateInfo{
		value:    value,
		nas:      nas,
		user:     user,
		deadline: s.now().Add(validity),
	}
	s.states[string(value)] = st
	return st
}

// Sweep removes expired records that no in-flight operation depends on.
func (s *Server) Sweep() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, rec := range s.records {
		// Pending records never expire and are kept so their
		// single execution is never duplicated.
		if rec.completed && !now.Before(rec.expiresAt) {
			delete(s.records, key)
		}
	}
	for value, st := range s.states {
		if !now.Before(st.deadline) {
			delete(s.states, value)
		}
	}
}
