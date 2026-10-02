// Package radius2fa implements in-process two-stage RADIUS-style
// authentication with retransmission handling and one-time second-factor
// consumption. It keeps all state in memory and does not perform any
// byte-level packet encoding or decoding.
package radius2fa

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const (
	stateTTL    = 120 * time.Second
	resultTTL   = 120 * time.Second
	stateIDSize = 16
)

// Kind is the outcome of handling a request.
type Kind int

const (
	Reject Kind = iota
	Accept
	Challenge
)

// Response is the result of Handle. State is set only when Kind == Challenge.
type Response struct {
	Kind  Kind
	State string
}

// Request describes a single authentication request. The request key is
// (NAS, Identifier, RequestAuthenticator); a retransmission must also carry
// an identical User, Proof and State.
type Request struct {
	NAS                  string
	Identifier           byte
	RequestAuthenticator [16]byte
	User                 string
	Proof                string
	State                *string
}

// Server holds the in-memory authentication state.
type Server struct {
	mu             sync.Mutex
	now            func() time.Time
	verifyPassword func(user, proof string) bool
	consumeFactor  func(user, proof string) bool

	requests map[requestKey]*requestRecord
	states   map[string]*stateRecord
}

type requestKey struct {
	nas                  string
	identifier           byte
	requestAuthenticator [16]byte
}

type requestPayload struct {
	user  string
	proof string
	state *string
}

func payloadOf(req Request) requestPayload {
	return requestPayload{user: req.User, proof: req.Proof, state: req.State}
}

func equalPayload(a, b requestPayload) bool {
	if a.user != b.user || a.proof != b.proof {
		return false
	}
	if a.state == nil || b.state == nil {
		return a.state == b.state
	}
	return *a.state == *b.state
}

type requestRecord struct {
	payload   requestPayload
	done      chan struct{}
	completed bool
	result    Response
	expiresAt time.Time
}

type stateRecord struct {
	nas       string
	user      string
	expiresAt time.Time
}

// New builds a Server with an injected monotonic clock and the two
// verification callbacks. Both callbacks may block but must eventually
// return a boolean.
func New(now func() time.Time, verifyPassword, consumeFactor func(user, proof string) bool) *Server {
	return &Server{
		now:            now,
		verifyPassword: verifyPassword,
		consumeFactor:  consumeFactor,
		requests:       make(map[requestKey]*requestRecord),
		states:         make(map[string]*stateRecord),
	}
}

// Handle processes one request and returns Challenge, Accept or Reject.
// Retransmissions of an in-flight request wait for the same execution and
// share its result; retransmissions of a completed request get the retained
// result until it expires.
func (s *Server) Handle(req Request) Response {
	key := requestKey{
		nas:                  req.NAS,
		identifier:           req.Identifier,
		requestAuthenticator: req.RequestAuthenticator,
	}
	payload := payloadOf(req)

	s.mu.Lock()
	for {
		rec, ok := s.requests[key]
		if !ok {
			rec = &requestRecord{payload: payload, done: make(chan struct{})}
			s.requests[key] = rec
			s.mu.Unlock()

			result := s.process(req)

			s.mu.Lock()
			rec.result = result
			rec.completed = true
			rec.expiresAt = s.now().Add(resultTTL)
			close(rec.done)
			s.mu.Unlock()
			return result
		}
		if !equalPayload(rec.payload, payload) {
			s.mu.Unlock()
			return Response{Kind: Reject}
		}
		if rec.completed {
			if s.now().Before(rec.expiresAt) {
				result := rec.result
				s.mu.Unlock()
				return result
			}
			delete(s.requests, key)
			continue
		}
		done := rec.done
		s.mu.Unlock()
		<-done
		s.mu.Lock()
		result := rec.result
		s.mu.Unlock()
		return result
	}
}

// process executes the two-stage flow for a fresh request. It runs outside
// the server lock so blocking callbacks do not stall other requests.
func (s *Server) process(req Request) Response {
	if req.State == nil {
		if !s.verifyPassword(req.User, req.Proof) {
			return Response{Kind: Reject}
		}
		return Response{Kind: Challenge, State: s.issueState(req.NAS, req.User)}
	}

	s.mu.Lock()
	st, ok := s.states[*req.State]
	if !ok ||
		st.nas != req.NAS ||
		st.user != req.User ||
		!s.now().Before(st.expiresAt) {
		s.mu.Unlock()
		return Response{Kind: Reject}
	}
	// Claim: the state is consumed now, regardless of the factor outcome.
	delete(s.states, *req.State)
	s.mu.Unlock()

	if s.consumeFactor(req.User, req.Proof) {
		return Response{Kind: Accept}
	}
	return Response{Kind: Reject}
}

// issueState creates a unique state id bound to nas+user, valid stateTTL
// from now.
func (s *Server) issueState(nas, user string) string {
	buf := make([]byte, stateIDSize)
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		id := hex.EncodeToString(buf)
		if _, taken := s.states[id]; taken {
			continue
		}
		s.states[id] = &stateRecord{
			nas:       nas,
			user:      user,
			expiresAt: s.now().Add(stateTTL),
		}
		return id
	}
}

// Sweep removes expired records that no in-flight operation depends on.
// Records with a pending execution are never removed, so a sweep can never
// cause a duplicate callback execution.
func (s *Server) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, rec := range s.requests {
		if rec.completed && !now.Before(rec.expiresAt) {
			delete(s.requests, key)
		}
	}
	for id, st := range s.states {
		if !now.Before(st.expiresAt) {
			delete(s.states, id)
		}
	}
}
