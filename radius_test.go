package radius2fa

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock safe for concurrent use.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Unix(1_700_000_000, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func strPtr(s string) *string { return &s }

func auth(id byte) [16]byte {
	var a [16]byte
	a[0] = id
	return a
}

// newChallenge runs the password stage and returns the issued state.
func newChallenge(t *testing.T, s *Server, nas, user string) string {
	t.Helper()
	resp := s.Handle(Request{NAS: nas, Identifier: 1, RequestAuthenticator: auth(1), User: user, Proof: "pw"})
	if resp.Kind != Challenge || resp.State == "" {
		t.Fatalf("expected Challenge with state, got %+v", resp)
	}
	return resp.State
}

// TestConcurrentRetransmissionSharesBlockedFactor covers concurrent
// retransmissions of the same second-stage request while the factor callback
// is blocked after consuming the one-time factor: all retransmissions share
// the single Accept result, and ConsumeFactor runs exactly once even across
// a clock advance and a Sweep.
func TestConcurrentRetransmissionSharesBlockedFactor(t *testing.T) {
	clock := newFakeClock()

	entered := make(chan struct{})
	release := make(chan struct{})
	var factorCalls atomic.Int32

	s := New(clock.Now,
		func(user, proof string) bool { return true },
		func(user, proof string) bool {
			factorCalls.Add(1)
			close(entered)
			<-release
			return true
		},
	)

	state := newChallenge(t, s, "nas1", "alice")

	req := Request{
		NAS:                  "nas1",
		Identifier:           2,
		RequestAuthenticator: auth(2),
		User:                 "alice",
		Proof:                "otp",
		State:                strPtr(state),
	}

	const n = 8
	results := make(chan Response, n)
	for i := 0; i < n; i++ {
		go func() { results <- s.Handle(req) }()
	}

	// Wait until the factor callback is blocked inside ConsumeFactor.
	<-entered

	// Time passes and a sweep runs while the callback is still blocked;
	// the pending record must survive and must not be re-executed.
	clock.Advance(121 * time.Second)
	s.Sweep()

	close(release)

	for i := 0; i < n; i++ {
		resp := <-results
		if resp.Kind != Accept {
			t.Fatalf("retransmission %d: expected Accept, got %+v", i, resp)
		}
	}
	if got := factorCalls.Load(); got != 1 {
		t.Fatalf("ConsumeFactor called %d times, want 1", got)
	}

	// A later retransmission still gets the retained Accept result.
	if resp := s.Handle(req); resp.Kind != Accept {
		t.Fatalf("retained retransmission: expected Accept, got %+v", resp)
	}
	if got := factorCalls.Load(); got != 1 {
		t.Fatalf("ConsumeFactor called %d times after retention, want 1", got)
	}
}

// TestStateClaimRaceWithWrongNAS covers two different request keys racing to
// claim the same state while a wrong-NAS request is mixed in: at most one
// valid request may execute ConsumeFactor, and the wrong-NAS request can
// neither claim nor consume the state.
func TestStateClaimRaceWithWrongNAS(t *testing.T) {
	clock := newFakeClock()

	entered := make(chan struct{})
	release := make(chan struct{})
	var factorCalls atomic.Int32

	s := New(clock.Now,
		func(user, proof string) bool { return true },
		func(user, proof string) bool {
			factorCalls.Add(1)
			close(entered)
			<-release
			return true
		},
	)

	state := newChallenge(t, s, "nas1", "alice")

	// A wrong-NAS request must be rejected without consuming the state.
	wrongNAS := Request{
		NAS:                  "evil-nas",
		Identifier:           9,
		RequestAuthenticator: auth(9),
		User:                 "alice",
		Proof:                "otp",
		State:                strPtr(state),
	}
	if resp := s.Handle(wrongNAS); resp.Kind != Reject {
		t.Fatalf("wrong NAS: expected Reject, got %+v", resp)
	}
	if got := factorCalls.Load(); got != 0 {
		t.Fatalf("wrong NAS triggered ConsumeFactor %d times", got)
	}

	// Two different keys with correct binding race for the same state,
	// with more wrong-NAS attempts mixed in concurrently.
	reqA := Request{NAS: "nas1", Identifier: 2, RequestAuthenticator: auth(2), User: "alice", Proof: "otp", State: strPtr(state)}
	reqB := Request{NAS: "nas1", Identifier: 3, RequestAuthenticator: auth(3), User: "alice", Proof: "otp", State: strPtr(state)}

	const wrongNASExtra = 4
	results := make(chan Response, 2+wrongNASExtra)
	for i := 0; i < wrongNASExtra; i++ {
		bad := wrongNAS
		bad.Identifier = byte(10 + i)
		bad.RequestAuthenticator = auth(byte(10 + i))
		go func() { results <- s.Handle(bad) }()
	}
	go func() { results <- s.Handle(reqA) }()
	go func() { results <- s.Handle(reqB) }()

	// The single claimer is now blocked inside ConsumeFactor.
	<-entered
	close(release)

	accepts := 0
	for i := 0; i < 2+wrongNASExtra; i++ {
		resp := <-results
		switch resp.Kind {
		case Accept:
			accepts++
		case Reject:
		default:
			t.Fatalf("unexpected response %+v", resp)
		}
	}
	if accepts != 1 {
		t.Fatalf("got %d Accepts, want exactly 1", accepts)
	}
	if got := factorCalls.Load(); got != 1 {
		t.Fatalf("ConsumeFactor called %d times, want 1", got)
	}

	// The state is fully consumed: any later use is rejected.
	if resp := s.Handle(Request{NAS: "nas1", Identifier: 7, RequestAuthenticator: auth(7), User: "alice", Proof: "otp", State: strPtr(state)}); resp.Kind != Reject {
		t.Fatalf("consumed state reuse: expected Reject, got %+v", resp)
	}
	if got := factorCalls.Load(); got != 1 {
		t.Fatalf("ConsumeFactor called %d times after reuse attempt, want 1", got)
	}
}

// TestSameKeyDifferentPayloadRejected: same key but different payload is an
// immediate Reject and must not disturb the original in-flight request.
func TestSameKeyDifferentPayloadRejected(t *testing.T) {
	clock := newFakeClock()
	entered := make(chan struct{})
	release := make(chan struct{})

	s := New(clock.Now,
		func(user, proof string) bool { return true },
		func(user, proof string) bool {
			close(entered)
			<-release
			return true
		},
	)
	state := newChallenge(t, s, "nas1", "alice")

	base := Request{NAS: "nas1", Identifier: 2, RequestAuthenticator: auth(2), User: "alice", Proof: "otp", State: strPtr(state)}
	resultCh := make(chan Response, 1)
	go func() { resultCh <- s.Handle(base) }()
	<-entered

	mutated := base
	mutated.Proof = "different"
	if resp := s.Handle(mutated); resp.Kind != Reject {
		t.Fatalf("different payload: expected immediate Reject, got %+v", resp)
	}

	close(release)
	if resp := <-resultCh; resp.Kind != Accept {
		t.Fatalf("original request: expected Accept, got %+v", resp)
	}
}

// TestStateDeadlineIsStrict: a state can be claimed only strictly before its
// deadline; at exactly the deadline it is rejected without consuming.
func TestStateDeadlineIsStrict(t *testing.T) {
	clock := newFakeClock()
	var factorCalls atomic.Int32
	s := New(clock.Now,
		func(user, proof string) bool { return true },
		func(user, proof string) bool { factorCalls.Add(1); return true },
	)
	state := newChallenge(t, s, "nas1", "alice")
	req := Request{NAS: "nas1", Identifier: 2, RequestAuthenticator: auth(2), User: "alice", Proof: "otp", State: strPtr(state)}

	clock.Advance(119 * time.Second)
	if resp := s.Handle(req); resp.Kind != Accept {
		t.Fatalf("before deadline: expected Accept, got %+v", resp)
	}

	state2 := newChallenge(t, s, "nas1", "alice")
	req2 := req
	req2.Identifier = 3
	req2.RequestAuthenticator = auth(3)
	req2.State = strPtr(state2)
	clock.Advance(121 * time.Second) // now exactly at state2's deadline
	if resp := s.Handle(req2); resp.Kind != Reject {
		t.Fatalf("at deadline: expected Reject, got %+v", resp)
	}
	if got := factorCalls.Load(); got != 1 {
		t.Fatalf("ConsumeFactor called %d times, want 1 (deadline claim must not consume)", got)
	}
}

// TestCompletedResultExpires: a completed result is retained exactly 120s
// and is not renewed by retransmissions.
func TestCompletedResultExpires(t *testing.T) {
	clock := newFakeClock()
	var factorCalls atomic.Int32
	s := New(clock.Now,
		func(user, proof string) bool { return true },
		func(user, proof string) bool { factorCalls.Add(1); return true },
	)
	state := newChallenge(t, s, "nas1", "alice")
	req := Request{NAS: "nas1", Identifier: 2, RequestAuthenticator: auth(2), User: "alice", Proof: "otp", State: strPtr(state)}

	if resp := s.Handle(req); resp.Kind != Accept {
		t.Fatalf("expected Accept, got %+v", resp)
	}
	clock.Advance(60 * time.Second)
	if resp := s.Handle(req); resp.Kind != Accept {
		t.Fatalf("retained: expected Accept, got %+v", resp)
	}
	// Retransmission must not renew; 60s later the result has expired and
	// the state is already consumed, so the reprocessed request rejects.
	clock.Advance(60 * time.Second)
	if resp := s.Handle(req); resp.Kind != Reject {
		t.Fatalf("after expiry: expected Reject, got %+v", resp)
	}
	if got := factorCalls.Load(); got != 1 {
		t.Fatalf("ConsumeFactor called %d times, want 1", got)
	}
}

// TestSameIdentifierDifferentKeysNotMerged: requests sharing only the
// Identifier are independent.
func TestSameIdentifierDifferentKeysNotMerged(t *testing.T) {
	clock := newFakeClock()
	s := New(clock.Now,
		func(user, proof string) bool { return proof == "pw" },
		func(user, proof string) bool { return true },
	)
	r1 := s.Handle(Request{NAS: "nas1", Identifier: 5, RequestAuthenticator: auth(5), User: "alice", Proof: "pw"})
	r2 := s.Handle(Request{NAS: "nas2", Identifier: 5, RequestAuthenticator: auth(5), User: "alice", Proof: "bad"})
	if r1.Kind != Challenge || r2.Kind != Reject {
		t.Fatalf("keys merged by Identifier: got %+v and %+v", r1, r2)
	}
	if r1.State == "" {
		t.Fatal("expected non-empty state")
	}
}

// TestPasswordFailureRejects and retransmission shares the stored Reject.
func TestPasswordFailureRejects(t *testing.T) {
	clock := newFakeClock()
	var pwCalls atomic.Int32
	s := New(clock.Now,
		func(user, proof string) bool { pwCalls.Add(1); return false },
		func(user, proof string) bool { return true },
	)
	req := Request{NAS: "nas1", Identifier: 1, RequestAuthenticator: auth(1), User: "alice", Proof: "bad"}
	if resp := s.Handle(req); resp.Kind != Reject {
		t.Fatalf("expected Reject, got %+v", resp)
	}
	if resp := s.Handle(req); resp.Kind != Reject {
		t.Fatalf("retransmission: expected Reject, got %+v", resp)
	}
	if got := pwCalls.Load(); got != 1 {
		t.Fatalf("VerifyPassword called %d times, want 1", got)
	}
}

// TestSweepRemovesOnlyExpired: Sweep removes expired completed records and
// expired unclaimed states, but keeps live ones.
func TestSweepRemovesOnlyExpired(t *testing.T) {
	clock := newFakeClock()
	s := New(clock.Now,
		func(user, proof string) bool { return true },
		func(user, proof string) bool { return true },
	)
	state := newChallenge(t, s, "nas1", "alice")

	// Expired unclaimed state is swept; using it afterwards rejects.
	clock.Advance(120 * time.Second)
	s.Sweep()
	req := Request{NAS: "nas1", Identifier: 2, RequestAuthenticator: auth(2), User: "alice", Proof: "otp", State: strPtr(state)}
	if resp := s.Handle(req); resp.Kind != Reject {
		t.Fatalf("swept state: expected Reject, got %+v", resp)
	}

	// A fresh flow completes; its result survives a sweep before expiry and
	// is removed at expiry.
	state2 := newChallenge(t, s, "nas1", "alice")
	req2 := Request{NAS: "nas1", Identifier: 3, RequestAuthenticator: auth(3), User: "alice", Proof: "otp", State: strPtr(state2)}
	if resp := s.Handle(req2); resp.Kind != Accept {
		t.Fatalf("expected Accept, got %+v", resp)
	}
	clock.Advance(119 * time.Second)
	s.Sweep()
	if resp := s.Handle(req2); resp.Kind != Accept {
		t.Fatalf("sweep kept live result: expected Accept, got %+v", resp)
	}
	clock.Advance(1 * time.Second)
	s.Sweep()
	if resp := s.Handle(req2); resp.Kind != Reject {
		t.Fatalf("sweep removed expired result: expected Reject, got %+v", resp)
	}
}
