package radius2fa

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// manualClock is a controllable monotonic clock.
type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func newManualClock() *manualClock {
	return &manualClock{t: time.Unix(1_700_000_000, 0)}
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func req(nas string, id byte, user, proof string) Request {
	var ra [16]byte
	ra[0] = id
	return Request{NAS: nas, Identifier: id, RequestAuthenticator: ra, User: user, Proof: proof}
}

func withState(r Request, state []byte) Request {
	r.State = state
	return r
}

// challenge runs phase one and returns the issued state.
func challenge(t *testing.T, s *Server, r Request) []byte {
	t.Helper()
	res := s.Handle(r)
	if res.Result != Challenge {
		t.Fatalf("phase1: got %v, want Challenge", res.Result)
	}
	if len(res.State) == 0 {
		t.Fatal("phase1: empty state")
	}
	return res.State
}

// TestConcurrentPhase2Retransmission covers the required scenario:
// concurrent retransmissions of the same second-phase request block
// while the factor callback is held, survive Sweep past the state
// deadline, and all share the single Accept result.
func TestConcurrentPhase2Retransmission(t *testing.T) {
	clock := newManualClock()
	entered := make(chan struct{})
	release := make(chan struct{})
	var factorCalls atomic.Int32

	s := New(clock,
		func(user, proof string) bool { return true },
		func(user, proof string) bool {
			factorCalls.Add(1)
			close(entered) // factor consumed, callback not yet returned
			<-release
			return true
		})

	state := challenge(t, s, req("nas1", 1, "alice", "pw"))
	phase2 := withState(req("nas1", 2, "alice", "123456"), state)

	const n = 5
	results := make([]Response, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = s.Handle(phase2)
		}(i)
	}

	<-entered // first request is inside the blocked callback

	// State deadline passes while verification is in flight.
	clock.Advance(121 * time.Second)
	s.Sweep() // must not drop the pending request or duplicate execution

	close(release)
	wg.Wait()

	for i, res := range results {
		if res.Result != Accept {
			t.Fatalf("retransmission %d: got %v, want Accept", i, res.Result)
		}
	}
	if got := factorCalls.Load(); got != 1 {
		t.Fatalf("ConsumeFactor called %d times, want 1", got)
	}

	// Completed 121s after start: result retained 120s from completion.
	again := s.Handle(phase2)
	if again.Result != Accept {
		t.Fatalf("post-completion retransmission: got %v, want Accept", again.Result)
	}
	if got := factorCalls.Load(); got != 1 {
		t.Fatalf("ConsumeFactor called %d times after replay, want 1", got)
	}
}

// TestStateClaimRace covers the required scenario: two different
// request keys race for one State while a wrong-NAS request mixes in;
// at most one valid request runs ConsumeFactor and the wrong NAS
// cannot steal the State.
func TestStateClaimRace(t *testing.T) {
	clock := newManualClock()
	entered := make(chan struct{})
	release := make(chan struct{})
	var factorCalls atomic.Int32

	s := New(clock,
		func(user, proof string) bool { return true },
		func(user, proof string) bool {
			factorCalls.Add(1)
			close(entered)
			<-release
			return true
		})

	state := challenge(t, s, req("nas1", 1, "alice", "pw"))

	// Wrong NAS first: must reject and must not consume the State.
	badNAS := withState(req("evil-nas", 9, "alice", "123456"), state)
	if res := s.Handle(badNAS); res.Result != Reject {
		t.Fatalf("wrong NAS: got %v, want Reject", res.Result)
	}
	if got := factorCalls.Load(); got != 0 {
		t.Fatalf("wrong NAS consumed factor: calls=%d", got)
	}

	// Two distinct valid keys race for the same State.
	keyA := withState(req("nas1", 2, "alice", "123456"), state)
	keyB := withState(req("nas1", 3, "alice", "123456"), state)

	resA := make(chan Response, 1)
	resB := make(chan Response, 1)
	go func() { resA <- s.Handle(keyA) }()
	go func() { resB <- s.Handle(keyB) }()

	<-entered // exactly one claimer reached the callback
	close(release)

	a, b := <-resA, <-resB
	accepts := 0
	if a.Result == Accept {
		accepts++
	}
	if b.Result == Accept {
		accepts++
	}
	if accepts != 1 {
		t.Fatalf("accepts=%d (A=%v B=%v), want exactly 1", accepts, a.Result, b.Result)
	}
	if got := factorCalls.Load(); got != 1 {
		t.Fatalf("ConsumeFactor called %d times, want 1", got)
	}

	// The State is consumed: any other key using it rejects.
	late := withState(req("nas1", 4, "alice", "123456"), state)
	if res := s.Handle(late); res.Result != Reject {
		t.Fatalf("late key with consumed state: got %v, want Reject", res.Result)
	}
}

func TestPasswordFailureRejects(t *testing.T) {
	clock := newManualClock()
	s := New(clock,
		func(user, proof string) bool { return false },
		func(user, proof string) bool { t.Fatal("factor must not run"); return false })

	if res := s.Handle(req("nas1", 1, "alice", "bad")); res.Result != Reject {
		t.Fatalf("got %v, want Reject", res.Result)
	}
}

func TestPhase1RetransmissionSharesChallenge(t *testing.T) {
	clock := newManualClock()
	var verifyCalls atomic.Int32
	s := New(clock,
		func(user, proof string) bool { verifyCalls.Add(1); return true },
		func(user, proof string) bool { return true })

	r := req("nas1", 1, "alice", "pw")
	first := challenge(t, s, r)
	second := challenge(t, s, r)
	if !bytes.Equal(first, second) {
		t.Fatal("retransmission must replay the same State")
	}
	if got := verifyCalls.Load(); got != 1 {
		t.Fatalf("VerifyPassword called %d times, want 1", got)
	}
}

func TestSameKeyDifferentPayloadRejects(t *testing.T) {
	clock := newManualClock()
	entered := make(chan struct{})
	release := make(chan struct{})
	s := New(clock,
		func(user, proof string) bool { close(entered); <-release; return true },
		func(user, proof string) bool { return true })

	orig := req("nas1", 1, "alice", "pw")
	done := make(chan Response, 1)
	go func() { done <- s.Handle(orig) }()
	<-entered

	// Same key, different proof: immediate Reject, no waiting.
	conflict := req("nas1", 1, "alice", "other")
	if res := s.Handle(conflict); res.Result != Reject {
		t.Fatalf("conflicting payload: got %v, want Reject", res.Result)
	}

	close(release)
	if res := <-done; res.Result != Challenge {
		t.Fatalf("original request: got %v, want Challenge", res.Result)
	}
}

func TestStateExpiresAtDeadline(t *testing.T) {
	clock := newManualClock()
	var factorCalls atomic.Int32
	s := New(clock,
		func(user, proof string) bool { return true },
		func(user, proof string) bool { factorCalls.Add(1); return true })

	state := challenge(t, s, req("nas1", 1, "alice", "pw"))

	clock.Advance(119 * time.Second)
	ok := withState(req("nas1", 2, "alice", "123456"), state)
	if res := s.Handle(ok); res.Result != Accept {
		t.Fatalf("before deadline: got %v, want Accept", res.Result)
	}

	state2 := challenge(t, s, req("nas1", 3, "alice", "pw"))
	clock.Advance(120 * time.Second) // exactly at deadline: expired
	late := withState(req("nas1", 4, "alice", "123456"), state2)
	if res := s.Handle(late); res.Result != Reject {
		t.Fatalf("at deadline: got %v, want Reject", res.Result)
	}
	if got := factorCalls.Load(); got != 1 {
		t.Fatalf("ConsumeFactor called %d times, want 1", got)
	}
}

func TestStateBindingEnforced(t *testing.T) {
	clock := newManualClock()
	var factorCalls atomic.Int32
	s := New(clock,
		func(user, proof string) bool { return true },
		func(user, proof string) bool { factorCalls.Add(1); return true })

	state := challenge(t, s, req("nas1", 1, "alice", "pw"))

	wrongUser := withState(req("nas1", 2, "bob", "123456"), state)
	if res := s.Handle(wrongUser); res.Result != Reject {
		t.Fatalf("wrong user: got %v, want Reject", res.Result)
	}
	wrongNAS := withState(req("nas2", 3, "alice", "123456"), state)
	if res := s.Handle(wrongNAS); res.Result != Reject {
		t.Fatalf("wrong NAS: got %v, want Reject", res.Result)
	}
	if got := factorCalls.Load(); got != 0 {
		t.Fatalf("bad bindings consumed factor: calls=%d", got)
	}

	// Failed claims must not consume the State.
	good := withState(req("nas1", 4, "alice", "123456"), state)
	if res := s.Handle(good); res.Result != Accept {
		t.Fatalf("correct binding: got %v, want Accept", res.Result)
	}
}

func TestFailedFactorConsumesState(t *testing.T) {
	clock := newManualClock()
	s := New(clock,
		func(user, proof string) bool { return true },
		func(user, proof string) bool { return false })

	state := challenge(t, s, req("nas1", 1, "alice", "pw"))
	first := withState(req("nas1", 2, "alice", "000000"), state)
	if res := s.Handle(first); res.Result != Reject {
		t.Fatalf("bad factor: got %v, want Reject", res.Result)
	}
	// State consumed despite failure: a new key cannot reuse it.
	second := withState(req("nas1", 3, "alice", "123456"), state)
	if res := s.Handle(second); res.Result != Reject {
		t.Fatalf("reuse after failed factor: got %v, want Reject", res.Result)
	}
}

func TestCompletedResultExpiresWithoutSweep(t *testing.T) {
	clock := newManualClock()
	var factorCalls atomic.Int32
	s := New(clock,
		func(user, proof string) bool { return true },
		func(user, proof string) bool { factorCalls.Add(1); return true })

	state := challenge(t, s, req("nas1", 1, "alice", "pw"))
	phase2 := withState(req("nas1", 2, "alice", "123456"), state)
	if res := s.Handle(phase2); res.Result != Accept {
		t.Fatalf("got %v, want Accept", res.Result)
	}

	clock.Advance(119 * time.Second)
	if res := s.Handle(phase2); res.Result != Accept {
		t.Fatalf("within retention: got %v, want Accept", res.Result)
	}
	if got := factorCalls.Load(); got != 1 {
		t.Fatalf("replay re-ran factor: calls=%d", got)
	}

	// Retransmission does not renew retention; Handle enforces
	// expiry on its own, and the consumed State rejects reprocessing.
	clock.Advance(1 * time.Second)
	if res := s.Handle(phase2); res.Result != Reject {
		t.Fatalf("after retention: got %v, want Reject", res.Result)
	}
	if got := factorCalls.Load(); got != 1 {
		t.Fatalf("expired record re-ran factor: calls=%d", got)
	}
}

func TestSweepRemovesOnlyExpired(t *testing.T) {
	clock := newManualClock()
	s := New(clock,
		func(user, proof string) bool { return true },
		func(user, proof string) bool { return true })

	state := challenge(t, s, req("nas1", 1, "alice", "pw"))
	phase2 := withState(req("nas1", 2, "alice", "123456"), state)
	s.Handle(phase2)

	clock.Advance(120 * time.Second)
	s.Sweep()

	s.mu.Lock()
	remaining := len(s.records)
	statesLeft := len(s.states)
	s.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("Sweep left %d records, want 0", remaining)
	}
	if statesLeft != 0 {
		t.Fatalf("Sweep left %d states, want 0", statesLeft)
	}
}
