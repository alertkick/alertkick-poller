// Package leader implements active/passive leader election for a poller
// instance via a Mongo-backed lease held in apapi.
//
// One poller per location is "leader" at any moment — only the leader runs
// the dispatcher (Kafka consumer or HTTP puller) and submits results.
// Followers keep their heartbeat and health server running so the cluster
// can see both instances, but they don't do real check work.
//
// The Run loop reports transitions (leader ↔ follower) via a state channel
// so main.go can start and stop the worker goroutines cleanly, and exposes
// a snapshot of the current state via IsLeader() for the health server.
package leader

import (
	"alertkick-poller/client"
	"context"
	"errors"
	"log"
	"sync/atomic"
	"time"
)

// State is the poller's current role. Emitted on the State channel each
// time it changes so main.go can start/stop the per-role work.
type State int

const (
	StateFollower State = iota
	StateLeader
)

func (s State) String() string {
	if s == StateLeader {
		return "leader"
	}
	return "follower"
}

// Config tunes election behavior. Zero values mean "use defaults"; the
// intervals align with apapi's PollerLeaseTTL (30s) so the leader gets
// multiple chances to renew before the TTL elapses.
type Config struct {
	PollerUUID string
	// RenewInterval is how often the leader renews. Default: 10s.
	RenewInterval time.Duration
	// AcquireInterval is how often followers retry acquire. Default: 5s.
	AcquireInterval time.Duration
}

// Elector runs the election loop and publishes role transitions.
type Elector struct {
	cfg      Config
	client   *client.Client
	state    atomic.Int32 // State as int32 for atomic access from IsLeader
	stateCh  chan State
	term     atomic.Int64
}

// New returns an Elector ready to Run. The caller must read from State()
// to observe transitions, or the election will deadlock on the send.
func New(c *client.Client, cfg Config) *Elector {
	if cfg.RenewInterval == 0 {
		cfg.RenewInterval = 10 * time.Second
	}
	if cfg.AcquireInterval == 0 {
		cfg.AcquireInterval = 5 * time.Second
	}
	e := &Elector{
		cfg:     cfg,
		client:  c,
		stateCh: make(chan State, 4), // small buffer so fast flaps don't block
	}
	e.state.Store(int32(StateFollower))
	return e
}

// State returns the channel that emits role transitions. Exactly one value
// per transition; initial state (follower) is emitted when Run starts.
func (e *Elector) State() <-chan State {
	return e.stateCh
}

// IsLeader is a cheap snapshot — useful for health endpoints and for the
// heartbeat loop which needs to tag its status but doesn't want to block
// on channel reads.
func (e *Elector) IsLeader() bool {
	return State(e.state.Load()) == StateLeader
}

// Term returns the lease term last observed by this poller. Stable while
// we hold the lease; jumps when we take over (apapi increments on acquire).
func (e *Elector) Term() int64 {
	return e.term.Load()
}

// Run blocks until ctx is done. Emits follower on start, then transitions
// to leader when acquire succeeds, back to follower when renewal fails,
// etc. On ctx cancellation, tries a best-effort Release if we're leader.
func (e *Elector) Run(ctx context.Context) {
	e.stateCh <- StateFollower

	for {
		if ctx.Err() != nil {
			e.shutdown()
			return
		}

		if State(e.state.Load()) == StateLeader {
			// Leader path: renew at RenewInterval. If renewal fails, step
			// down and re-enter the follower branch on the next iteration.
			if !e.sleep(ctx, e.cfg.RenewInterval) {
				e.shutdown()
				return
			}
			resp, err := e.client.RenewLease(e.cfg.PollerUUID)
			if err != nil {
				if errors.Is(err, client.ErrLeaseConflict) {
					log.Printf("[leader] lost lease (taken over by %s term=%d); stepping down", resp.LeaderUUID, resp.Term)
				} else {
					log.Printf("[leader] renew failed: %v; stepping down", err)
				}
				e.setState(StateFollower)
				continue
			}
			e.term.Store(resp.Term)
			continue
		}

		// Follower path: retry acquire at AcquireInterval until we win.
		resp, err := e.client.AcquireLease(e.cfg.PollerUUID)
		if err == nil {
			log.Printf("[leader] acquired lease term=%d expires=%s", resp.Term, resp.ExpiresAt.Format(time.RFC3339))
			e.term.Store(resp.Term)
			e.setState(StateLeader)
			continue
		}
		if errors.Is(err, client.ErrLeaseConflict) {
			// Noisy on every poll — only log on change. Track last-seen
			// leader so we only emit when it differs.
			e.logIfChanged(resp.LeaderUUID, resp.Term)
		} else {
			log.Printf("[leader] acquire error (will retry): %v", err)
		}
		if !e.sleep(ctx, e.cfg.AcquireInterval) {
			e.shutdown()
			return
		}
	}
}

// setState transitions and publishes — no-op if already in the target
// state (defensive; shouldn't happen with the current call sites).
func (e *Elector) setState(s State) {
	prev := State(e.state.Swap(int32(s)))
	if prev == s {
		return
	}
	// Non-blocking send: if the consumer is slow we'd rather drop than stall
	// the election loop. The consumer reads IsLeader() on its own cadence as
	// a safety net.
	select {
	case e.stateCh <- s:
	default:
		log.Printf("[leader] state channel full; %s transition dropped (consumer will recover via IsLeader polling)", s)
	}
}

// shutdown is called once on ctx cancellation. Release is best-effort —
// if it fails the TTL still bounds the handoff.
func (e *Elector) shutdown() {
	if State(e.state.Load()) != StateLeader {
		return
	}
	if err := e.client.ReleaseLease(e.cfg.PollerUUID); err != nil {
		log.Printf("[leader] release on shutdown failed: %v", err)
		return
	}
	log.Printf("[leader] released lease on shutdown")
}

// lastSeenLeader is tracked in a small struct so "still following X" stays
// quiet in the logs across many acquire-retry polls.
var lastLog = struct {
	leaderUUID string
	term       int64
}{}

func (e *Elector) logIfChanged(leaderUUID string, term int64) {
	if lastLog.leaderUUID == leaderUUID && lastLog.term == term {
		return
	}
	lastLog.leaderUUID = leaderUUID
	lastLog.term = term
	log.Printf("[leader] following %s term=%d", leaderUUID, term)
}

// sleep returns false if ctx was canceled during the wait. Using a timer
// (not time.Sleep) so ctx cancellation cuts the wait short.
func (e *Elector) sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
