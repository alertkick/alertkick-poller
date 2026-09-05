package checker

import (
	"crypto/tls"
	"net/http/httptrace"
	"sync"
	"time"
)

// httpTimings accumulates connection-phase durations for a single HTTP check
// via net/http/httptrace. Redirect hops that dial a new connection re-fire
// the callbacks, so DNS/connect/TLS times accumulate across hops; the first
// byte is overwritten per hop so it ends up anchored to the final response.
// Callbacks can fire concurrently (happy-eyeballs dials), hence the mutex.
type httpTimings struct {
	mu          sync.Mutex
	start       time.Time
	dnsStart    time.Time
	connStart   time.Time
	tlsStart    time.Time
	dnsMs       int64
	connectMs   int64
	tlsMs       int64
	firstByteMs int64
}

func newHTTPTimings() *httpTimings {
	return &httpTimings{start: time.Now()}
}

func (t *httpTimings) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			t.mu.Lock()
			t.dnsStart = time.Now()
			t.mu.Unlock()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			t.mu.Lock()
			if !t.dnsStart.IsZero() {
				t.dnsMs += time.Since(t.dnsStart).Milliseconds()
				t.dnsStart = time.Time{}
			}
			t.mu.Unlock()
		},
		ConnectStart: func(_, _ string) {
			t.mu.Lock()
			// Parallel happy-eyeballs dials: keep the earliest start.
			if t.connStart.IsZero() {
				t.connStart = time.Now()
			}
			t.mu.Unlock()
		},
		ConnectDone: func(_, _ string, err error) {
			t.mu.Lock()
			if err == nil && !t.connStart.IsZero() {
				t.connectMs += time.Since(t.connStart).Milliseconds()
				t.connStart = time.Time{}
			}
			t.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			t.mu.Lock()
			t.tlsStart = time.Now()
			t.mu.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			t.mu.Lock()
			if err == nil && !t.tlsStart.IsZero() {
				t.tlsMs += time.Since(t.tlsStart).Milliseconds()
				t.tlsStart = time.Time{}
			}
			t.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			t.mu.Lock()
			t.firstByteMs = time.Since(t.start).Milliseconds()
			t.mu.Unlock()
		},
	}
}

// details returns the phase timings as check-result details; total should
// span through reading the response body (the full load time).
func (t *httpTimings) details(total time.Duration) map[string]interface{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	return map[string]interface{}{
		"dns_time_ms":     t.dnsMs,
		"connect_time_ms": t.connectMs,
		"tls_time_ms":     t.tlsMs,
		"first_byte_ms":   t.firstByteMs,
		"total_time_ms":   total.Milliseconds(),
	}
}
