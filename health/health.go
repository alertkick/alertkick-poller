// Package health exposes the poller's HTTP health surface:
//
//   /livez   200 if process alive (no deps probed)
//   /readyz  200 if all configured deps are reachable, 503 + JSON
//            details otherwise
//   /healthz always 200 with rich JSON: status, version, uptime,
//            per-dep latency, internal counters
//   /version build metadata only — same JSON shape every alertkick
//            service exposes so the api can fan in via /api/v1/versions
//   /metrics legacy JSON metrics (uptime + counters); kept for the
//            apapi heartbeat path that still consumes it
//   /ready   legacy boolean readiness gate (kept for back-compat)
//
// Probes are inline rather than registry-based — the poller has at most
// two deps (api + kafka brokers when in kafka mode) so a registry would
// be overkill here. Each probe runs with a 1s deadline.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// BuildInfo is the static build metadata baked into the binary at link
// time. Set once at startup via SetBuild before Start.
type BuildInfo struct {
	Service   string `json:"service"`
	Version   string `json:"version"`
	GitHash   string `json:"git_hash,omitempty"`
	GitBranch string `json:"git_branch,omitempty"`
	BuildTime string `json:"build_time,omitempty"`
}

// Server provides health and readiness endpoints.
type Server struct {
	port      int
	startedAt time.Time
	ready     atomic.Bool

	build   BuildInfo
	apiURL  string   // optional — empty disables api probe
	brokers []string // optional — empty disables kafka probe

	// Metrics exposed via /metrics
	ChecksExecuted     atomic.Int64
	ChecksPerMinute    atomic.Int64
	Errors             atomic.Int64
	QueueDepth         atomic.Int64
	AvgCheckDurationMs atomic.Int64
}

// NewServer creates a new health server.
func NewServer(port int) *Server {
	s := &Server{
		port:      port,
		startedAt: time.Now().UTC(),
	}
	return s
}

// SetBuild stores the build metadata served by /version, /livez, etc.
func (s *Server) SetBuild(b BuildInfo) { s.build = b }

// SetProbeTargets configures which deps /readyz checks. Pass apiURL=""
// to skip the api probe; pass brokers=nil to skip the kafka probe.
func (s *Server) SetProbeTargets(apiURL string, brokers []string) {
	s.apiURL = apiURL
	s.brokers = brokers
}

// SetReady marks the poller as ready to serve.
func (s *Server) SetReady(ready bool) {
	s.ready.Store(ready)
}

// UptimeSeconds returns the poller uptime in seconds.
func (s *Server) UptimeSeconds() int64 {
	return int64(time.Since(s.startedAt).Seconds())
}

// Start starts the health HTTP server in a goroutine.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", s.handleReady)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/livez", s.handleLivez)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/version", s.handleVersion)

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("[health] listening on %s", addr)

	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("[health] server error: %v", err)
		}
	}()
}

// --- Legacy back-compat handlers ---

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.ready.Load() {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "not ready")
	}
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"uptime_seconds":       s.UptimeSeconds(),
		"ready":                s.ready.Load(),
		"checks_executed":      s.ChecksExecuted.Load(),
		"checks_per_minute":    s.ChecksPerMinute.Load(),
		"errors":               s.Errors.Load(),
		"queue_depth":          s.QueueDepth.Load(),
		"avg_check_duration_ms": s.AvgCheckDurationMs.Load(),
	})
}

// --- New standardized handlers ---

func (s *Server) handleLivez(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"service":    s.build.Service,
		"version":    s.build.Version,
		"build_time": s.build.BuildTime,
	})
}

type checkResult struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
}

func (s *Server) runProbes(ctx context.Context) []checkResult {
	var results []checkResult
	if s.apiURL != "" {
		results = append(results, runProbe(ctx, "api", func(c context.Context) error {
			return httpProbe(c, strings.TrimRight(s.apiURL, "/")+"/livez")
		}))
	}
	for _, b := range s.brokers {
		results = append(results, runProbe(ctx, "kafka:"+b, func(c context.Context) error {
			return tcpProbe(c, b)
		}))
		break // one broker is enough; cluster is reachable if any peer answers
	}
	return results
}

func runProbe(ctx context.Context, name string, fn func(context.Context) error) checkResult {
	pctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	start := time.Now()
	err := fn(pctx)
	res := checkResult{Name: name, LatencyMs: time.Since(start).Milliseconds()}
	if err != nil {
		res.Status = "fail"
		res.Error = err.Error()
	} else {
		res.Status = "ok"
	}
	return res
}

func httpProbe(ctx context.Context, raw string) error {
	if _, err := url.Parse(raw); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func tcpProbe(ctx context.Context, addr string) error {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	results := s.runProbes(r.Context())
	ok := s.ready.Load()
	for _, c := range results {
		if c.Status != "ok" {
			ok = false
		}
	}
	status := "ok"
	code := http.StatusOK
	if !ok {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{
		"status":  status,
		"service": s.build.Service,
		"version": s.build.Version,
		"checks":  results,
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	results := s.runProbes(r.Context())
	status := "ok"
	for _, c := range results {
		if c.Status != "ok" {
			status = "degraded"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":              status,
		"service":             s.build.Service,
		"version":             s.build.Version,
		"git_hash":            s.build.GitHash,
		"git_branch":          s.build.GitBranch,
		"build_time":          s.build.BuildTime,
		"uptime":              time.Since(s.startedAt).Round(time.Second).String(),
		"checks":              results,
		"checks_executed":     s.ChecksExecuted.Load(),
		"errors":              s.Errors.Load(),
		"queue_depth":         s.QueueDepth.Load(),
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.build)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
