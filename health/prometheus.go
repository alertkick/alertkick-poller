package health

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
)

// Histogram is a fixed-bucket Prometheus histogram safe for concurrent
// Observe calls. Hand-rolled so the poller keeps zero metric dependencies —
// the render side of client_golang is the only part we'd use anyway.
type Histogram struct {
	bounds []float64 // upper bounds in ascending order, +Inf implied
	counts []atomic.Int64
	sumU   atomic.Uint64 // math.Float64bits-encoded sum, CAS-updated
	count  atomic.Int64
}

// NewHistogram creates a histogram with the given ascending upper bounds.
func NewHistogram(bounds ...float64) *Histogram {
	return &Histogram{
		bounds: bounds,
		counts: make([]atomic.Int64, len(bounds)+1), // +1 for +Inf
	}
}

// Observe records a value.
func (h *Histogram) Observe(v float64) {
	idx := len(h.bounds)
	for i, b := range h.bounds {
		if v <= b {
			idx = i
			break
		}
	}
	h.counts[idx].Add(1)
	h.count.Add(1)
	for {
		old := h.sumU.Load()
		nu := math.Float64bits(math.Float64frombits(old) + v)
		if h.sumU.CompareAndSwap(old, nu) {
			return
		}
	}
}

// write renders the histogram in Prometheus text format.
func (h *Histogram) write(w io.Writer, name string) {
	fmt.Fprintf(w, "# TYPE %s histogram\n", name)
	cumulative := int64(0)
	for i, b := range h.bounds {
		cumulative += h.counts[i].Load()
		fmt.Fprintf(w, "%s_bucket{le=%q} %d\n", name, formatFloat(b), cumulative)
	}
	cumulative += h.counts[len(h.bounds)].Load()
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, cumulative)
	fmt.Fprintf(w, "%s_sum %v\n", name, math.Float64frombits(h.sumU.Load()))
	fmt.Fprintf(w, "%s_count %d\n", name, h.count.Load())
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// writePrometheus renders every poller metric in Prometheus exposition
// format. Scraped by Alloy on the node and remote_written to
// VictoriaMetrics (Poller Health dashboard in Grafana).
func (s *Server) writePrometheus(w io.Writer) {
	writeGauge := func(name, help string, v float64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", name, help, name, name, v)
	}
	writeCounter := func(name, help string, v int64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}

	fmt.Fprintf(w, "# HELP poller_build_info Build metadata; value is always 1.\n# TYPE poller_build_info gauge\n")
	fmt.Fprintf(w, "poller_build_info{version=%q,git_hash=%q} 1\n",
		strings.TrimSpace(s.build.Version), strings.TrimSpace(s.build.GitHash))

	ready := 0.0
	if s.ready.Load() {
		ready = 1
	}
	writeGauge("poller_ready", "1 when the poller reports ready.", ready)
	writeGauge("poller_leader", "1 when this poller holds the location lease and executes checks.", float64(s.Leader.Load()))
	writeGauge("poller_uptime_seconds", "Seconds since process start.", float64(s.UptimeSeconds()))
	writeGauge("poller_last_beat_age_seconds", "Age of the core-loop liveness beacon; a growing value means the poller is wedged.", s.LastBeatAge().Seconds())
	writeGauge("poller_queue_depth", "Unsubmitted check results buffered in memory.", float64(s.QueueDepth.Load()))

	writeCounter("poller_checks_executed_total", "Monitor checks executed.", s.ChecksExecuted.Load())
	writeCounter("poller_check_errors_total", "Monitor checks that failed (monitor down or check error).", s.Errors.Load())
	writeCounter("poller_results_submitted_total", "Check results accepted by the result sink.", s.ResultsSubmitted.Load())
	writeCounter("poller_result_submit_errors_total", "Result batch submissions that failed and were requeued.", s.ResultSubmitErrors.Load())

	s.CheckDuration.write(w, "poller_check_duration_seconds")
	s.DispatchLag.write(w, "poller_check_dispatch_lag_seconds")
}
