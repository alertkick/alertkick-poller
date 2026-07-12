package health

import (
	"strings"
	"testing"
)

func TestWritePrometheus(t *testing.T) {
	s := NewServer(0)
	s.SetBuild(BuildInfo{Service: "alertkick-poller", Version: "v1.1.1", GitHash: "abc123"})
	s.SetReady(true)
	s.Leader.Store(1)
	s.ChecksExecuted.Add(42)
	s.Errors.Add(3)
	s.ResultsSubmitted.Add(40)
	s.CheckDuration.Observe(0.2)
	s.CheckDuration.Observe(1.7)
	s.DispatchLag.Observe(0.4)
	var b strings.Builder
	s.writePrometheus(&b)
	out := b.String()
	for _, want := range []string{
		`poller_build_info{version="v1.1.1",git_hash="abc123"} 1`,
		"poller_ready 1",
		"poller_leader 1",
		"poller_checks_executed_total 42",
		"poller_check_errors_total 3",
		"poller_results_submitted_total 40",
		`poller_check_duration_seconds_bucket{le="0.25"} 1`,
		`poller_check_duration_seconds_bucket{le="2.5"} 2`,
		`poller_check_duration_seconds_bucket{le="+Inf"} 2`,
		"poller_check_duration_seconds_count 2",
		`poller_check_dispatch_lag_seconds_bucket{le="0.5"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}
