package resultsink

import (
	"alertkick-poller/client"
	"context"
)

// HTTPResultSink wraps the existing SubmitResults call. Kept thin so the
// HTTP path is identical to its pre-refactor behaviour for on-prem pollers.
type HTTPResultSink struct {
	client *client.Client
}

func NewHTTPResultSink(c *client.Client) *HTTPResultSink {
	return &HTTPResultSink{client: c}
}

func (s *HTTPResultSink) Submit(_ context.Context, pollerUUID string, batch []client.CheckResult) (*SubmitStats, error) {
	resp, err := s.client.SubmitResults(pollerUUID, batch)
	if err != nil {
		return nil, err
	}
	return &SubmitStats{Accepted: resp.Accepted, Rejected: resp.Rejected}, nil
}

func (s *HTTPResultSink) Flush(_ context.Context) error { return nil }
func (s *HTTPResultSink) Close() error                  { return nil }
