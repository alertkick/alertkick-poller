// Package resultsink abstracts over the transport that carries check results
// back to apapi. HTTP mode batches into a single POST; Kafka mode produces
// one record per result keyed by monitor UUID.
package resultsink

import (
	"alertkick-poller/client"
	"context"
)

// ResultSink delivers check results back to apapi.
// Submit returns a count of accepted/rejected results when the transport
// tells us (HTTP does; Kafka is fire-and-forget so accepted==len(batch)).
type ResultSink interface {
	// Submit ships a batch of results. On error the caller is expected to
	// requeue — sinks do not retry internally.
	Submit(ctx context.Context, pollerUUID string, batch []client.CheckResult) (*SubmitStats, error)

	// Flush forces any buffered writes out before shutdown. HTTP has no
	// internal buffer; Kafka's writer flushes pending async writes.
	Flush(ctx context.Context) error

	// Close releases transport resources. Safe to call multiple times.
	Close() error
}

// SubmitStats mirrors the HTTP response so the call site can log the same
// way regardless of transport.
type SubmitStats struct {
	Accepted int
	Rejected int
}
