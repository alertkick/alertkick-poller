// Package dispatcher abstracts over the source of monitor assignments so the
// poller's worker pool doesn't care whether checks arrived via HTTP pull
// (customer on-prem) or Kafka consumer (managed fleet).
package dispatcher

import (
	"alertkick-poller/client"
	"context"
)

// Dispatcher produces monitor assignments for the executor pool.
// Implementations block in Run until ctx is canceled; they must not close
// the out channel (the caller owns it).
type Dispatcher interface {
	// Run consumes from the underlying source and pushes MonitorAssignments
	// to out. Returns when ctx is canceled or a fatal error occurs.
	Run(ctx context.Context, out chan<- *client.MonitorAssignment) error

	// Close releases any underlying transport resources. Safe to call after
	// Run returns; safe to call multiple times.
	Close() error
}
