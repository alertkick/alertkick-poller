package dispatcher

import (
	"alertkick-poller/client"
	"alertkick-poller/scheduler"
	"context"
	"log"
	"time"
)

// HTTPDispatcher is the customer-on-prem path: poll /poller/monitors on an
// interval, feed the scheduler, and emit due checks at 1Hz. Identical
// behaviour to the pre-refactor main loop.
type HTTPDispatcher struct {
	client         *client.Client
	sched          *scheduler.Scheduler
	pollInterval   time.Duration
	maxConcurrency int
	onQueueDepth   func(int) // optional: report due-queue depth to health server
}

// NewHTTPDispatcher builds a dispatcher that pulls monitors from apapi.
// onQueueDepth may be nil.
func NewHTTPDispatcher(
	c *client.Client,
	sched *scheduler.Scheduler,
	pollInterval time.Duration,
	maxConcurrency int,
	onQueueDepth func(int),
) *HTTPDispatcher {
	return &HTTPDispatcher{
		client:         c,
		sched:          sched,
		pollInterval:   pollInterval,
		maxConcurrency: maxConcurrency,
		onQueueDepth:   onQueueDepth,
	}
}

func (d *HTTPDispatcher) Run(ctx context.Context, out chan<- *client.MonitorAssignment) error {
	// Initial fetch so we start with a populated scheduler.
	if monitors, err := d.client.GetMonitors(); err != nil {
		log.Printf("[dispatcher/http] initial monitor fetch failed: %v", err)
	} else {
		d.sched.UpdateMonitors(monitors)
		log.Printf("[dispatcher/http] loaded %d monitors", len(monitors))
	}

	fetchTicker := time.NewTicker(d.pollInterval)
	defer fetchTicker.Stop()
	dueTicker := time.NewTicker(1 * time.Second)
	defer dueTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-fetchTicker.C:
			monitors, err := d.client.GetMonitors()
			if err != nil {
				log.Printf("[dispatcher/http] monitor fetch failed: %v", err)
				continue
			}
			d.sched.UpdateMonitors(monitors)
			log.Printf("[dispatcher/http] refreshed %d monitors", len(monitors))

		case <-dueTicker.C:
			due := d.sched.GetDueChecks(d.maxConcurrency)
			if d.onQueueDepth != nil {
				d.onQueueDepth(len(due))
			}
			now := time.Now()
			for _, m := range due {
				m.ReceivedAt = now
				select {
				case <-ctx.Done():
					return nil
				case out <- m:
				default:
					log.Printf("[dispatcher/http] check channel full, dropping check for %s", m.UUID)
				}
			}
		}
	}
}

// Close is a no-op for HTTP — the client has no persistent connection we own.
func (d *HTTPDispatcher) Close() error { return nil }
