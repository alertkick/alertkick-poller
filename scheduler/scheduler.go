package scheduler

import (
	"alertkick-poller/client"
	"sync"
	"time"
)

// CheckJob represents a scheduled check to execute.
type CheckJob struct {
	Monitor    *client.MonitorAssignment
	NextCheckAt time.Time
}

// Scheduler manages the internal check schedule.
// It maintains a list of monitors and tracks when each should next be checked.
type Scheduler struct {
	mu       sync.RWMutex
	monitors map[string]*CheckJob // keyed by monitor UUID
}

// NewScheduler creates a new scheduler.
func NewScheduler() *Scheduler {
	return &Scheduler{
		monitors: make(map[string]*CheckJob),
	}
}

// UpdateMonitors replaces the full set of monitors from the API.
// New monitors get an immediate first check; existing monitors keep their schedule.
func (s *Scheduler) UpdateMonitors(monitors []client.MonitorAssignment) {
	s.mu.Lock()
	defer s.mu.Unlock()

	newSet := make(map[string]*CheckJob, len(monitors))

	for i := range monitors {
		m := &monitors[i]
		if existing, ok := s.monitors[m.UUID]; ok {
			// Keep existing schedule
			existing.Monitor = m
			newSet[m.UUID] = existing
		} else {
			// New monitor: schedule first check immediately
			newSet[m.UUID] = &CheckJob{
				Monitor:     m,
				NextCheckAt: time.Now().UTC(),
			}
		}
	}

	s.monitors = newSet
}

// GetDueChecks returns monitors that are due for checking and marks them as scheduled.
func (s *Scheduler) GetDueChecks(maxBatch int) []*client.MonitorAssignment {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	due := make([]*client.MonitorAssignment, 0)

	for _, job := range s.monitors {
		if job.NextCheckAt.Before(now) || job.NextCheckAt.Equal(now) {
			due = append(due, job.Monitor)

			// Schedule next check
			interval := time.Duration(job.Monitor.CheckIntervalSeconds) * time.Second
			if interval == 0 {
				interval = 60 * time.Second
			}
			job.NextCheckAt = now.Add(interval)

			if len(due) >= maxBatch {
				break
			}
		}
	}

	return due
}

// MonitorCount returns the number of tracked monitors.
func (s *Scheduler) MonitorCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.monitors)
}
