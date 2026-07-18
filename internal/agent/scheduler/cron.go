// internal/agent/scheduler/cron.go
package scheduler

import (
	"fmt"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

type Scheduler struct {
	cron *cron.Cron
	mu   sync.Mutex
	jobs map[string]cron.EntryID
}

// WithinWindow reports whether now is inside a local-time [start,end)
// execution window. A window crossing midnight, such as 22:00-06:00, is
// supported. Empty values are rejected so a configuration error cannot turn
// into an unexpected all-day backup window.
func WithinWindow(now time.Time, start, end string) (bool, error) {
	parse := func(value string) (int, error) {
		t, err := time.Parse("15:04", value)
		if err != nil {
			return 0, err
		}
		return t.Hour()*60 + t.Minute(), nil
	}
	startMinute, err := parse(start)
	if err != nil {
		return false, fmt.Errorf("parse window start: %w", err)
	}
	endMinute, err := parse(end)
	if err != nil {
		return false, fmt.Errorf("parse window end: %w", err)
	}
	if startMinute == endMinute {
		return false, fmt.Errorf("window start and end must differ")
	}
	minute := now.Hour()*60 + now.Minute()
	if startMinute < endMinute {
		return minute >= startMinute && minute < endMinute, nil
	}
	return minute >= startMinute || minute < endMinute, nil
}

type Job struct {
	Name     string
	Schedule string
	Fn       func()
}

func New() *Scheduler {
	return &Scheduler{
		cron: cron.New(cron.WithParser(cron.NewParser(
			cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow,
		))),
		jobs: make(map[string]cron.EntryID),
	}
}

func (s *Scheduler) AddJob(job Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := s.cron.AddFunc(job.Schedule, job.Fn)
	if err != nil {
		return err
	}
	s.jobs[job.Name] = id
	return nil
}

func (s *Scheduler) RemoveJob(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.jobs[name]; ok {
		s.cron.Remove(id)
		delete(s.jobs, name)
	}
}

func (s *Scheduler) Start() {
	s.cron.Start()
}

func (s *Scheduler) Stop() {
	s.cron.Stop()
}
