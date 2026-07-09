// internal/agent/scheduler/cron.go
package scheduler

import (
	"sync"

	"github.com/robfig/cron/v3"
)

type Scheduler struct {
	cron   *cron.Cron
	mu     sync.Mutex
	jobs   map[string]cron.EntryID
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
