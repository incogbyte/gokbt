package util

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type ProgressBar struct {
	total     int64
	current   int64
	successes int64
	startTime time.Time
	enabled   bool
	mu        sync.Mutex
	done      chan struct{}
	label     string
}

func NewProgressBar(total int64, enabled bool, label string) *ProgressBar {
	return &ProgressBar{
		total:     total,
		enabled:   enabled,
		done:      make(chan struct{}),
		label:     label,
		startTime: time.Now(),
	}
}

func (p *ProgressBar) Start() {
	if !p.enabled {
		return
	}
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-p.done:
				p.render(true)
				return
			case <-ticker.C:
				p.render(false)
			}
		}
	}()
}

func (p *ProgressBar) Increment() {
	atomic.AddInt64(&p.current, 1)
}

func (p *ProgressBar) IncrementSuccess() {
	atomic.AddInt64(&p.successes, 1)
}

func (p *ProgressBar) Stop() {
	if !p.enabled {
		return
	}
	close(p.done)
}

func (p *ProgressBar) render(final bool) {
	current := atomic.LoadInt64(&p.current)
	successes := atomic.LoadInt64(&p.successes)
	elapsed := time.Since(p.startTime)
	
	var pct float64
	if p.total > 0 {
		pct = float64(current) / float64(p.total) * 100
	}
	
	rate := float64(current) / elapsed.Seconds()
	if elapsed.Seconds() < 0.1 {
		rate = 0
	}
	
	var eta string
	if rate > 0 && p.total > 0 {
		remaining := float64(p.total-current) / rate
		eta = time.Duration(remaining * float64(time.Second)).Truncate(time.Second).String()
	} else {
		eta = "?"
	}
	
	barWidth := 30
	filled := int(pct / 100 * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}
	bar := ""
	for i := 0; i < barWidth; i++ {
		if i < filled {
			bar += "="
		} else {
			bar += "-"
		}
	}
	
	suffix := ""
	if final {
		suffix = "\n"
	} else {
		suffix = "\r"
	}
	
	fmt.Printf("\r%s [%s] %d/%d (%.1f%%) | %d found | %.1f/s | ETA: %s%s",
		p.label, bar, current, p.total, pct, successes, rate, eta, suffix)
}

