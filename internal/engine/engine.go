package engine

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/matinsenpai/senpaiscanner/internal/prober"
	"github.com/matinsenpai/senpaiscanner/internal/result"
)

// Config controls engine behaviour.
type Config struct {
	Concurrency    int
	RateLimit      float64 // probes per second, <=0 means unlimited
	ProbeConfig    prober.Config
	PipelineConfig PipelineConfig
}

// PipelineConfig enables a conservative staged scan that avoids expensive
// HTTP/download/WebSocket probes for candidates that fail quick discovery.
type PipelineConfig struct {
	Enabled           bool
	DiscoveryWorkers  int
	ValidationWorkers int
	SpeedWorkers      int
	CandidateLimit    int
}

// Stats exposes real-time counters.
type Stats struct {
	Tested   atomic.Int64
	Healthy  atomic.Int64
	Failed   atomic.Int64
	InFlight atomic.Int64
}

// ResultFunc is called for every completed probe result. It is invoked from
// worker goroutines, so implementations must be goroutine-safe.
type ResultFunc func(*result.Result)

// Engine orchestrates a pool of prober goroutines.
type Engine struct {
	cfg     Config
	stats   Stats
	limiter *rate.Limiter
}

// New creates a new Engine.
func New(cfg Config) *Engine {
	var lim *rate.Limiter
	if cfg.RateLimit > 0 {
		lim = rate.NewLimiter(rate.Limit(cfg.RateLimit), int(cfg.RateLimit)+1)
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 100
	}
	return &Engine{cfg: cfg, limiter: lim}
}

// Stats returns a pointer to the live statistics.
func (e *Engine) Stats() *Stats {
	return &e.stats
}

// Run consumes IPs from src, probes each one, and forwards results to fn.
// It blocks until src is exhausted or ctx is cancelled.
func (e *Engine) Run(ctx context.Context, src <-chan net.IP, fn ResultFunc) {
	if e.cfg.PipelineConfig.Enabled {
		e.RunStaged(ctx, src, fn)
		return
	}
	sem := make(chan struct{}, e.cfg.Concurrency)
	var wg sync.WaitGroup

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case ip, ok := <-src:
			if !ok {
				wg.Wait()
				return
			}

			if e.limiter != nil {
				if err := e.limiter.Wait(ctx); err != nil {
					wg.Wait()
					return
				}
			}

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Wait()
				return
			}
			e.stats.InFlight.Add(1)
			wg.Add(1)

			go func(ip net.IP) {
				defer func() {
					<-sem
					e.stats.InFlight.Add(-1)
					wg.Done()
				}()

				r := prober.Probe(ctx, ip, e.cfg.ProbeConfig)
				e.stats.Tested.Add(1)
				if r.IsHealthy() {
					e.stats.Healthy.Add(1)
				} else {
					e.stats.Failed.Add(1)
				}
				fn(r)
			}(ip)
		}
	}
}

// RunList probes a fixed slice of IPs (used in `senpaiscanner test`).
func (e *Engine) RunList(ctx context.Context, ips []net.IP, fn ResultFunc) {
	ch := make(chan net.IP, len(ips))
	for _, ip := range ips {
		ch <- ip
	}
	close(ch)

	// Raise the timeout floor for the final validation round so slow IPs
	// still get a fair chance rather than being cut off too early.
	cfg := e.cfg
	cfg.ProbeConfig.Timeout = max(cfg.ProbeConfig.Timeout, 10*time.Second)
	e2 := New(cfg)
	e2.Run(ctx, ch, fn)
}

// RunStaged probes in three conservative phases: quick TCP/TLS discovery,
// Cloudflare HTTP validation, then the original expensive probe for best
// candidates only. Direct scanning remains the default unless PipelineConfig is
// enabled.
func (e *Engine) RunStaged(ctx context.Context, src <-chan net.IP, fn ResultFunc) {
	pipe := e.cfg.PipelineConfig
	if pipe.DiscoveryWorkers <= 0 {
		pipe.DiscoveryWorkers = max(e.cfg.Concurrency, 1)
	}
	if pipe.ValidationWorkers <= 0 {
		pipe.ValidationWorkers = max(e.cfg.Concurrency/2, 1)
	}
	if pipe.SpeedWorkers <= 0 {
		pipe.SpeedWorkers = max(e.cfg.Concurrency/5, 1)
	}
	if pipe.CandidateLimit <= 0 {
		pipe.CandidateLimit = max(e.cfg.Concurrency*2, 50)
	}

	discoveryCfg := e.cfg.ProbeConfig
	discoveryCfg.Mode = prober.ModeTLS
	if e.cfg.ProbeConfig.Mode == prober.ModeTCP {
		discoveryCfg.Mode = prober.ModeTCP
	}
	discoveryCfg.Tries = 1
	discoveryCfg.SpeedBytes = 0
	discoveryCfg.RequireWebSocket = false
	discoveryCfg.Timeout = minDuration(nonZeroDuration(discoveryCfg.Timeout, 2*time.Second), 2*time.Second)

	validationCfg := e.cfg.ProbeConfig
	validationCfg.Mode = prober.ModeHTTP
	validationCfg.Tries = max(minInt(validationCfg.Tries, 2), 1)
	validationCfg.SpeedBytes = 0
	validationCfg.RequireWebSocket = false
	validationCfg.Timeout = minDuration(nonZeroDuration(validationCfg.Timeout, 4*time.Second), 4*time.Second)

	discovered := e.collectStage(ctx, src, pipe.DiscoveryWorkers, discoveryCfg)
	if ctx.Err() != nil || len(discovered) == 0 {
		return
	}
	discoveryCandidates := make([]*result.Result, 0, len(discovered))
	for _, r := range discovered {
		if r.Avg() > 0 && r.Loss() < 100 {
			discoveryCandidates = append(discoveryCandidates, r)
		}
	}
	if len(discoveryCandidates) == 0 {
		return
	}
	validationInput := makeIPChan(discoveryCandidates)
	validated := e.collectStage(ctx, validationInput, pipe.ValidationWorkers, validationCfg)
	if ctx.Err() != nil || len(validated) == 0 {
		return
	}

	var candidates []*result.Result
	for _, r := range validated {
		if r.IsHealthy() && r.Loss() < 50 && r.Avg() > 0 {
			candidates = append(candidates, r)
		}
	}
	result.Sort(candidates, result.SortByCleanScore)
	if len(candidates) > pipe.CandidateLimit {
		candidates = candidates[:pipe.CandidateLimit]
	}
	finalInput := makeIPChan(candidates)
	e.runStage(ctx, finalInput, pipe.SpeedWorkers, e.cfg.ProbeConfig, fn)
}

func (e *Engine) collectStage(ctx context.Context, src <-chan net.IP, workers int, cfg prober.Config) []*result.Result {
	var mu sync.Mutex
	var out []*result.Result
	e.runStage(ctx, src, workers, cfg, func(r *result.Result) {
		mu.Lock()
		out = append(out, r)
		mu.Unlock()
	})
	return out
}

func (e *Engine) runStage(ctx context.Context, src <-chan net.IP, workers int, cfg prober.Config, fn ResultFunc) {
	stageCfg := e.cfg
	stageCfg.Concurrency = workers
	stageCfg.PipelineConfig.Enabled = false
	stageCfg.ProbeConfig = cfg
	New(stageCfg).Run(ctx, src, func(r *result.Result) {
		e.stats.Tested.Add(1)
		if r.IsHealthy() {
			e.stats.Healthy.Add(1)
		} else {
			e.stats.Failed.Add(1)
		}
		fn(r)
	})
}

func makeIPChan(results []*result.Result) <-chan net.IP {
	ch := make(chan net.IP, len(results))
	for _, r := range results {
		ch <- r.IP
	}
	close(ch)
	return ch
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func nonZeroDuration(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
