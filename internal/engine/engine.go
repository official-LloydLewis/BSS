package engine

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/official-LloydLewis/SenPaiScanner/internal/prober"
	"github.com/official-LloydLewis/SenPaiScanner/internal/result"
)

// Config controls engine behaviour.
type Config struct {
	Concurrency      int
	RateLimit        float64 // probes per second, <=0 means unlimited
	StopAfterHealthy int     // cancel once this many healthy results are found; <=0 disables
	StopHealthyFunc  func(*result.Result) bool
	ProbeConfig      prober.Config
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

type cancelKey struct{}

// WithStopCancel attaches a cancel function that Engine can call when StopAfterHealthy is reached.
func WithStopCancel(ctx context.Context, cancel context.CancelFunc) context.Context {
	return context.WithValue(ctx, cancelKey{}, cancel)
}

// Engine orchestrates a pool of prober goroutines.
type Engine struct {
	cfg         Config
	stats       Stats
	stopHealthy atomic.Int64
	limiter     *rate.Limiter
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
					if e.shouldStopAfter(r) {
						if canceler, ok := ctx.Value(cancelKey{}).(context.CancelFunc); ok {
							canceler()
						}
					}
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
	originalTimeout := e.cfg.ProbeConfig.Timeout
	e.cfg.ProbeConfig.Timeout = max(e.cfg.ProbeConfig.Timeout, 10*time.Second)
	defer func() { e.cfg.ProbeConfig.Timeout = originalTimeout }()
	e.Run(ctx, ch, fn)
}

func (e *Engine) shouldStopAfter(r *result.Result) bool {
	if e.cfg.StopAfterHealthy <= 0 || !r.IsHealthy() {
		return false
	}
	if e.cfg.StopHealthyFunc != nil && !e.cfg.StopHealthyFunc(r) {
		return false
	}
	return e.stopHealthy.Add(1) >= int64(e.cfg.StopAfterHealthy)
}
