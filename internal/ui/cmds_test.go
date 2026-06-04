package ui

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/config"
	"github.com/matinsenpai/senpaiscanner/internal/ipsrc"
	"github.com/matinsenpai/senpaiscanner/internal/prober"
	"github.com/matinsenpai/senpaiscanner/internal/result"
)

func TestConfigProbeFromURLUsesConfigPortSNIAndWebSocket(t *testing.T) {
	raw := "vless://3441b906-471f-4160-8f2c-a981793e6155@104.17.89.5:2087?encryption=none&security=tls&sni=winter-thunder-0638.matinsenpaivideo2.workers.dev&fp=chrome&insecure=0&allowInsecure=0&type=ws&host=winter-thunder-0638.matinsenpaivideo2.workers.dev&path=%2F#CF"

	cfg, err := configProbeFromURL(raw, 7*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Port != 2087 {
		t.Fatalf("port = %d, want 2087", cfg.Port)
	}
	if cfg.SNI != "winter-thunder-0638.matinsenpaivideo2.workers.dev" {
		t.Fatalf("SNI = %q", cfg.SNI)
	}
	if cfg.WebSocketHost != "winter-thunder-0638.matinsenpaivideo2.workers.dev" {
		t.Fatalf("WebSocketHost = %q", cfg.WebSocketHost)
	}
	if cfg.WebSocketPath != "/" {
		t.Fatalf("WebSocketPath = %q, want /", cfg.WebSocketPath)
	}
	if !cfg.RequireWebSocket {
		t.Fatal("RequireWebSocket = false, want true")
	}
}

func TestRunConfigPortProbesCompletesWhenNeighborsFillQueue(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}

	ips := make(chan net.IP, 1)
	ips <- net.ParseIP("192.0.2.32")
	close(ips)

	var callbacks atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConfigPortProbesWithProbe(
			context.Background(),
			ips,
			[]int{443},
			2,
			prober.Config{Port: 443, Mode: prober.ModeTCP},
			func(*result.Result) {
				callbacks.Add(1)
			},
			neighborScanOpts{
				enabled:  true,
				nets:     []*net.IPNet{ipNet},
				perHit:   64,
				maxTotal: 64,
			},
			func(_ context.Context, ip net.IP, cfg prober.Config) *result.Result {
				return &result.Result{
					IP:        ip,
					Port:      cfg.Port,
					ProbeMode: cfg.Mode.String(),
					Latencies: []time.Duration{time.Millisecond},
					Timestamp: time.Now(),
				}
			},
		)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runConfigPortProbes did not finish after queuing neighbor probes")
	}

	if got := callbacks.Load(); got != 65 {
		t.Fatalf("callbacks = %d, want 65 (1 seed + 64 neighbors)", got)
	}
}

func TestRunConfigPortProbesDeduplicatesSeedsAndRespectsExpansionLimit(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.0.2.0/24")
	ips := make(chan net.IP, 2)
	ips <- net.ParseIP("192.0.2.32")
	ips <- net.ParseIP("192.0.2.32")
	close(ips)
	var callbacks atomic.Int64
	runConfigPortProbesWithProbe(context.Background(), ips, []int{443}, 2, prober.Config{Port: 443, Mode: prober.ModeTCP}, func(*result.Result) { callbacks.Add(1) }, neighborScanOpts{enabled: true, nets: []*net.IPNet{ipNet}, perHit: 254, maxTotal: 10}, func(_ context.Context, ip net.IP, cfg prober.Config) *result.Result {
		return &result.Result{IP: ip, Port: cfg.Port, ProbeMode: "tcp", Latencies: []time.Duration{time.Millisecond}}
	})
	if got := callbacks.Load(); got != 11 {
		t.Fatalf("callbacks = %d, want one seed + 10 neighbors", got)
	}
}

func TestRunConfigPortProbesExpandsOnlyHealthyUnderThreshold(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.0.2.0/24")
	for _, latency := range []time.Duration{0, result.DefaultMaxPhase1AvgLatency + time.Millisecond} {
		ips := make(chan net.IP, 1)
		ips <- net.ParseIP("192.0.2.32")
		close(ips)
		var callbacks atomic.Int64
		runConfigPortProbesWithProbe(context.Background(), ips, []int{443}, 1, prober.Config{Port: 443, Mode: prober.ModeTCP}, func(*result.Result) { callbacks.Add(1) }, neighborScanOpts{enabled: true, nets: []*net.IPNet{ipNet}, perHit: 254, maxTotal: 10}, func(_ context.Context, ip net.IP, cfg prober.Config) *result.Result {
			return &result.Result{IP: ip, Port: cfg.Port, ProbeMode: "tcp", Latencies: []time.Duration{latency}}
		})
		if got := callbacks.Load(); got != 1 {
			t.Fatalf("latency %s callbacks = %d, want no expansion", latency, got)
		}
	}
}

func TestPrioritizedIPStreamQueuesPreviousGoodFirstAndDeduplicates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rest := make(chan net.IP, 2)
	rest <- net.ParseIP("104.24.72.1")
	rest <- net.ParseIP("104.24.72.2")
	close(rest)
	out := prioritizedIPStream(ctx, []net.IP{net.ParseIP("104.24.72.1")}, rest)
	var got []string
	for ip := range out {
		got = append(got, ip.String())
	}
	if len(got) != 2 || got[0] != "104.24.72.1" || got[1] != "104.24.72.2" {
		t.Fatalf("order = %v", got)
	}
}

func TestAdaptiveExpansionUsesOnlyTopFiveSeedsByDefault(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.0.0.0/16")
	ips := make(chan net.IP, 6)
	for i := 1; i <= 6; i++ {
		ips <- net.ParseIP(fmt.Sprintf("192.0.%d.32", i))
	}
	close(ips)
	var stats phase1DiscoveryStats
	runConfigPortProbesWithProbe(context.Background(), ips, []int{443}, 4, prober.Config{Port: 443, Mode: prober.ModeTCP}, func(*result.Result) {}, neighborScanOpts{enabled: true, nets: []*net.IPNet{ipNet}, onStats: func(s phase1DiscoveryStats) { stats = s }}, func(_ context.Context, ip net.IP, cfg prober.Config) *result.Result {
		return &result.Result{IP: ip, Port: cfg.Port, ProbeMode: "tcp", Latencies: []time.Duration{time.Millisecond}}
	})
	if stats.SeedsExpanded != ipsrc.DefaultNeighborSeedLimit {
		t.Fatalf("seeds expanded = %d", stats.SeedsExpanded)
	}
	if stats.NeighborQueued > ipsrc.DefaultNeighborSeedLimit*ipsrc.DefaultNeighborPerHit {
		t.Fatalf("neighbors queued = %d", stats.NeighborQueued)
	}
}

func TestSpeedTestCandidateLimitRespected(t *testing.T) {
	ips := make(chan net.IP, 120)
	for i := 1; i <= 120; i++ {
		ips <- net.ParseIP(fmt.Sprintf("192.0.2.%d", i))
	}
	close(ips)
	var speedCalls atomic.Int64
	var stats phase1DiscoveryStats
	runConfigPortProbesWithProbe(context.Background(), ips, []int{443}, 8, prober.Config{Port: 443, Mode: prober.ModeHTTP, SpeedBytes: config.SpeedTestBytes}, func(*result.Result) {}, neighborScanOpts{maxSpeedCandidates: config.MaxSpeedTestCandidates, onStats: func(s phase1DiscoveryStats) { stats = s }}, func(_ context.Context, ip net.IP, cfg prober.Config) *result.Result {
		return &result.Result{IP: ip, Port: cfg.Port, ProbeMode: "http", Latencies: []time.Duration{time.Millisecond}, TLSOk: true, HTTPStatus: 200, Colo: "FRA"}
	}, func(_ context.Context, r *result.Result, _ prober.Config, _ int64) {
		speedCalls.Add(1)
		r.SpeedTested = true
		r.Throughput = 1
	})
	if speedCalls.Load() != config.MaxSpeedTestCandidates || stats.SpeedTested != config.MaxSpeedTestCandidates {
		t.Fatalf("speed calls/stats = %d/%d", speedCalls.Load(), stats.SpeedTested)
	}
}

func TestCancellationStopsSpeedWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ips := make(chan net.IP, 20)
	for i := 1; i <= 20; i++ {
		ips <- net.ParseIP(fmt.Sprintf("192.0.2.%d", i))
	}
	close(ips)
	var calls atomic.Int64
	runConfigPortProbesWithProbe(ctx, ips, []int{443}, 2, prober.Config{Port: 443, Mode: prober.ModeHTTP, SpeedBytes: config.SpeedTestBytes}, func(*result.Result) {}, neighborScanOpts{maxSpeedCandidates: 20}, func(_ context.Context, ip net.IP, cfg prober.Config) *result.Result {
		return &result.Result{IP: ip, Port: cfg.Port, ProbeMode: "http", Latencies: []time.Duration{time.Millisecond}, TLSOk: true, HTTPStatus: 200, Colo: "FRA"}
	}, func(_ context.Context, _ *result.Result, _ prober.Config, _ int64) {
		if calls.Add(1) == 1 {
			cancel()
		}
	})
	if calls.Load() > 2 {
		t.Fatalf("speed work continued after cancellation: %d calls", calls.Load())
	}
}

func TestPreviousGoodExpansionRestrictedToEligibleSeeds(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.0.0.0/16")
	seed := net.ParseIP("192.0.2.32")
	ips := make(chan net.IP, 1)
	ips <- seed
	close(ips)
	var stats phase1DiscoveryStats
	runConfigPortProbesWithProbe(context.Background(), ips, []int{443}, 1, prober.Config{Port: 443, Mode: prober.ModeTCP}, func(*result.Result) {}, neighborScanOpts{enabled: true, nets: []*net.IPNet{ipNet}, previous: ipSet([]net.IP{seed}), previousExpandable: map[string]struct{}{}, onStats: func(s phase1DiscoveryStats) { stats = s }}, func(_ context.Context, ip net.IP, cfg prober.Config) *result.Result {
		return &result.Result{IP: ip, Port: cfg.Port, ProbeMode: "tcp", Latencies: []time.Duration{time.Millisecond}}
	})
	if stats.SeedsExpanded != 0 || stats.NeighborQueued != 0 {
		t.Fatalf("ineligible previous seed expanded: %+v", stats)
	}
}

func TestCancellationStopsExpansionWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	_, ipNet, _ := net.ParseCIDR("192.0.2.0/24")
	ips := make(chan net.IP, 1)
	ips <- net.ParseIP("192.0.2.32")
	close(ips)
	var calls atomic.Int64
	runConfigPortProbesWithProbe(ctx, ips, []int{443}, 2, prober.Config{Port: 443, Mode: prober.ModeTCP}, func(*result.Result) {}, neighborScanOpts{enabled: true, nets: []*net.IPNet{ipNet}, maxSeeds: 1, perHit: 64}, func(_ context.Context, ip net.IP, cfg prober.Config) *result.Result {
		if calls.Add(1) == 2 {
			cancel()
		}
		return &result.Result{IP: ip, Port: cfg.Port, ProbeMode: "tcp", Latencies: []time.Duration{time.Millisecond}}
	})
	if calls.Load() > 3 {
		t.Fatalf("expansion work continued after cancellation: %d calls", calls.Load())
	}
}
