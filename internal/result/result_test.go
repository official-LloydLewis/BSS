package result

import (
	"net"
	"testing"
	"time"
)

func makeResult(latencies []time.Duration) *Result {
	return &Result{
		IP:        net.ParseIP("1.1.1.1"),
		Port:      443,
		Latencies: latencies,
		TLSOk:     true,
	}
}

func TestLoss(t *testing.T) {
	r := makeResult([]time.Duration{100 * time.Millisecond, 0, 100 * time.Millisecond, 0})
	if got := r.Loss(); got != 50.0 {
		t.Errorf("Loss() = %v, want 50.0", got)
	}
}

func TestLossAllFailed(t *testing.T) {
	r := makeResult([]time.Duration{0, 0, 0})
	if r.Loss() != 100.0 {
		t.Errorf("expected 100%% loss, got %.1f", r.Loss())
	}
	if r.IsHealthy() {
		t.Error("expected unhealthy result")
	}
}

func TestAvg(t *testing.T) {
	r := makeResult([]time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 0})
	avg := r.Avg()
	if avg != 150*time.Millisecond {
		t.Errorf("Avg() = %v, want 150ms", avg)
	}
}

func TestMinMax(t *testing.T) {
	r := makeResult([]time.Duration{50 * time.Millisecond, 200 * time.Millisecond, 80 * time.Millisecond})
	if r.Min() != 50*time.Millisecond {
		t.Errorf("Min() = %v, want 50ms", r.Min())
	}
	if r.Max() != 200*time.Millisecond {
		t.Errorf("Max() = %v, want 200ms", r.Max())
	}
}

func TestJitter(t *testing.T) {
	r := makeResult([]time.Duration{100 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond})
	if r.Jitter() != 0 {
		t.Errorf("Jitter() with identical samples = %v, want 0", r.Jitter())
	}
}

func TestSort(t *testing.T) {
	results := []*Result{
		{IP: net.ParseIP("1.1.1.1"), Latencies: []time.Duration{200 * time.Millisecond}},
		{IP: net.ParseIP("1.1.1.2"), Latencies: []time.Duration{50 * time.Millisecond}},
		{IP: net.ParseIP("1.1.1.3"), Latencies: []time.Duration{100 * time.Millisecond}},
	}
	Sort(results, SortByAvg)
	if results[0].IP.String() != "1.1.1.2" {
		t.Errorf("first result after sort = %s, want 1.1.1.2", results[0].IP)
	}
}

func TestTopN(t *testing.T) {
	results := []*Result{
		{IP: net.ParseIP("1.1.1.1"), Latencies: []time.Duration{200 * time.Millisecond}, TLSOk: true},
		{IP: net.ParseIP("1.1.1.2"), Latencies: []time.Duration{50 * time.Millisecond}, TLSOk: true},
		{IP: net.ParseIP("1.1.1.3"), Latencies: []time.Duration{0}}, // unhealthy
		{IP: net.ParseIP("1.1.1.4"), Latencies: []time.Duration{100 * time.Millisecond}, TLSOk: true},
	}
	top := TopN(results, 2)
	if len(top) != 2 {
		t.Errorf("TopN(2) returned %d results, want 2", len(top))
	}
	if top[0].IP.String() != "1.1.1.2" {
		t.Errorf("best result = %s, want 1.1.1.2", top[0].IP)
	}
}

func TestHTTPHealthRequiresCloudflareValidation(t *testing.T) {
	r := makeResult([]time.Duration{100 * time.Millisecond, 120 * time.Millisecond})
	r.ProbeMode = "http"
	r.HTTPStatus = 200
	r.TLSOk = true

	if r.IsHealthy() {
		t.Fatal("expected HTTP result without colo to be unhealthy")
	}

	r.Colo = "FRA"
	if !r.IsHealthy() {
		t.Fatal("expected validated HTTP result to be healthy")
	}

	r.SpeedTested = true
	if r.IsHealthy() {
		t.Fatal("expected speed-tested result with zero throughput to be unhealthy")
	}

	r.Throughput = 256 * 1024
	if !r.IsHealthy() {
		t.Fatal("expected speed-tested result with throughput to be healthy")
	}
}

func TestHTTPHealthRequiresTLSOnNonPlainHTTPPorts(t *testing.T) {
	r := makeResult([]time.Duration{100 * time.Millisecond})
	r.ProbeMode = "http"
	r.Port = 2087
	r.TLSOk = false
	r.HTTPStatus = 200
	r.Colo = "FRA"

	if r.IsHealthy() {
		t.Fatal("expected HTTPS-style port without TLS to be unhealthy")
	}
}

func TestHTTPHealthRequiresWebSocketWhenConfigured(t *testing.T) {
	r := makeResult([]time.Duration{100 * time.Millisecond})
	r.ProbeMode = "http"
	r.HTTPStatus = 200
	r.Colo = "FRA"
	r.RequireWS = true

	if r.IsHealthy() {
		t.Fatal("expected required websocket failure to be unhealthy")
	}

	r.WSOk = true
	if !r.IsHealthy() {
		t.Fatal("expected required websocket success to be healthy")
	}
}

func TestHTTPTimeoutIsNotHealthy(t *testing.T) {
	// Simulates the bug: all tries time out (latency 0) or previously recorded 3s.
	r := &Result{
		IP:          net.ParseIP("1.1.1.1"),
		ProbeMode:   "http",
		Latencies:   []time.Duration{0, 0, 0, 0},
		SpeedTested: true,
	}
	if r.IsHealthy() {
		t.Fatal("expected all-failed HTTP probe to be unhealthy")
	}
}

func TestTLSRequiresHandshake(t *testing.T) {
	r := makeResult([]time.Duration{100 * time.Millisecond})
	r.ProbeMode = "tls"
	r.TLSOk = false
	if r.IsHealthy() {
		t.Fatal("expected TLS result without handshake to be unhealthy")
	}
	r.TLSOk = true
	if !r.IsHealthy() {
		t.Fatal("expected TLS handshake success to be healthy")
	}
}

func TestSortBySpeed(t *testing.T) {
	results := []*Result{
		{IP: net.ParseIP("1.1.1.1"), Latencies: []time.Duration{80 * time.Millisecond}, Throughput: 100 * 1024},
		{IP: net.ParseIP("1.1.1.2"), Latencies: []time.Duration{90 * time.Millisecond}, Throughput: 900 * 1024},
	}

	Sort(results, SortBySpeed)
	if results[0].IP.String() != "1.1.1.2" {
		t.Errorf("first result after speed sort = %s, want 1.1.1.2", results[0].IP)
	}
}

func TestSortByJitterPrefersHealthyResults(t *testing.T) {
	results := []*Result{
		{IP: net.ParseIP("1.1.1.1"), Latencies: []time.Duration{0, 0, 0, 0}},
		{IP: net.ParseIP("1.1.1.2"), Latencies: []time.Duration{90 * time.Millisecond, 100 * time.Millisecond, 110 * time.Millisecond}, TLSOk: true},
	}

	Sort(results, SortByJitter)
	if results[0].IP.String() != "1.1.1.2" {
		t.Fatalf("first result after jitter sort = %s, want 1.1.1.2", results[0].IP)
	}
}

func TestSortByLossPrefersPartialOverTotalFailure(t *testing.T) {
	results := []*Result{
		{IP: net.ParseIP("1.1.1.1"), Latencies: []time.Duration{0, 0, 0, 0}},
		{IP: net.ParseIP("1.1.1.2"), Latencies: []time.Duration{100 * time.Millisecond, 0, 120 * time.Millisecond, 0}, TLSOk: true},
	}

	Sort(results, SortByLoss)
	if results[0].IP.String() != "1.1.1.2" {
		t.Fatalf("first result after loss sort = %s, want 1.1.1.2", results[0].IP)
	}
}

func TestSortBySpeedKeepsHealthyResultsAheadOfUntestedFailures(t *testing.T) {
	results := []*Result{
		{IP: net.ParseIP("1.1.1.1"), Latencies: []time.Duration{0, 0, 0}, Throughput: 0},
		{IP: net.ParseIP("1.1.1.2"), Latencies: []time.Duration{80 * time.Millisecond}, Throughput: 100 * 1024, TLSOk: true},
	}

	Sort(results, SortBySpeed)
	if results[0].IP.String() != "1.1.1.2" {
		t.Fatalf("first result after speed sort = %s, want 1.1.1.2", results[0].IP)
	}
}

func TestQualityScoreOrdering(t *testing.T) {
	base := Result{
		IP:         net.ParseIP("1.1.1.1"),
		Port:       443,
		ProbeMode:  "http",
		Latencies:  []time.Duration{100 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond},
		Throughput: 256 * 1024,
	}

	tests := []struct {
		name   string
		better Result
		worse  Result
	}{
		{
			name:   "lower loss",
			better: base,
			worse:  withLatencies(base, 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond, 0),
		},
		{
			name:   "lower jitter",
			better: base,
			worse:  withLatencies(base, 50*time.Millisecond, 100*time.Millisecond, 150*time.Millisecond, 100*time.Millisecond),
		},
		{
			name:   "lower latency",
			better: base,
			worse:  withLatencies(base, 200*time.Millisecond, 200*time.Millisecond, 200*time.Millisecond, 200*time.Millisecond),
		},
		{
			name:   "higher throughput",
			better: withThroughput(base, 1024*1024),
			worse:  withThroughput(base, 64*1024),
		},
		{
			name:   "successful protocol validation",
			better: withValidation(base),
			worse:  base,
		},
		{
			name:   "required websocket success bonus",
			better: withRequiredWebSocket(base, true),
			worse:  withRequiredWebSocket(base, false),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := tt.better.QualityScore(), tt.worse.QualityScore(); got <= want {
				t.Fatalf("better score = %.2f, worse score = %.2f", got, want)
			}
		})
	}
}

func TestSortByQualityKeepsHealthyResultsFirst(t *testing.T) {
	healthy := &Result{
		IP:        net.ParseIP("1.1.1.1"),
		Latencies: []time.Duration{10 * time.Second, 10 * time.Second, 0},
	}
	unhealthy := &Result{
		IP:          net.ParseIP("1.1.1.2"),
		ProbeMode:   "http",
		Port:        443,
		Latencies:   []time.Duration{10 * time.Millisecond, 0},
		TLSOk:       true,
		WSOk:        true,
		RequireWS:   true,
		HTTPStatus:  200,
		Colo:        "FRA",
		Throughput:  10 * 1024 * 1024,
		SpeedTested: true,
	}
	if healthy.QualityScore() >= unhealthy.QualityScore() {
		t.Fatalf("test setup requires unhealthy score %.2f to exceed healthy score %.2f", unhealthy.QualityScore(), healthy.QualityScore())
	}

	results := []*Result{unhealthy, healthy}
	Sort(results, SortByQuality)
	if results[0] != healthy {
		t.Fatalf("healthy result should sort first, got %s", results[0].IP)
	}
}

func TestTopNUsesQualityScore(t *testing.T) {
	fast := &Result{IP: net.ParseIP("1.1.1.1"), Latencies: []time.Duration{40 * time.Millisecond}, Throughput: 0}
	quality := &Result{IP: net.ParseIP("1.1.1.2"), Latencies: []time.Duration{80 * time.Millisecond}, Throughput: 2 * 1024 * 1024}

	top := TopN([]*Result{fast, quality}, 1)
	if len(top) != 1 || top[0] != quality {
		t.Fatalf("TopN should choose higher quality result, got %+v", top)
	}
}

func withLatencies(r Result, latencies ...time.Duration) Result {
	r.Latencies = latencies
	return r
}

func withThroughput(r Result, throughput float64) Result {
	r.Throughput = throughput
	return r
}

func withValidation(r Result) Result {
	r.TLSOk = true
	r.HTTPStatus = 200
	r.Colo = "FRA"
	return r
}

func withRequiredWebSocket(r Result, ok bool) Result {
	r.RequireWS = true
	r.WSOk = ok
	return r
}

func TestQualityScoreStrongLatencyPreference(t *testing.T) {
	base := Result{
		IP:         net.ParseIP("1.1.1.1"),
		Latencies:  []time.Duration{200 * time.Millisecond},
		Throughput: 512 * 1024,
		TLSOk:      true,
	}

	scoreAt := func(d time.Duration) float64 {
		r := base
		r.Latencies = []time.Duration{d}
		return r.QualityScore()
	}

	if scoreAt(200*time.Millisecond) <= scoreAt(700*time.Millisecond) {
		t.Fatal("200ms result should score above 700ms result")
	}
	if scoreAt(700*time.Millisecond) <= scoreAt(1200*time.Millisecond) {
		t.Fatal("700ms result should score above 1200ms result")
	}
	if scoreAt(300*time.Millisecond) <= scoreAt(1000*time.Millisecond) {
		t.Fatal("300ms result should score above 1000ms result")
	}
}

func TestQualityScoreLossAndLatencyCannotBeHidden(t *testing.T) {
	zeroLoss := Result{Latencies: []time.Duration{300 * time.Millisecond, 300 * time.Millisecond, 300 * time.Millisecond}, Throughput: 512 * 1024}
	lossy := Result{Latencies: []time.Duration{300 * time.Millisecond, 300 * time.Millisecond, 0}, Throughput: 512 * 1024}
	if zeroLoss.QualityScore() <= lossy.QualityScore() {
		t.Fatal("0% loss should score above similar-latency 33% loss")
	}

	goodLatency := Result{Latencies: []time.Duration{300 * time.Millisecond}, Throughput: 128 * 1024}
	badLatencyFast := Result{Latencies: []time.Duration{1200 * time.Millisecond}, Throughput: 10 * 1024 * 1024}
	if goodLatency.QualityScore() <= badLatencyFast.QualityScore() {
		t.Fatal("high throughput should not hide very bad latency")
	}
}

func TestTopNFiltersDefaultMaxPhase1Latency(t *testing.T) {
	fast := &Result{IP: net.ParseIP("1.1.1.1"), Latencies: []time.Duration{200 * time.Millisecond}}
	slow := &Result{IP: net.ParseIP("1.1.1.2"), Latencies: []time.Duration{900 * time.Millisecond}}

	top := TopN([]*Result{slow, fast}, 0)
	if len(top) != 1 || top[0] != fast {
		t.Fatalf("TopN should exclude results above %s, got %+v", DefaultMaxPhase1AvgLatency, top)
	}
	if !slow.IsHealthy() {
		t.Fatal("latency filtering should not change the underlying protocol health result")
	}
	if got := TopNWithMaxLatency([]*Result{slow, fast}, 0, 0); len(got) != 2 {
		t.Fatalf("disabled latency cutoff should keep both results, got %d", len(got))
	}
}
