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

func TestCalculateScoresAndFailureReasons(t *testing.T) {
	good := &Result{IP: net.ParseIP("1.1.1.1"), Port: 443, ProbeMode: "http", Latencies: []time.Duration{40 * time.Millisecond, 45 * time.Millisecond, 50 * time.Millisecond}, TLSOk: true, HTTPStatus: 200, Colo: "FRA", SpeedTested: true, Throughput: 2 * 1024 * 1024, RequireWS: true, WSOk: true}
	good.CalculateScores()
	if good.CleanScore <= 80 || good.CleanScore > 100 {
		t.Fatalf("good CleanScore = %.2f, want 80..100", good.CleanScore)
	}
	if good.FailureReason != "" {
		t.Fatalf("good FailureReason = %q, want empty", good.FailureReason)
	}

	failed := &Result{IP: net.ParseIP("1.1.1.2"), Port: 443, ProbeMode: "http", Latencies: []time.Duration{0, 0, 0}, SpeedTested: true, RequireWS: true}
	failed.CalculateScores()
	if failed.CleanScore > 5 {
		t.Fatalf("failed CleanScore = %.2f, want <= 5", failed.CleanScore)
	}
	if failed.FailureReason != "all probes failed" {
		t.Fatalf("failed FailureReason = %q", failed.FailureReason)
	}

	lossy := &Result{IP: net.ParseIP("1.1.1.3"), Port: 443, ProbeMode: "tls", Latencies: []time.Duration{70 * time.Millisecond, 0, 0, 0}, TLSOk: true}
	lossy.CalculateScores()
	if lossy.FailureReason != "high packet loss" {
		t.Fatalf("lossy FailureReason = %q", lossy.FailureReason)
	}
	if lossy.CleanScore >= good.CleanScore/2 {
		t.Fatalf("high loss did not heavily punish score: %.2f vs %.2f", lossy.CleanScore, good.CleanScore)
	}
}

func TestSortByCleanScore(t *testing.T) {
	fast := &Result{IP: net.ParseIP("1.1.1.1"), ProbeMode: "tls", Latencies: []time.Duration{50 * time.Millisecond}, TLSOk: true, CleanScore: 80}
	slow := &Result{IP: net.ParseIP("1.1.1.2"), ProbeMode: "tls", Latencies: []time.Duration{150 * time.Millisecond}, TLSOk: true, CleanScore: 80}
	best := &Result{IP: net.ParseIP("1.1.1.3"), ProbeMode: "tls", Latencies: []time.Duration{120 * time.Millisecond}, TLSOk: true, CleanScore: 90}
	dead := &Result{IP: net.ParseIP("1.1.1.4"), ProbeMode: "tls", Latencies: []time.Duration{0}, CleanScore: 100}
	results := []*Result{dead, slow, fast, best}
	Sort(results, SortByCleanScore)
	if got := results[0].IP.String(); got != "1.1.1.3" {
		t.Fatalf("first = %s, want 1.1.1.3", got)
	}
	if got := results[1].IP.String(); got != "1.1.1.1" {
		t.Fatalf("tie should use latency, got %s", got)
	}
	if got := results[len(results)-1].IP.String(); got != "1.1.1.4" {
		t.Fatalf("unhealthy result should be last, got %s", got)
	}
}

func TestColoBoostBlockAndSubnetTracker(t *testing.T) {
	preferred := &Result{IP: net.ParseIP("203.0.113.10"), ProbeMode: "http", Port: 443, Latencies: []time.Duration{80 * time.Millisecond}, TLSOk: true, HTTPStatus: 200, Colo: "FRA"}
	plain := &Result{IP: net.ParseIP("203.0.113.20"), ProbeMode: "http", Port: 443, Latencies: []time.Duration{80 * time.Millisecond}, TLSOk: true, HTTPStatus: 200, Colo: "AMS"}
	blocked := &Result{IP: net.ParseIP("203.0.113.30"), ProbeMode: "http", Port: 443, Latencies: []time.Duration{80 * time.Millisecond}, TLSOk: true, HTTPStatus: 200, Colo: "BAD"}
	opts := ScoreOptions{PreferredColos: map[string]bool{"FRA": true}, BlockedColos: map[string]bool{"BAD": true}}
	preferred.CalculateScoresWithOptions(opts)
	plain.CalculateScoresWithOptions(opts)
	blocked.CalculateScoresWithOptions(opts)
	if preferred.CleanScore <= plain.CleanScore {
		t.Fatalf("preferred score %.2f should beat plain %.2f", preferred.CleanScore, plain.CleanScore)
	}
	if blocked.FailureReason != "blocked colo" || blocked.CleanScore >= plain.CleanScore/2 {
		t.Fatalf("blocked colo not punished: score %.2f reason %q", blocked.CleanScore, blocked.FailureReason)
	}

	tracker := NewSubnetTracker(24)
	tracker.Add(preferred)
	tracker.Add(plain)
	stats := tracker.Stats()
	if len(stats) != 1 || stats[0].CIDR != "203.0.113.0/24" || stats[0].TestedCount != 2 || stats[0].SubnetScore <= 0 {
		t.Fatalf("unexpected subnet stats: %+v", stats)
	}
}
