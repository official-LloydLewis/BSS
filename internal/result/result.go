package result

import (
	"math"
	"net"
	"sort"
	"time"
)

// DefaultMaxPhase1AvgLatency is the default cutoff for Phase 1 top/export lists.
// It applies to TCP connect RTT when available, otherwise the legacy full probe
// average. Results remain available in scan history even when they exceed it.
const DefaultMaxPhase1AvgLatency = 800 * time.Millisecond

// Result holds all measured statistics for a single Cloudflare IP.
type Result struct {
	IP               net.IP
	Port             int
	ProbeMode        string          // tcp | tls | http
	Latencies        []time.Duration // per-try full protocol probe durations; 0 = failed try
	ConnectLatencies []time.Duration // per-try TCP connect durations; 0 = TCP connect failed or was not measured
	TLSOk            bool
	WSOk             bool // WebSocket connection survived hold test
	RequireWS        bool // true when WebSocket success is part of health criteria
	HTTPStatus       int
	HTTP2            bool // true when an HTTP probe negotiated HTTP/2
	Colo             string
	Throughput       float64 // bytes/sec, 0 if not measured
	DownloadBytes    int64
	DownloadElapsed  time.Duration
	SpeedTested      bool   // true when a payload download check was attempted
	SpeedTestError   string // optional error recorded when a payload download check fails
	Timestamp        time.Time
}

// Loss returns packet loss percentage (0–100).
func (r *Result) Loss() float64 {
	if len(r.Latencies) == 0 {
		return 100
	}
	failed := 0
	for _, l := range r.Latencies {
		if l == 0 {
			failed++
		}
	}
	return float64(failed) / float64(len(r.Latencies)) * 100
}

// Avg returns the mean of successful full protocol probe durations. Depending
// on ProbeMode, this includes TCP connect only (tcp), TCP+TLS handshake (tls),
// or TCP+TLS+HTTP request through response headers (http).
func (r *Result) Avg() time.Duration { return avgDurations(r.Latencies) }

// ConnectAvg returns the mean of successful TCP connect measurements. It is the
// closest available measurement to network RTT and intentionally excludes TLS,
// HTTP response, and download/sample work.
func (r *Result) ConnectAvg() time.Duration { return avgDurations(r.ConnectLatencies) }

// RTT returns the preferred latency used for ranking: TCP connect latency when
// available, with a safe fallback to the legacy full probe duration.
func (r *Result) RTT() time.Duration {
	if avg := r.ConnectAvg(); avg > 0 {
		return avg
	}
	return r.Avg()
}

func avgDurations(values []time.Duration) time.Duration {
	var sum time.Duration
	var count int
	for _, l := range values {
		if l > 0 {
			sum += l
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return sum / time.Duration(count)
}

// Min returns the best successful latency.
func (r *Result) Min() time.Duration {
	var m time.Duration
	for _, l := range r.Latencies {
		if l > 0 && (m == 0 || l < m) {
			m = l
		}
	}
	return m
}

// Max returns the worst successful latency.
func (r *Result) Max() time.Duration {
	var m time.Duration
	for _, l := range r.Latencies {
		if l > m {
			m = l
		}
	}
	return m
}

// Jitter returns the standard deviation of successful full probe durations.
func (r *Result) Jitter() time.Duration { return jitterDurations(r.Latencies) }

// ConnectJitter returns the standard deviation of successful TCP connect durations.
func (r *Result) ConnectJitter() time.Duration { return jitterDurations(r.ConnectLatencies) }

// RTTJitter returns TCP connect jitter when available, otherwise full probe jitter.
func (r *Result) RTTJitter() time.Duration {
	if r.ConnectAvg() > 0 {
		return r.ConnectJitter()
	}
	return r.Jitter()
}

func jitterDurations(values []time.Duration) time.Duration {
	var count int
	for _, l := range values {
		if l > 0 {
			count++
		}
	}
	if count < 2 {
		return 0
	}
	avg := float64(avgDurations(values))
	var variance float64
	for _, l := range values {
		if l > 0 {
			diff := float64(l) - avg
			variance += diff * diff
		}
	}
	variance /= float64(count)
	return time.Duration(math.Sqrt(variance))
}

// SpeedMbps returns measured throughput in decimal megabits per second.
func (r *Result) SpeedMbps() float64 {
	if r == nil || r.Throughput <= 0 {
		return 0
	}
	return r.Throughput * 8 / 1_000_000
}

// QualityScore returns a deterministic 0–100 score for ranking Phase 1 results.
// Higher scores prefer stable, low-latency connections with better throughput
// and successful protocol validation.
func (r *Result) QualityScore() float64 {
	avg := r.RTT()
	jitter := r.RTTJitter()

	lossScore := clampQuality(100 - r.Loss())
	latencyScore := 0.0
	jitterScore := 0.0
	if avg > 0 {
		latencyScore = lowerIsBetterQuality(float64(avg)/float64(time.Millisecond), 100)
		jitterScore = lowerIsBetterQuality(float64(jitter)/float64(time.Millisecond), 50)
	}

	throughput := math.Max(r.Throughput, 0)
	throughputScore := clampQuality(100 * (1 - math.Exp(-throughput/(1024*1024))))

	// Loss and RTT remain dominant. Throughput can distinguish otherwise
	// similar candidates, but cannot rescue a very slow or lossy edge.
	score := lossScore*0.40 + latencyScore*0.30 + jitterScore*0.15 + throughputScore*0.10
	if r.TLSOk {
		score += 2
	}
	if r.HTTPStatus >= 200 && r.HTTPStatus < 400 {
		score += 2
	}
	if r.Colo != "" {
		score++
	}
	if r.RequireWS && r.WSOk {
		score += 5
	}
	return clampQuality(score)
}

func lowerIsBetterQuality(value, scale float64) float64 {
	if value < 0 {
		value = 0
	}
	return 100 / (1 + value/scale)
}

func clampQuality(score float64) float64 {
	switch {
	case math.IsNaN(score), score < 0:
		return 0
	case score > 100:
		return 100
	default:
		return score
	}
}

// IsHealthy returns true only when the probe mode's success criteria are met.
// A failed try must record latency 0; timeouts must never count as success.
func (r *Result) IsHealthy() bool {
	if r.Loss() >= 50 || r.Avg() <= 0 {
		return false
	}

	switch r.ProbeMode {
	case "http":
		// Plain HTTP (port 80) has no TLS; every other HTTP-mode port is HTTPS.
		if r.Port != 80 && !r.TLSOk {
			return false
		}
		if r.HTTPStatus < 200 || r.HTTPStatus >= 400 || r.Colo == "" {
			return false
		}
		if r.RequireWS && !r.WSOk {
			return false
		}
		return true
	case "tls":
		return r.TLSOk
	default: // tcp
		return true
	}
}

// IsHealthyForPhase1 reports whether a result meets protocol health criteria
// and the supplied preferred-latency cutoff (TCP connect RTT with a full-probe
// fallback). A non-positive cutoff disables the latency filter.
func (r *Result) IsHealthyForPhase1(maxLatency time.Duration) bool {
	if !r.IsHealthy() {
		return false
	}
	return maxLatency <= 0 || r.RTT() <= maxLatency
}

// SortBy defines the available sort criteria.
type SortBy int

const (
	SortByAvg SortBy = iota
	SortByLoss
	SortByJitter
	SortByColo
	SortBySpeed
	SortByQuality
)

func sortRank(r *Result) int {
	if r.IsHealthy() {
		return 0
	}
	if r.RTT() > 0 || r.Loss() < 100 {
		return 1
	}
	return 2
}

func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return -1
	default:
		return 1
	}
}

func cmpDuration(a, b time.Duration) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func cmpFloatAsc(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func cmpFloatDesc(a, b float64) int {
	return -cmpFloatAsc(a, b)
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func compareResults(a, b *Result, by SortBy) int {
	if rankCmp := sortRank(a) - sortRank(b); rankCmp != 0 {
		return rankCmp
	}

	switch by {
	case SortByLoss:
		if cmp := cmpFloatAsc(a.Loss(), b.Loss()); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.RTT(), b.RTT()); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.RTTJitter(), b.RTTJitter()); cmp != 0 {
			return cmp
		}
	case SortByJitter:
		if cmp := cmpDuration(a.RTTJitter(), b.RTTJitter()); cmp != 0 {
			return cmp
		}
		if cmp := cmpFloatAsc(a.Loss(), b.Loss()); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.RTT(), b.RTT()); cmp != 0 {
			return cmp
		}
	case SortByColo:
		if cmp := cmpString(a.Colo, b.Colo); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.RTT(), b.RTT()); cmp != 0 {
			return cmp
		}
		if cmp := cmpFloatAsc(a.Loss(), b.Loss()); cmp != 0 {
			return cmp
		}
	case SortBySpeed:
		if cmp := cmpFloatDesc(a.Throughput, b.Throughput); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.RTT(), b.RTT()); cmp != 0 {
			return cmp
		}
		if cmp := cmpFloatAsc(a.Loss(), b.Loss()); cmp != 0 {
			return cmp
		}
	case SortByQuality:
		if cmp := cmpFloatDesc(a.QualityScore(), b.QualityScore()); cmp != 0 {
			return cmp
		}
		if cmp := cmpFloatAsc(a.Loss(), b.Loss()); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.RTTJitter(), b.RTTJitter()); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.RTT(), b.RTT()); cmp != 0 {
			return cmp
		}
		if cmp := cmpFloatDesc(a.Throughput, b.Throughput); cmp != 0 {
			return cmp
		}
	default:
		if cmp := cmpDuration(a.RTT(), b.RTT()); cmp != 0 {
			return cmp
		}
		if cmp := cmpFloatAsc(a.Loss(), b.Loss()); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.RTTJitter(), b.RTTJitter()); cmp != 0 {
			return cmp
		}
	}

	if cmp := cmpBool(a.TLSOk, b.TLSOk); cmp != 0 {
		return cmp
	}
	if cmp := cmpBool(a.WSOk, b.WSOk); cmp != 0 {
		return cmp
	}
	if cmp := cmpString(a.IP.String(), b.IP.String()); cmp != 0 {
		return cmp
	}
	return 0
}

// Sort reorders results in-place according to the given criterion (ascending).
func Sort(results []*Result, by SortBy) {
	sort.SliceStable(results, func(i, j int) bool {
		return compareResults(results[i], results[j], by) < 0
	})
}

// TopN returns the n best healthy results by quality score.
func TopN(results []*Result, n int) []*Result {
	return TopNWithMaxLatency(results, n, DefaultMaxPhase1AvgLatency)
}

// TopNWithMaxLatency returns the n best healthy results by quality score using
// the supplied Phase 1 average-latency cutoff.
func TopNWithMaxLatency(results []*Result, n int, maxLatency time.Duration) []*Result {
	var healthy []*Result
	for _, r := range results {
		if r.IsHealthyForPhase1(maxLatency) {
			healthy = append(healthy, r)
		}
	}
	Sort(healthy, SortByQuality)
	if n > 0 && n < len(healthy) {
		return healthy[:n]
	}
	return healthy
}
