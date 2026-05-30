package result

import (
	"math"
	"net"
	"sort"
	"strings"
	"time"
)

// Result holds all measured statistics for a single Cloudflare IP.
type Result struct {
	IP             net.IP
	Port           int
	ProbeMode      string          // tcp | tls | http
	Latencies      []time.Duration // per-try latencies; 0 = failed try
	TLSOk          bool
	WSOk           bool // WebSocket connection survived hold test
	RequireWS      bool // true when WebSocket success is part of health criteria
	HTTPStatus     int
	Colo           string
	Throughput     float64 // bytes/sec, 0 if not measured
	SpeedTested    bool    // true when a payload download check was attempted
	CleanScore     float64
	LatencyScore   float64
	LossScore      float64
	JitterScore    float64
	SpeedScore     float64
	StabilityScore float64
	ProtocolScore  float64
	FailureReason  string
	Timestamp      time.Time
}

// ScoreOptions adjusts deterministic clean-score calculation.
type ScoreOptions struct {
	PreferredColos map[string]bool
	BlockedColos   map[string]bool
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

// Avg returns the mean of successful latency measurements.
func (r *Result) Avg() time.Duration {
	var sum time.Duration
	var count int
	for _, l := range r.Latencies {
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

// Jitter returns the standard deviation of successful latencies.
func (r *Result) Jitter() time.Duration {
	var count int
	for _, l := range r.Latencies {
		if l > 0 {
			count++
		}
	}
	if count < 2 {
		return 0
	}
	avg := float64(r.Avg())
	var variance float64
	for _, l := range r.Latencies {
		if l > 0 {
			diff := float64(l) - avg
			variance += diff * diff
		}
	}
	variance /= float64(count)
	return time.Duration(math.Sqrt(variance))
}

// CalculateScores populates score fields using deterministic 0–100 component
// scores. Higher is cleaner; very high loss and failed required protocol checks
// are intentionally punished heavily.
func (r *Result) CalculateScores() {
	r.CalculateScoresWithOptions(ScoreOptions{})
}

// CalculateScoresWithOptions applies the clean score plus optional colo policy.
func (r *Result) CalculateScoresWithOptions(opts ScoreOptions) {
	loss := r.Loss()
	avgMS := float64(r.Avg().Milliseconds())
	jitterMS := float64(r.Jitter().Milliseconds())

	r.LatencyScore = scoreLowerBetter(avgMS, 50, 800)
	if avgMS <= 0 {
		r.LatencyScore = 0
	}
	r.LossScore = clamp(100 - loss*2.5) // 40% loss reaches zero.
	if loss >= 80 {
		r.LossScore = 0
	}
	r.JitterScore = scoreLowerBetter(jitterMS, 20, 300)
	if r.Avg() <= 0 {
		r.JitterScore = 0
	}
	if r.SpeedTested {
		r.SpeedScore = scoreHigherBetter(r.Throughput/1024, 64, 2048)
	} else {
		r.SpeedScore = 75 // neutral-ish when speed is not part of this scan.
	}
	r.StabilityScore = stabilityScore(r)
	r.ProtocolScore = protocolScore(r)

	score := r.LatencyScore*0.25 + r.LossScore*0.25 + r.JitterScore*0.15 + r.SpeedScore*0.20 + r.StabilityScore*0.10 + r.ProtocolScore*0.05
	if loss >= 50 {
		score *= 0.35
	}
	if r.SpeedTested && r.Throughput <= 0 {
		score *= 0.55
	}
	if r.RequireWS && !r.WSOk {
		score *= 0.35
	}
	colo := strings.ToUpper(r.Colo)
	if opts.BlockedColos != nil && opts.BlockedColos[colo] {
		score *= 0.10
	}
	if opts.PreferredColos != nil && opts.PreferredColos[colo] {
		score += 5
	}
	if r.Loss() == 100 || r.Avg() <= 0 {
		score = math.Min(score, 5)
	}
	r.CleanScore = clamp(score)
	r.FailureReason = r.failureReason(opts)
}

func (r *Result) failureReason(opts ScoreOptions) string {
	colo := strings.ToUpper(r.Colo)
	if opts.BlockedColos != nil && opts.BlockedColos[colo] {
		return "blocked colo"
	}
	if r.Loss() == 100 || r.Avg() <= 0 {
		return "all probes failed"
	}
	if r.Loss() >= 50 {
		return "high packet loss"
	}
	if r.ProbeMode == "http" {
		if r.Port != 80 && !r.TLSOk {
			return "tls handshake failed"
		}
		if r.HTTPStatus < 200 || r.HTTPStatus >= 400 {
			return "http validation failed"
		}
		if r.Colo == "" {
			return "missing cloudflare colo"
		}
		if r.SpeedTested && r.Throughput <= 0 {
			return "speed test failed"
		}
		if r.RequireWS && !r.WSOk {
			return "websocket test failed"
		}
	} else if r.ProbeMode == "tls" && !r.TLSOk {
		return "tls handshake failed"
	}
	if r.Jitter() > 250*time.Millisecond {
		return "high jitter"
	}
	if r.Max() > 0 && r.Min() > 0 && r.Max() > r.Min()*4 {
		return "unstable latency"
	}
	if r.CleanScore < 50 {
		return "low clean score"
	}
	return ""
}

func scoreLowerBetter(value, excellent, poor float64) float64 {
	if value <= excellent {
		return 100
	}
	if value >= poor {
		return 0
	}
	return clamp(100 * (poor - value) / (poor - excellent))
}

func scoreHigherBetter(value, acceptable, excellent float64) float64 {
	if value <= 0 {
		return 0
	}
	if value >= excellent {
		return 100
	}
	if value <= acceptable {
		return 35 * value / acceptable
	}
	return clamp(35 + 65*(value-acceptable)/(excellent-acceptable))
}

func stabilityScore(r *Result) float64 {
	avg := r.Avg()
	if avg <= 0 {
		return 0
	}
	jitterRatio := float64(r.Jitter()) / float64(avg)
	spreadRatio := 0.0
	if r.Min() > 0 {
		spreadRatio = float64(r.Max()-r.Min()) / float64(r.Min())
	}
	score := 100 - jitterRatio*120 - spreadRatio*15 - r.Loss()
	return clamp(score)
}

func protocolScore(r *Result) float64 {
	switch r.ProbeMode {
	case "http":
		score := 0.0
		if r.Port == 80 || r.TLSOk {
			score += 35
		}
		if r.HTTPStatus >= 200 && r.HTTPStatus < 400 {
			score += 30
		}
		if r.Colo != "" {
			score += 20
		}
		if !r.RequireWS || r.WSOk {
			score += 15
		}
		return clamp(score)
	case "tls":
		if r.TLSOk {
			return 100
		}
		return 0
	default:
		if r.Avg() > 0 && r.Loss() < 100 {
			return 80
		}
		return 0
	}
}

func clamp(v float64) float64 {
	if v < 0 || math.IsNaN(v) {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
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
		if r.SpeedTested && r.Throughput <= 0 {
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

// SortBy defines the available sort criteria.
type SortBy int

const (
	SortByAvg SortBy = iota
	SortByLoss
	SortByJitter
	SortByColo
	SortBySpeed
	SortByCleanScore
)

func sortRank(r *Result) int {
	if r.IsHealthy() {
		return 0
	}
	if r.Avg() > 0 || r.Loss() < 100 {
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

func cmpFloatDesc(a, b float64) int { return -cmpFloatAsc(a, b) }

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
		if cmp := cmpDuration(a.Avg(), b.Avg()); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.Jitter(), b.Jitter()); cmp != 0 {
			return cmp
		}
	case SortByJitter:
		if cmp := cmpDuration(a.Jitter(), b.Jitter()); cmp != 0 {
			return cmp
		}
		if cmp := cmpFloatAsc(a.Loss(), b.Loss()); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.Avg(), b.Avg()); cmp != 0 {
			return cmp
		}
	case SortByColo:
		if cmp := cmpString(a.Colo, b.Colo); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.Avg(), b.Avg()); cmp != 0 {
			return cmp
		}
		if cmp := cmpFloatAsc(a.Loss(), b.Loss()); cmp != 0 {
			return cmp
		}
	case SortBySpeed:
		if cmp := cmpFloatDesc(a.Throughput, b.Throughput); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.Avg(), b.Avg()); cmp != 0 {
			return cmp
		}
		if cmp := cmpFloatAsc(a.Loss(), b.Loss()); cmp != 0 {
			return cmp
		}
	case SortByCleanScore:
		if cmp := cmpFloatDesc(effectiveCleanScore(a), effectiveCleanScore(b)); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.Avg(), b.Avg()); cmp != 0 {
			return cmp
		}
		if cmp := cmpFloatAsc(a.Loss(), b.Loss()); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.Jitter(), b.Jitter()); cmp != 0 {
			return cmp
		}
		if cmp := cmpFloatDesc(a.Throughput, b.Throughput); cmp != 0 {
			return cmp
		}
	default:
		if cmp := cmpDuration(a.Avg(), b.Avg()); cmp != 0 {
			return cmp
		}
		if cmp := cmpFloatAsc(a.Loss(), b.Loss()); cmp != 0 {
			return cmp
		}
		if cmp := cmpDuration(a.Jitter(), b.Jitter()); cmp != 0 {
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

func effectiveCleanScore(r *Result) float64 {
	if r.CleanScore > 0 || r.FailureReason != "" {
		return r.CleanScore
	}
	cp := *r
	cp.CalculateScores()
	return cp.CleanScore
}

// Sort reorders results in-place according to the given criterion (ascending).
func Sort(results []*Result, by SortBy) {
	sort.SliceStable(results, func(i, j int) bool { return compareResults(results[i], results[j], by) < 0 })
}

// TopN returns the n best healthy results by CleanScore, then latency.
func TopN(results []*Result, n int) []*Result {
	var healthy []*Result
	for _, r := range results {
		if r.IsHealthy() {
			healthy = append(healthy, r)
		}
	}
	Sort(healthy, SortByCleanScore)
	if n > 0 && n < len(healthy) {
		return healthy[:n]
	}
	return healthy
}
