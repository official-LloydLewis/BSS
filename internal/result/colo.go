package result

import (
	"sort"
	"strings"
	"time"
)

// ColoFilter controls which colos are eligible for healthy/top/export lists.
// It does not alter the raw result history.
type ColoFilter struct {
	Allow map[string]struct{}
	Block map[string]struct{}
}

// NewColoFilter builds a case-insensitive filter from comma-separated lists.
func NewColoFilter(allow, block string) ColoFilter {
	return ColoFilter{Allow: coloSet(allow), Block: coloSet(block)}
}

func coloSet(raw string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, value := range strings.Split(raw, ",") {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value != "" {
			set[value] = struct{}{}
		}
	}
	return set
}

// Allows reports whether a result may appear in filtered ranking/export lists.
func (f ColoFilter) Allows(r *Result) bool {
	if r == nil {
		return false
	}
	colo := strings.ToUpper(r.Colo)
	if _, blocked := f.Block[colo]; blocked {
		return false
	}
	if len(f.Allow) == 0 {
		return true
	}
	_, allowed := f.Allow[colo]
	return allowed
}

// Filter returns a new slice without modifying the raw input history.
func (f ColoFilter) Filter(results []*Result) []*Result {
	out := make([]*Result, 0, len(results))
	for _, r := range results {
		if f.Allows(r) {
			out = append(out, r)
		}
	}
	return out
}

// ColoStat summarizes observed performance for one Cloudflare colo.
type ColoStat struct {
	Colo         string
	Count        int
	HealthyCount int
	AvgRTT       time.Duration
	AvgScore     float64
	AvgSpeedMbps float64
	BestIP       string
	BestScore    float64
}

// ColoStats aggregates raw scan history, including unhealthy results when they
// have a colo. Speed averages include only successful speed measurements.
func ColoStats(results []*Result) []ColoStat {
	type aggregate struct {
		stat       ColoStat
		rttTotal   time.Duration
		rttCount   int
		scoreTotal float64
		speedTotal float64
		speedCount int
	}
	byColo := make(map[string]*aggregate)
	for _, r := range results {
		if r == nil || strings.TrimSpace(r.Colo) == "" {
			continue
		}
		colo := strings.ToUpper(r.Colo)
		a := byColo[colo]
		if a == nil {
			a = &aggregate{stat: ColoStat{Colo: colo}}
			byColo[colo] = a
		}
		a.stat.Count++
		score := r.QualityScore()
		a.scoreTotal += score
		if r.IsHealthy() {
			a.stat.HealthyCount++
		}
		if r.RTT() > 0 {
			a.rttTotal += r.RTT()
			a.rttCount++
		}
		if r.Throughput > 0 {
			a.speedTotal += r.SpeedMbps()
			a.speedCount++
		}
		if a.stat.BestIP == "" || score > a.stat.BestScore {
			a.stat.BestIP = r.IP.String()
			a.stat.BestScore = score
		}
	}
	out := make([]ColoStat, 0, len(byColo))
	for _, a := range byColo {
		if a.rttCount > 0 {
			a.stat.AvgRTT = a.rttTotal / time.Duration(a.rttCount)
		}
		if a.stat.Count > 0 {
			a.stat.AvgScore = a.scoreTotal / float64(a.stat.Count)
		}
		if a.speedCount > 0 {
			a.stat.AvgSpeedMbps = a.speedTotal / float64(a.speedCount)
		}
		out = append(out, a.stat)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AvgScore == out[j].AvgScore {
			return out[i].Colo < out[j].Colo
		}
		return out[i].AvgScore > out[j].AvgScore
	})
	return out
}
