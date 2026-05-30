package result

import (
	"encoding/binary"
	"net"
)

// SubnetStats tracks aggregate quality for an IPv4 subnet, normally /24.
type SubnetStats struct {
	CIDR              string
	TestedCount       int
	HealthyCount      int
	AverageLatencyMS  float64
	AverageLoss       float64
	AverageJitterMS   float64
	AverageThroughput float64
	AverageCleanScore float64
	SubnetScore       float64
}

// SubnetTracker accumulates conservative per-subnet quality observations.
type SubnetTracker struct {
	prefixBits int
	stats      map[uint32]*subnetAccumulator
}

type subnetAccumulator struct {
	key        uint32
	tested     int
	healthy    int
	latencyMS  float64
	loss       float64
	jitterMS   float64
	throughput float64
	cleanScore float64
}

// NewSubnetTracker creates an IPv4 subnet tracker. Invalid prefixes fall back
// to /24, which is the scanner's default granularity for Cloudflare ranges.
func NewSubnetTracker(prefixBits int) *SubnetTracker {
	if prefixBits < 8 || prefixBits > 32 {
		prefixBits = 24
	}
	return &SubnetTracker{prefixBits: prefixBits, stats: make(map[uint32]*subnetAccumulator)}
}

// Add includes a result in its IPv4 subnet aggregate. IPv6 results are ignored.
func (t *SubnetTracker) Add(r *Result) {
	if t == nil || r == nil {
		return
	}
	ip4 := r.IP.To4()
	if ip4 == nil {
		return
	}
	key := binary.BigEndian.Uint32(ip4) & t.mask()
	s := t.stats[key]
	if s == nil {
		s = &subnetAccumulator{key: key}
		t.stats[key] = s
	}
	s.tested++
	if r.IsHealthy() {
		s.healthy++
	}
	s.latencyMS += float64(r.Avg().Milliseconds())
	s.loss += r.Loss()
	s.jitterMS += float64(r.Jitter().Milliseconds())
	s.throughput += r.Throughput
	if r.CleanScore == 0 && r.FailureReason == "" {
		r.CalculateScores()
	}
	s.cleanScore += r.CleanScore
}

// Stats returns a stable snapshot keyed by CIDR.
func (t *SubnetTracker) Stats() []SubnetStats {
	if t == nil {
		return nil
	}
	out := make([]SubnetStats, 0, len(t.stats))
	for _, s := range t.stats {
		if s.tested == 0 {
			continue
		}
		st := SubnetStats{
			CIDR:              t.cidr(s.key),
			TestedCount:       s.tested,
			HealthyCount:      s.healthy,
			AverageLatencyMS:  s.latencyMS / float64(s.tested),
			AverageLoss:       s.loss / float64(s.tested),
			AverageJitterMS:   s.jitterMS / float64(s.tested),
			AverageThroughput: s.throughput / float64(s.tested),
			AverageCleanScore: s.cleanScore / float64(s.tested),
		}
		healthyRatio := float64(st.HealthyCount) / float64(st.TestedCount)
		st.SubnetScore = clamp(st.AverageCleanScore*0.7 + healthyRatio*100*0.3)
		out = append(out, st)
	}
	return out
}

func (t *SubnetTracker) mask() uint32 {
	return ^uint32(0) << (32 - t.prefixBits)
}

func (t *SubnetTracker) cidr(key uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, key)
	return (&net.IPNet{IP: ip, Mask: net.CIDRMask(t.prefixBits, 32)}).String()
}
