package result

import (
	"net"
	"testing"
	"time"
)

func coloResult(ip, colo string, rtt time.Duration, speed float64) *Result {
	return &Result{IP: net.ParseIP(ip), Port: 443, ProbeMode: "http", Latencies: []time.Duration{rtt}, ConnectLatencies: []time.Duration{rtt}, TLSOk: true, HTTPStatus: 200, Colo: colo, Throughput: speed}
}

func TestColoStatsAggregate(t *testing.T) {
	stats := ColoStats([]*Result{coloResult("104.1.1.1", "FRA", 100*time.Millisecond, 1_000_000), coloResult("104.1.1.2", "FRA", 200*time.Millisecond, 2_000_000)})
	if len(stats) != 1 || stats[0].Count != 2 || stats[0].HealthyCount != 2 || stats[0].AvgRTT != 150*time.Millisecond || stats[0].AvgSpeedMbps != 12 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if stats[0].BestIP == "" {
		t.Fatal("missing best IP")
	}
}

func TestColoFilterAllowBlockAndRawPreservation(t *testing.T) {
	raw := []*Result{coloResult("104.1.1.1", "FRA", time.Millisecond, 0), coloResult("104.1.1.2", "AMS", time.Millisecond, 0)}
	if got := NewColoFilter("", "").Filter(raw); len(got) != 2 {
		t.Fatalf("empty filter got %d", len(got))
	}
	if got := NewColoFilter("fra", "").Filter(raw); len(got) != 1 || got[0].Colo != "FRA" {
		t.Fatalf("allow got %+v", got)
	}
	if got := NewColoFilter("", "FRA").Filter(raw); len(got) != 1 || got[0].Colo != "AMS" {
		t.Fatalf("block got %+v", got)
	}
	if len(raw) != 2 {
		t.Fatal("filter mutated raw scan history")
	}
}
