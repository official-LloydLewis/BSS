package history

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/config"
	"github.com/matinsenpai/senpaiscanner/internal/result"
)

func healthy(ip string, rtt time.Duration, speed float64, scoreColo string) *result.Result {
	return &result.Result{IP: net.ParseIP(ip), Port: 443, ProbeMode: "http", Latencies: []time.Duration{rtt}, ConnectLatencies: []time.Duration{rtt}, TLSOk: true, HTTPStatus: 200, Colo: scoreColo, Throughput: speed}
}

func TestLoadGoodValidAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, GoodIPsFile), []byte(`[{"ip":"104.24.72.1","best_port":443,"times_seen":2}]`), 0644); err != nil {
		t.Fatal(err)
	}
	recs, err := LoadGood(dir)
	if err != nil || len(recs) != 1 || recs[0].TimesSeen != 2 {
		t.Fatalf("records=%v err=%v", recs, err)
	}
	if err := os.WriteFile(filepath.Join(dir, GoodIPsFile), []byte(`{bad`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGood(dir); err == nil {
		t.Fatal("expected corrupt JSON error")
	}
}

func TestSaveGoodResultsMergesAndUpdatesBestFields(t *testing.T) {
	dir := t.TempDir()
	first := healthy("104.24.72.1", 100*time.Millisecond, 1_000_000, "FRA")
	if err := SaveGoodResults(dir, []*result.Result{first, first}); err != nil {
		t.Fatal(err)
	}
	second := healthy("104.24.72.1", 50*time.Millisecond, 2_000_000, "AMS")
	if err := SaveGoodResults(dir, []*result.Result{second}); err != nil {
		t.Fatal(err)
	}
	recs, err := LoadGood(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("records=%d, want merged record", len(recs))
	}
	r := recs[0]
	if r.TimesSeen != 2 || r.BestRTTMs != 50 || r.BestSpeedMbps != 16 || r.Colo != "AMS" || r.LastSeen.IsZero() {
		t.Fatalf("unexpected record: %+v", r)
	}
}

func TestLoadGoodLimitReturnsBestAndCapsResults(t *testing.T) {
	dir := t.TempDir()
	records := []IPRecord{
		{IP: "104.24.72.1", BestScore: 10},
		{IP: "104.24.72.2", BestScore: 30},
		{IP: "104.24.72.3", BestScore: 20},
	}
	if err := writeRecords(filepath.Join(dir, GoodIPsFile), records); err != nil {
		t.Fatal(err)
	}
	got, err := LoadGoodLimit(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].IP != "104.24.72.2" || got[1].IP != "104.24.72.3" {
		t.Fatalf("got %+v", got)
	}
}

func TestPreviousGoodDefaultLoadLimit(t *testing.T) {
	dir := t.TempDir()
	records := make([]IPRecord, config.MaxPreviousGoodIPs+10)
	for i := range records {
		records[i] = IPRecord{IP: fmt.Sprintf("192.0.%d.%d", i/254, i%254+1), BestScore: float64(i)}
	}
	if err := writeRecords(filepath.Join(dir, GoodIPsFile), records); err != nil {
		t.Fatal(err)
	}
	got, err := LoadGoodLimit(dir, config.MaxPreviousGoodIPs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != config.MaxPreviousGoodIPs {
		t.Fatalf("loaded %d, want %d", len(got), config.MaxPreviousGoodIPs)
	}
}
