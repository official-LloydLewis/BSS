package ui

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/result"
)

func TestLiveResultFileNameFormat(t *testing.T) {
	path, err := liveResultFilePath()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "BSSResult-") {
		t.Fatalf("basename = %q", base)
	}
	if !strings.HasSuffix(base, ".txt") {
		t.Fatalf("basename = %q, want .txt suffix", base)
	}
}

func TestLiveResultWriterRewritesHealthyPhase1Rows(t *testing.T) {
	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	w, path, err := newLiveResultWriter(false)
	if err != nil {
		t.Fatal(err)
	}
	r := &result.Result{
		IP:         net.ParseIP("104.18.1.1"),
		Port:       443,
		Latencies:  []time.Duration{100 * time.Millisecond},
		ProbeMode:  "http",
		TLSOk:      true,
		HTTPStatus: 200,
		Colo:       "FRA",
		Throughput: 1_000_000,
	}
	w.AddPhase1(r)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "104.18.1.1:443") {
		t.Fatalf("file missing endpoint:\n%s", text)
	}
	if !strings.Contains(text, "Phase 1") {
		t.Fatalf("file missing phase header:\n%s", text)
	}
	if !strings.Contains(text, "BSS (Better Senpai Scanner) — live results") {
		t.Fatalf("file missing BSS header:\n%s", text)
	}
	if !strings.Contains(text, "SPEED(Mbps)") || !strings.Contains(text, "8.00") {
		t.Fatalf("file missing speed column/value:\n%s", text)
	}
	if !strings.Contains(text, "SCORE") {
		t.Fatalf("file missing score column:\n%s", text)
	}
	if score := fmt.Sprintf("%.1f", r.QualityScore()); !strings.Contains(text, score) {
		t.Fatalf("file missing formatted score %s:\n%s", score, text)
	}
}

func TestResolveTopNCustom(t *testing.T) {
	m := NewApp("test")
	m.configTopNIdx = len(configTopNLabels) - 1
	m.configTopNCustom = "75"
	if got := m.resolveTopN(); got != 75 {
		t.Fatalf("topN = %d, want 75", got)
	}
}

func TestResolveTopNPreset(t *testing.T) {
	m := NewApp("test")
	m.configTopNIdx = 2
	if got := m.resolveTopN(); got != 50 {
		t.Fatalf("topN = %d, want 50", got)
	}
}

func TestLiveResultWriterIncludesSpeedDiagnostics(t *testing.T) {
	dir := t.TempDir()
	w := &LiveResultWriter{path: filepath.Join(dir, "result.txt"), started: time.Now(), phase: 1, phase1Seen: make(map[string]struct{})}
	w.SetDiscoveryStats(phase1DiscoveryStats{SpeedTestsScheduled: 3, SpeedTestsStarted: 2, SpeedTestsCompleted: 2, SpeedTestsFailed: 1, LastSpeedTestError: "download timeout"})
	b, err := os.ReadFile(w.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "Speed tests scheduled/started/completed/failed: 3/2/2/1") || !strings.Contains(string(b), "Last speed failure: download timeout") {
		t.Fatalf("missing diagnostics:\n%s", b)
	}
}

func TestLiveResultWriterExportsExplicitSpeedFailureReason(t *testing.T) {
	dir := t.TempDir()
	w := &LiveResultWriter{path: filepath.Join(dir, "result.txt"), started: time.Now(), phase: 1, phase1Seen: make(map[string]struct{})}
	w.AddPhase1(&result.Result{IP: net.ParseIP("104.18.1.1"), Port: 443, ProbeMode: "http", Latencies: []time.Duration{time.Millisecond}, TLSOk: true, HTTPStatus: 200, Colo: "FRA", SpeedTested: true, SpeedTestError: "download timeout"})
	b, err := os.ReadFile(w.path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "Speed test failures") || !strings.Contains(text, "104.18.1.1:443") || !strings.Contains(text, "download timeout") {
		t.Fatalf("missing explicit failure reason:\n%s", text)
	}
}
