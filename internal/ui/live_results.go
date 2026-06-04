package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/config"
	"github.com/matinsenpai/senpaiscanner/internal/ipsrc"
	"github.com/matinsenpai/senpaiscanner/internal/result"
	"github.com/matinsenpai/senpaiscanner/internal/xraytest"
)

var liveResultWriter *LiveResultWriter

func setLiveResultWriter(w *LiveResultWriter) { liveResultWriter = w }

func clearLiveResultWriter() { liveResultWriter = nil }

// LiveResultWriter appends scan results to a text file the user can open while
// the scan runs. The file is rewritten on each update so external viewers refresh.
type LiveResultWriter struct {
	mu sync.Mutex

	path         string
	started      time.Time
	withConfig   bool
	phase        int
	phase1Only   bool
	phase1Done   bool
	phase1Rows   []*result.Result
	phase1Seen   map[string]struct{}
	phase2Rows   []*xraytest.ValidationResult
	phase1Probed int
	discovery    phase1DiscoveryStats
}

func newLiveResultWriter(withConfig bool) (*LiveResultWriter, string, error) {
	path, err := liveResultFilePath()
	if err != nil {
		return nil, "", err
	}
	w := &LiveResultWriter{
		path:       path,
		started:    time.Now(),
		withConfig: withConfig,
		phase:      1,
		phase1Seen: make(map[string]struct{}),
	}
	if err := w.flush(); err != nil {
		return nil, "", err
	}
	return w, path, nil
}

func liveResultFilePath() (string, error) {
	name := fmt.Sprintf("BSSResult-%s.txt", time.Now().Format("20060102-150405"))
	for _, dir := range resultFileDirs() {
		if dir == "" {
			continue
		}
		return filepath.Join(dir, name), nil
	}
	return name, nil
}

func resultFileDirs() []string {
	seen := make(map[string]struct{})
	var dirs []string
	add := func(dir string) {
		if dir == "" {
			return
		}
		if _, ok := seen[dir]; ok {
			return
		}
		seen[dir] = struct{}{}
		dirs = append(dirs, dir)
	}
	if wd, err := os.Getwd(); err == nil {
		add(wd)
	}
	if exe, err := os.Executable(); err == nil {
		add(filepath.Dir(exe))
	}
	return dirs
}

func (w *LiveResultWriter) AddPhase1(r *result.Result) {
	if w == nil || r == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.phase1Seen == nil {
		w.phase1Seen = make(map[string]struct{})
	}
	key := formatEndpoint(r.IP.String(), r.Port)
	if _, ok := w.phase1Seen[key]; !ok {
		w.phase1Seen[key] = struct{}{}
		w.phase1Probed++
	}
	if r.IsHealthyForPhase1(result.DefaultMaxPhase1AvgLatency) {
		w.phase1Rows = upsertPhase1Result(w.phase1Rows, r)
	}
	_ = w.writeLocked()
}

func (w *LiveResultWriter) SetDiscoveryStats(stats phase1DiscoveryStats) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.discovery = stats
	_ = w.writeLocked()
}

func (w *LiveResultWriter) BeginPhase2() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.phase = 2
	w.phase1Done = true
	w.phase2Rows = nil
	_ = w.writeLocked()
}

func (w *LiveResultWriter) FinishPhase1Only() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.phase1Only = true
	w.phase1Done = true
	_ = w.writeLocked()
}

func (w *LiveResultWriter) AddPhase2(v *xraytest.ValidationResult) {
	if w == nil || v == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.phase2Rows = append(w.phase2Rows, v)
	_ = w.writeLocked()
}

func (w *LiveResultWriter) flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeLocked()
}

func (w *LiveResultWriter) writeLocked() error {
	var sb strings.Builder
	sb.WriteString("BSS (Better Senpai Scanner) — live results\n")
	sb.WriteString(fmt.Sprintf("Started: %s\n", w.started.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Updated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	if w.withConfig {
		sb.WriteString("Plan: Phase 1 connectivity, then Phase 2 xray validation\n")
	} else {
		sb.WriteString("Plan: Phase 1 connectivity only\n")
	}
	sb.WriteString("\n")

	healthy := len(w.phase1Rows)
	sb.WriteString(fmt.Sprintf("=== Phase 1 — connectivity (%d healthy / %d probed) ===\n", healthy, w.phase1Probed))
	s := w.discovery
	sb.WriteString(fmt.Sprintf("Previous good IPs loaded/retested/healthy: %d/%d/%d\n", s.PreviousLoaded, s.PreviousRetested, s.PreviousHealthy))
	sb.WriteString(fmt.Sprintf("Neighbor seeds/queued/tested: %d/%d/%d (defaults: top %d, %d/seed, max %d)\n", s.SeedsExpanded, s.NeighborQueued, s.NeighborTested, ipsrc.DefaultNeighborSeedLimit, ipsrc.DefaultNeighborPerHit, ipsrc.DefaultNeighborMaxTotal))
	sb.WriteString(fmt.Sprintf("Speed tests scheduled/started/completed/failed: %d/%d/%d/%d (default: top %d only)\n\n", s.SpeedTestsScheduled, s.SpeedTestsStarted, s.SpeedTestsCompleted, s.SpeedTestsFailed, config.MaxSpeedTestCandidates))
	sb.WriteString(fmt.Sprintf("  %-22s  %7s  %9s  %10s  %11s  %7s  %8s  %6s\n", "ENDPOINT", "SCORE", "RTT(ms)", "PROBE(ms)", "SPEED(Mbps)", "LOSS", "COLO", "STATUS"))
	sb.WriteString("  " + strings.Repeat("─", 112) + "\n")

	rows := append([]*result.Result(nil), w.phase1Rows...)
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].RTT() < rows[j].RTT()
	})
	if len(rows) == 0 {
		sb.WriteString("  (no healthy results yet)\n")
	} else {
		for _, r := range rows {
			colo := r.Colo
			if colo == "" {
				colo = "—"
			}
			status := "healthy"
			if !r.IsHealthyForPhase1(result.DefaultMaxPhase1AvgLatency) {
				status = "fail"
			} else if r.SpeedTested && r.Throughput <= 0 {
				status = "healthy; speed fail"
			}
			sb.WriteString(fmt.Sprintf("  %-22s  %7.1f  %9.2f  %10.2f  %11s  %6.1f%%  %-8s  %s\n",
				formatEndpoint(r.IP.String(), r.Port),
				r.QualityScore(),
				float64(r.RTT().Milliseconds()),
				float64(r.Avg().Milliseconds()),
				formatPhase1Speed(r),
				r.Loss(),
				colo,
				status,
			))
		}
	}

	if stats := result.ColoStats(w.phase1Rows); len(stats) > 0 {
		sb.WriteString("\n=== Colo summary ===\n\n")
		sb.WriteString(fmt.Sprintf("  %-6s  %7s  %9s  %9s  %11s  %s\n", "COLO", "HEALTHY", "AVG RTT", "AVG SCORE", "AVG SPEED", "BEST IP"))
		for _, stat := range stats {
			speed := "—"
			if stat.AvgSpeedMbps > 0 {
				speed = fmt.Sprintf("%.2fMbps", stat.AvgSpeedMbps)
			}
			sb.WriteString(fmt.Sprintf("  %-6s  %7d  %7dms  %9.1f  %11s  %s\n", stat.Colo, stat.HealthyCount, stat.AvgRTT.Milliseconds(), stat.AvgScore, speed, stat.BestIP))
		}
	}

	if w.phase >= 2 && !w.phase1Only {
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("=== Phase 2 — xray validation (%d tested) ===\n\n", len(w.phase2Rows)))
		sb.WriteString(fmt.Sprintf("  %-22s  %-8s  %8s  %8s  %6s\n", "ENDPOINT", "TYPE", "SPEED", "LATENCY", "STATUS"))
		sb.WriteString("  " + strings.Repeat("─", 64) + "\n")
		if len(w.phase2Rows) == 0 {
			sb.WriteString("  (no validation results yet)\n")
		} else {
			for _, r := range w.phase2Rows {
				status := "fail"
				speed := "—"
				latency := "—"
				if r.Success {
					status = "ok"
					speed = formatValidationSpeed(r.Throughput)
					latency = formatValidationLatency(r.Latency)
				}
				sb.WriteString(fmt.Sprintf("  %-22s  %-8s  %8s  %8s  %6s\n",
					formatEndpoint(r.IP, r.Port),
					r.Transport,
					speed,
					latency,
					status,
				))
			}
		}
	}

	return os.WriteFile(w.path, []byte(sb.String()), 0644)
}
