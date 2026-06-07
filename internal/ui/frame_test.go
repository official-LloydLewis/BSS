package ui

import (
	"net"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/matinsenpai/senpaiscanner/internal/result"
)

func TestFixedFrameConstrainsWidthHeightAndPreservesStatusBar(t *testing.T) {
	view := "HEADER\n1234567890\ncontent\nSTATUS"
	got := fixedFrame(view, 6, 3)
	lines := strings.Split(got, "\n")
	if len(lines) != 3 {
		t.Fatalf("line count = %d, want 3: %q", len(lines), got)
	}
	if lines[0] != "HEADER" || lines[2] != "STATUS" {
		t.Fatalf("frame did not preserve header/status: %q", got)
	}
	for _, line := range lines {
		if lipgloss.Width(line) > 6 {
			t.Fatalf("line width = %d, want <= 6: %q", lipgloss.Width(line), line)
		}
	}
}

func TestWindowResizeUpdatesModifierControlsAndRenderedFrame(t *testing.T) {
	m := NewApp("test")
	model, _ := m.Update(tea.WindowSizeMsg{Width: 48, Height: 18})
	got := model.(AppModel)
	if got.modifierConfig.Width() > 40 || got.modifierInput.Width() > 40 {
		t.Fatalf("modifier textareas exceed content width: config=%d input=%d", got.modifierConfig.Width(), got.modifierInput.Width())
	}
	lines := strings.Split(got.View(), "\n")
	if len(lines) != 18 {
		t.Fatalf("rendered lines = %d, want 18", len(lines))
	}
}

func TestLiveScanViewShowsStableStatsAndRequiredResultColumns(t *testing.T) {
	m := NewApp("test")
	m.page = PageLiveScan
	m.width = 100
	m.height = 24
	m.scanTotal = 1000
	m.scanStarted = time.Now().Add(-2 * time.Second)
	m.scanStats = StatsMsg{Tested: 250, Healthy: 10, Failed: 240, InFlight: 5}
	m.scanResults = []*result.Result{{
		IP: net.ParseIP("104.18.1.1"), Port: 443, ProbeMode: "http",
		Latencies: []time.Duration{100 * time.Millisecond}, ConnectLatencies: []time.Duration{50 * time.Millisecond},
		TLSOk: true, HTTP2: true, HTTPStatus: 200, Colo: "FRA",
	}}

	view := ansiRE.ReplaceAllString(m.View(), "")
	for _, want := range []string{"IPs Scanned", "Remaining", "Good", "Failed", "Speed", "Elapsed", "RTT", "SCORE", "STABILITY", "TLS", "HTTP2"} {
		if !strings.Contains(view, want) {
			t.Fatalf("live scan view missing %q:\n%s", want, view)
		}
	}
	if len(strings.Split(m.View(), "\n")) != m.height {
		t.Fatalf("live view does not fill fixed terminal height")
	}
}

func TestUpsertIndexedResultReplacesWithoutGrowing(t *testing.T) {
	first := &result.Result{IP: net.ParseIP("1.1.1.1"), Port: 443}
	updated := &result.Result{IP: net.ParseIP("1.1.1.1"), Port: 443, TLSOk: true}
	rows, index := upsertIndexedResult(nil, nil, first)
	rows, index = upsertIndexedResult(rows, index, updated)
	if len(rows) != 1 || rows[0] != updated || len(index) != 1 {
		t.Fatalf("indexed upsert rows=%d index=%d result=%p, want replacement", len(rows), len(index), rows[0])
	}
}

func TestUpdateTopResultsKeepsBoundedSortedCache(t *testing.T) {
	var top []*result.Result
	for i := 40; i >= 1; i-- {
		r := &result.Result{IP: net.ParseIP("192.0.2.1"), Port: i, Latencies: []time.Duration{time.Duration(i) * time.Millisecond}}
		top = updateTopResults(top, r, result.SortByAvg, 5)
	}
	if len(top) != 5 {
		t.Fatalf("top cache length = %d, want 5", len(top))
	}
	for i, r := range top {
		if got, want := r.Port, i+1; got != want {
			t.Fatalf("top[%d] port = %d, want %d", i, got, want)
		}
	}
}
