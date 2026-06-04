package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/result"
)

// Format identifies the output format.
type Format int

const (
	FormatCSV Format = iota
	FormatJSON
	FormatTXT
)

// DetectFormat infers the output format from the file extension.
func DetectFormat(path string) Format {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".jsonl":
		return FormatJSON
	case ".txt":
		return FormatTXT
	default:
		return FormatCSV
	}
}

// Writer writes results to a file in a thread-safe manner.
//
// JSON output uses newline-delimited JSON (JSONL / JSON Lines): one JSON object
// per line, with no enclosing array. Each line is a self-contained, valid JSON
// value, so the file remains fully readable even if the process is interrupted
// mid-scan. Readers can parse it with standard JSON streaming libraries or a
// simple line-by-line loop.
type Writer struct {
	mu  sync.Mutex
	f   *os.File
	fmt Format
	csv *csv.Writer
}

// New creates (or truncates) the output file and returns a ready Writer.
func New(path string, fmt Format) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt2err(path, err)
	}

	w := &Writer{f: f, fmt: fmt}

	if fmt == FormatCSV {
		w.csv = csv.NewWriter(f)
		_ = w.csv.Write([]string{
			"ip", "quality_score", "loss_pct", "rtt_ms", "avg_ms", "probe_avg_ms", "min_ms", "max_ms",
			"jitter_ms", "speed_mbps", "download_bytes", "download_elapsed_ms", "speed_tested", "speed_test_error", "colo", "tls_ok", "ws_ok", "http_status",
		})
		w.csv.Flush()
	}

	return w, nil
}

// Write appends a result to the output file.
func (w *Writer) Write(r *result.Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.fmt {
	case FormatCSV:
		return w.writeCSV(r)
	case FormatJSON:
		return w.writeJSON(r)
	default:
		return w.writeTXT(r)
	}
}

// Close flushes and closes the underlying file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.csv != nil {
		w.csv.Flush()
	}
	return w.f.Close()
}

func (w *Writer) writeCSV(r *result.Result) error {
	row := []string{
		r.IP.String(),
		fmt.Sprintf("%.1f", r.QualityScore()),
		fmt.Sprintf("%.1f", r.Loss()),
		fmt.Sprintf("%.2f", float64(r.RTT().Milliseconds())),
		fmt.Sprintf("%.2f", float64(r.Avg().Milliseconds())),
		fmt.Sprintf("%.2f", float64(r.Avg().Milliseconds())),
		fmt.Sprintf("%.2f", float64(r.Min().Milliseconds())),
		fmt.Sprintf("%.2f", float64(r.Max().Milliseconds())),
		fmt.Sprintf("%.2f", float64(r.Jitter().Milliseconds())),
		fmt.Sprintf("%.2f", r.SpeedMbps()),
		fmt.Sprintf("%d", r.DownloadBytes),
		fmt.Sprintf("%.2f", float64(r.DownloadElapsed)/float64(time.Millisecond)),
		boolStr(r.SpeedTested),
		r.SpeedTestError,
		r.Colo,
		boolStr(r.TLSOk),
		boolStr(r.WSOk),
		fmt.Sprintf("%d", r.HTTPStatus),
	}
	w.csv.Write(row)
	w.csv.Flush()
	return w.csv.Error()
}

// writeJSON appends one JSONL record (no trailing comma, no enclosing array).
func (w *Writer) writeJSON(r *result.Result) error {
	type jsonResult struct {
		IP                string  `json:"ip"`
		QualityScore      float64 `json:"quality_score"`
		LossPct           float64 `json:"loss_pct"`
		RTTMs             float64 `json:"rtt_ms"`
		AvgMs             float64 `json:"avg_ms"`
		ProbeAvgMs        float64 `json:"probe_avg_ms"`
		MinMs             float64 `json:"min_ms"`
		MaxMs             float64 `json:"max_ms"`
		JitterMs          float64 `json:"jitter_ms"`
		SpeedMbps         float64 `json:"speed_mbps,omitempty"`
		DownloadBytes     int64   `json:"download_bytes,omitempty"`
		DownloadElapsedMs float64 `json:"download_elapsed_ms,omitempty"`
		SpeedTested       bool    `json:"speed_tested,omitempty"`
		SpeedTestError    string  `json:"speed_test_error,omitempty"`
		Colo              string  `json:"colo,omitempty"`
		TLSOk             bool    `json:"tls_ok"`
		WSOk              bool    `json:"ws_ok"`
		HTTPStatus        int     `json:"http_status,omitempty"`
	}
	obj := jsonResult{
		IP:                r.IP.String(),
		QualityScore:      r.QualityScore(),
		LossPct:           r.Loss(),
		RTTMs:             ms(r.RTT()),
		AvgMs:             ms(r.Avg()),
		ProbeAvgMs:        ms(r.Avg()),
		MinMs:             ms(r.Min()),
		MaxMs:             ms(r.Max()),
		JitterMs:          ms(r.Jitter()),
		SpeedMbps:         r.SpeedMbps(),
		DownloadBytes:     r.DownloadBytes,
		DownloadElapsedMs: float64(r.DownloadElapsed) / float64(time.Millisecond),
		SpeedTested:       r.SpeedTested,
		SpeedTestError:    r.SpeedTestError,
		Colo:              r.Colo,
		TLSOk:             r.TLSOk,
		WSOk:              r.WSOk,
		HTTPStatus:        r.HTTPStatus,
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.f.Write(b)
	return err
}

func (w *Writer) writeTXT(r *result.Result) error {
	// Plain IP-per-line format so the file can be pasted directly into
	// proxy / VPN tools (Xray, Sing-Box, etc.) without editing.
	_, err := w.f.WriteString(r.IP.String() + "\n")
	return err
}

// --- helpers -----------------------------------------------------------------

func ms(d interface{ Milliseconds() int64 }) float64 {
	return float64(d.Milliseconds())
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func fmt2err(path string, err error) error {
	return fmt.Errorf("opening output file %q: %w", path, err)
}
