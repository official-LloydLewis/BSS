package output

import (
	"encoding/csv"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/result"
)

func TestDetailedOutputsIncludeQualityScore(t *testing.T) {
	r := &result.Result{
		IP:               net.ParseIP("104.18.1.1"),
		Port:             443,
		ProbeMode:        "http",
		Latencies:        []time.Duration{500 * time.Millisecond},
		ConnectLatencies: []time.Duration{100 * time.Millisecond},
		TLSOk:            true,
		HTTPStatus:       200,
		Colo:             "FRA",
		Throughput:       256 * 1024,
		SpeedTested:      true,
		SpeedTestError:   "sample warning",
	}

	t.Run("CSV", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "results.csv")
		w, err := New(path, FormatCSV)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		records, err := csv.NewReader(f).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 2 || len(records[0]) < 5 || records[0][1] != "quality_score" || records[1][1] == "" {
			t.Fatalf("CSV missing quality score: %v", records)
		}
		if records[0][13] != "speed_test_error" || records[1][13] != "sample warning" {
			t.Fatalf("CSV missing speed error: %v", records)
		}
		if records[0][3] != "rtt_ms" || records[1][3] != "100.00" || records[0][4] != "avg_ms" || records[1][4] != "500.00" || records[0][5] != "probe_avg_ms" || records[1][5] != "500.00" {
			t.Fatalf("CSV missing separate RTT/probe timings: %v", records)
		}
	})

	t.Run("JSON", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "results.jsonl")
		w, err := New(path, FormatJSON)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]any
		if err := json.Unmarshal(b, &obj); err != nil {
			t.Fatal(err)
		}
		if _, ok := obj["quality_score"]; !ok {
			t.Fatalf("JSON missing quality_score: %s", b)
		}
		if obj["speed_test_error"] != "sample warning" {
			t.Fatalf("JSON missing speed error: %s", b)
		}
		if obj["rtt_ms"] != float64(100) || obj["probe_avg_ms"] != float64(500) {
			t.Fatalf("JSON missing separate RTT/probe timings: %s", b)
		}
	})
}
