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
		IP:         net.ParseIP("104.18.1.1"),
		Port:       443,
		ProbeMode:  "http",
		Latencies:  []time.Duration{100 * time.Millisecond},
		TLSOk:      true,
		HTTPStatus: 200,
		Colo:       "FRA",
		Throughput: 256 * 1024,
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
		if len(records) != 2 || len(records[0]) < 2 || records[0][1] != "quality_score" || records[1][1] == "" {
			t.Fatalf("CSV missing quality score: %v", records)
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
	})
}
