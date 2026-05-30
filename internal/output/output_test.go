package output

import (
	"encoding/csv"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/result"
)

func TestCSVAndJSONIncludeCleanScoreFields(t *testing.T) {
	r := &result.Result{IP: net.ParseIP("1.1.1.1"), Port: 443, ProbeMode: "http", Latencies: []time.Duration{50 * time.Millisecond}, TLSOk: true, HTTPStatus: 200, Colo: "FRA", CleanScore: 92.5, LatencyScore: 100, LossScore: 100, JitterScore: 100, SpeedScore: 75, StabilityScore: 100, ProtocolScore: 100, FailureReason: ""}

	csvPath := t.TempDir() + "/out.csv"
	w, err := New(csvPath, FormatCSV)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(r); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(f).ReadAll()
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if rows[0][12] != "clean_score" || rows[1][12] != "92.50" || rows[0][19] != "failure_reason" {
		t.Fatalf("unexpected csv rows: %#v", rows)
	}

	jsonPath := t.TempDir() + "/out.jsonl"
	jw, err := New(jsonPath, FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := jw.Write(r); err != nil {
		t.Fatal(err)
	}
	if err := jw.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["clean_score"].(float64) != 92.5 || obj["protocol_score"].(float64) != 100 {
		t.Fatalf("missing json score fields: %s", body)
	}
}
