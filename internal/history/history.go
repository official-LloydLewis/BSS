package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/result"
)

const (
	GoodIPsFile     = "good_ips.json"
	BadIPsFile      = "bad_ips.json"
	LastWorkingFile = "last_working.json"
	maxEntries      = 2000
	badSkipFailures = 3
)

// IPRecord is the human-readable persistent record for a previously good IP.
// Legacy Port/Successes fields are accepted when reading older files.
type IPRecord struct {
	IP            string    `json:"ip"`
	BestPort      int       `json:"best_port,omitempty"`
	LastSeen      time.Time `json:"last_seen"`
	TimesSeen     int       `json:"times_seen,omitempty"`
	BestRTTMs     float64   `json:"best_rtt_ms,omitempty"`
	BestScore     float64   `json:"best_score,omitempty"`
	BestSpeedMbps float64   `json:"best_speed_mbps,omitempty"`
	Colo          string    `json:"colo,omitempty"`
	Port          int       `json:"port,omitempty"`
	Successes     int       `json:"successes,omitempty"`
	Failures      int       `json:"failures,omitempty"`
}

type LastWorking struct {
	IPs     []string  `json:"ips,omitempty"`
	Configs []string  `json:"configs,omitempty"`
	Updated time.Time `json:"updated"`
}

func LoadGood(dir string) ([]IPRecord, error) { return loadRecords(filepath.Join(dir, GoodIPsFile)) }

// LoadGoodLimit returns the strongest previous records first and caps how many
// are retested. A non-positive limit returns all records.
func LoadGoodLimit(dir string, limit int) ([]IPRecord, error) {
	records, err := LoadGood(dir)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].BestScore != records[j].BestScore {
			return records[i].BestScore > records[j].BestScore
		}
		if records[i].BestRTTMs != records[j].BestRTTMs {
			if records[i].BestRTTMs == 0 {
				return false
			}
			if records[j].BestRTTMs == 0 {
				return true
			}
			return records[i].BestRTTMs < records[j].BestRTTMs
		}
		return records[i].LastSeen.After(records[j].LastSeen)
	})
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}
func LoadBad(dir string) ([]IPRecord, error) { return loadRecords(filepath.Join(dir, BadIPsFile)) }

func ShouldSkipBad(bad []IPRecord, ip string) bool {
	for _, r := range bad {
		if r.IP == ip && r.Failures >= badSkipFailures && time.Since(r.LastSeen) < 72*time.Hour {
			return true
		}
	}
	return false
}

// SaveGoodResults merges healthy Phase 1 results into good_ips.json.
func SaveGoodResults(dir string, results []*result.Result) error {
	now := time.Now().UTC()
	records, _ := LoadGood(dir)
	m := recordsMap(records)
	seenThisScan := make(map[string]struct{})
	for _, r := range results {
		if r == nil || !r.IsHealthyForPhase1(result.DefaultMaxPhase1AvgLatency) || r.IP == nil {
			continue
		}
		ip := r.IP.String()
		rec := m[ip]
		rec.IP = ip
		if rec.BestPort == 0 {
			rec.BestPort = r.Port
		}
		if _, seen := seenThisScan[ip]; !seen {
			rec.TimesSeen++
			seenThisScan[ip] = struct{}{}
		}
		rec.LastSeen = now
		rtt := float64(r.RTT()) / float64(time.Millisecond)
		score := r.QualityScore()
		if rec.BestRTTMs == 0 || (rtt > 0 && rtt < rec.BestRTTMs) {
			rec.BestRTTMs = rtt
			rec.BestPort = r.Port
		}
		if score > rec.BestScore {
			rec.BestScore = score
			rec.BestPort = r.Port
		}
		if speed := r.SpeedMbps(); speed > rec.BestSpeedMbps {
			rec.BestSpeedMbps = speed
		}
		if r.Colo != "" {
			rec.Colo = r.Colo
		}
		rec.Port, rec.Successes = 0, 0
		m[ip] = rec
	}
	return writeRecords(filepath.Join(dir, GoodIPsFile), trim(recordsSlice(m), maxEntries))
}

// SaveResults retains the legacy good/bad update API used by other workflows.
func SaveResults(dir string, goodIPs, badIPs []string, port int) error {
	now := time.Now().UTC()
	good, _ := LoadGood(dir)
	bad, _ := LoadBad(dir)
	goodMap := recordsMap(good)
	badMap := recordsMap(bad)
	for _, ip := range goodIPs {
		r := goodMap[ip]
		r.IP, r.BestPort, r.LastSeen = ip, port, now
		r.TimesSeen++
		r.Failures = 0
		goodMap[ip] = r
		delete(badMap, ip)
	}
	for _, ip := range badIPs {
		if _, ok := goodMap[ip]; ok {
			continue
		}
		r := badMap[ip]
		r.IP, r.Port, r.LastSeen = ip, port, now
		r.Failures++
		if r.Failures > 10 {
			r.Failures = 10
		}
		badMap[ip] = r
	}
	if err := writeRecords(filepath.Join(dir, GoodIPsFile), trim(recordsSlice(goodMap), maxEntries)); err != nil {
		return err
	}
	return writeRecords(filepath.Join(dir, BadIPsFile), trim(recordsSlice(badMap), maxEntries))
}

func SaveLastWorking(dir string, ips, configs []string) error {
	return writeJSON(filepath.Join(dir, LastWorkingFile), LastWorking{IPs: ips, Configs: configs, Updated: time.Now().UTC()})
}

func loadRecords(path string) ([]IPRecord, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []IPRecord
	if err := json.Unmarshal(b, &records); err != nil {
		return nil, err
	}
	for i := range records {
		if records[i].BestPort == 0 {
			records[i].BestPort = records[i].Port
		}
		if records[i].TimesSeen == 0 {
			records[i].TimesSeen = records[i].Successes
		}
	}
	return records, nil
}

func writeRecords(path string, records []IPRecord) error { return writeJSON(path, records) }
func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}
func recordsMap(records []IPRecord) map[string]IPRecord {
	m := make(map[string]IPRecord, len(records))
	for _, r := range records {
		if r.IP == "" {
			continue
		}
		if old, ok := m[r.IP]; ok {
			if r.TimesSeen < old.TimesSeen {
				r.TimesSeen = old.TimesSeen
			}
			if r.BestScore < old.BestScore {
				r.BestScore = old.BestScore
				r.BestPort = old.BestPort
			}
			if r.BestRTTMs == 0 || (old.BestRTTMs > 0 && old.BestRTTMs < r.BestRTTMs) {
				r.BestRTTMs = old.BestRTTMs
				r.BestPort = old.BestPort
			}
			if r.BestSpeedMbps < old.BestSpeedMbps {
				r.BestSpeedMbps = old.BestSpeedMbps
			}
			if r.Colo == "" {
				r.Colo = old.Colo
			}
			if r.LastSeen.Before(old.LastSeen) {
				r.LastSeen = old.LastSeen
			}
		}
		m[r.IP] = r
	}
	return m
}
func recordsSlice(m map[string]IPRecord) []IPRecord {
	out := make([]IPRecord, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	return out
}
func trim(records []IPRecord, max int) []IPRecord {
	sort.Slice(records, func(i, j int) bool { return records[i].LastSeen.After(records[j].LastSeen) })
	if len(records) > max {
		return records[:max]
	}
	return records
}
