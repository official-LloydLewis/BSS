package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	GoodIPsFile     = "good_ips.json"
	BadIPsFile      = "bad_ips.json"
	LastWorkingFile = "last_working.json"
	maxEntries      = 2000
	badSkipFailures = 3
)

type IPRecord struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port,omitempty"`
	Successes int       `json:"successes,omitempty"`
	Failures  int       `json:"failures,omitempty"`
	LastSeen  time.Time `json:"last_seen"`
}

type LastWorking struct {
	IPs     []string  `json:"ips,omitempty"`
	Configs []string  `json:"configs,omitempty"`
	Updated time.Time `json:"updated"`
}

func LoadGood(dir string) ([]IPRecord, error) { return loadRecords(filepath.Join(dir, GoodIPsFile)) }
func LoadBad(dir string) ([]IPRecord, error)  { return loadRecords(filepath.Join(dir, BadIPsFile)) }

func ShouldSkipBad(bad []IPRecord, ip string) bool {
	for _, r := range bad {
		if r.IP == ip && r.Failures >= badSkipFailures && time.Since(r.LastSeen) < 72*time.Hour {
			return true
		}
	}
	return false
}

func SaveResults(dir string, goodIPs, badIPs []string, port int) error {
	now := time.Now().UTC()
	good, _ := LoadGood(dir)
	bad, _ := LoadBad(dir)
	goodMap := recordsMap(good)
	badMap := recordsMap(bad)
	for _, ip := range goodIPs {
		r := goodMap[ip]
		r.IP = ip
		r.Port = port
		r.Successes++
		r.Failures = 0
		r.LastSeen = now
		goodMap[ip] = r
		delete(badMap, ip)
	}
	for _, ip := range badIPs {
		if _, ok := goodMap[ip]; ok {
			continue
		}
		r := badMap[ip]
		r.IP = ip
		r.Port = port
		r.Failures++
		if r.Failures > 10 {
			r.Failures = 10
		}
		r.LastSeen = now
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
	b = append(b, '\n')
	return os.WriteFile(path, b, 0644)
}

func recordsMap(records []IPRecord) map[string]IPRecord {
	m := make(map[string]IPRecord, len(records))
	for _, r := range records {
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
