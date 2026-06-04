// Package config holds default value constants for scan and test operations.
// The TUI reads these defaults when building form initial values.
package config

import "time"

// ScanDefaults are the factory defaults shown in the scan config form.
var ScanDefaults = struct {
	Count       int
	Concurrency int
	Timeout     time.Duration
	Tries       int
	Port        int
	Mode        string
	UseV4       bool
	UseV6       bool
	Top         int
}{
	Count:       500,
	Concurrency: 50,
	Timeout:     5 * time.Second,
	Tries:       4,
	Port:        443,
	Mode:        "http",
	UseV4:       true,
	UseV6:       false,
	Top:         10,
}

// Smart discovery defaults keep quality improvements bounded so Phase 1 scan
// time remains close to a basic connectivity scan.
const (
	MaxSpeedTestCandidates = 100
	SpeedTestBytes         = 256 * 1024
	MaxPreviousGoodIPs     = 500
	MaxPreviousExpandSeeds = 20
)
