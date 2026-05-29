package ui

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/matinsenpai/senpaiscanner/internal/configgen"
	"github.com/matinsenpai/senpaiscanner/internal/engine"
	"github.com/matinsenpai/senpaiscanner/internal/history"
	"github.com/matinsenpai/senpaiscanner/internal/ipsrc"
	"github.com/matinsenpai/senpaiscanner/internal/output"
	"github.com/matinsenpai/senpaiscanner/internal/prober"
	"github.com/matinsenpai/senpaiscanner/internal/result"
	"github.com/matinsenpai/senpaiscanner/internal/xraytest"
)

type scanManager struct {
	mu     sync.Mutex
	cancel context.CancelFunc
}

func (s *scanManager) SetCancel(cancel context.CancelFunc) {
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
}

func (s *scanManager) Cancel() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *scanManager) Clear(cancel context.CancelFunc) {
	s.mu.Lock()
	if sameCancel(s.cancel, cancel) {
		s.cancel = nil
	}
	s.mu.Unlock()
}

var scans scanManager
var scanIDCounter atomic.Int64

func sameCancel(a, b context.CancelFunc) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

func nextScanID() int64 { return scanIDCounter.Add(1) }

// StartScanCmd builds a tea.Cmd that runs the scan engine in the background,
// sending ResultMsg and StatsMsg messages to the Bubble Tea program.
func StartScanCmd(cfg ScanConfig, scanID int64) tea.Cmd {
	return func() tea.Msg {
		go runScan(cfg, scanID)
		return nil
	}
}

// CancelScanCmd cancels the running scan.
func CancelScanCmd() tea.Cmd {
	return func() tea.Msg {
		scans.Cancel()
		return nil
	}
}

// StartTestCmd runs the test pass against a file of IPs.
func StartTestCmd(ipFile string, scanID int64) tea.Cmd {
	return func() tea.Msg {
		go runTest(ipFile, scanID)
		return nil
	}
}

// StartColosCmd discovers accessible Cloudflare PoPs.
func StartColosCmd(scanID int64) tea.Cmd {
	return func() tea.Msg {
		go runColos(scanID)
		return nil
	}
}

// prog is set by main before launching the Bubble Tea program so the
// background goroutines can send messages back.
var prog *tea.Program

// SetProgram must be called before any scan command is started.
func SetProgram(p *tea.Program) { prog = p }

// ---------------------------------------------------------------------------
// Background runners
// ---------------------------------------------------------------------------

func runScan(cfg ScanConfig, scanID int64) {
	count, _ := strconv.Atoi(cfg.Count)
	concurrency, _ := strconv.Atoi(cfg.Concurrency)
	if concurrency <= 0 {
		concurrency = 50
	}
	timeout := parseTimeout(cfg.Timeout, 5*time.Second)
	tries, _ := strconv.Atoi(cfg.Tries)
	if tries <= 0 {
		tries = 4
	}
	port, _ := strconv.Atoi(cfg.Port)
	if port <= 0 {
		port = 443
	}

	mode, err := prober.ParseMode(cfg.Mode)
	if err != nil {
		mode = prober.ModeHTTP
	}

	var extra []string
	for _, c := range strings.Split(cfg.CIDR, ",") {
		c = strings.TrimSpace(c)
		if c != "" {
			extra = append(extra, c)
		}
	}

	useBuiltin := len(extra) == 0
	src, err := ipsrc.NewWithOptions(cfg.UseV4, cfg.UseV6, extra, ipsrc.Options{UseBuiltin: useBuiltin})
	if err != nil {
		sendError(scanID, fmt.Sprintf("Scan setup failed: %v", err))
		sendDone(scanID)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	ctx = engine.WithStopCancel(ctx, cancel)
	scans.SetCancel(cancel)
	defer scans.Clear(cancel)
	defer cancel()

	engineStopAfter := cfg.StopAfterHealthy
	if strings.TrimSpace(cfg.ColoFilter) != "" {
		engineStopAfter = 0
	}
	engCfg := engine.Config{
		Concurrency:      concurrency,
		StopAfterHealthy: engineStopAfter,
		ProbeConfig: prober.Config{
			Port:       port,
			Mode:       mode,
			Tries:      tries,
			Timeout:    timeout,
			SNI:        cfg.SNI,
			SpeedBytes: speedSampleForMode(mode),
			WSTest:     false,
		},
	}
	eng := engine.New(engCfg)

	coloSet := buildColoSet(cfg.ColoFilter)
	var healthyForStop atomic.Int64
	var resultsMu sync.Mutex
	var goodIPs []string
	var badIPs []string

	var writer *output.Writer
	if cfg.OutputFile != "" {
		fmt2 := output.DetectFormat(cfg.OutputFile)
		if w, e := output.New(cfg.OutputFile, fmt2); e == nil {
			writer = w
			defer writer.Close()
		} else {
			sendError(scanID, fmt.Sprintf("Output disabled: %v", e))
		}
	}

	ipStream := src.Stream(ctx, count)
	if cfg.Emergency {
		ipStream = emergencyIPStream(ctx, src, count)
	}
	eng.Run(ctx, ipStream, func(r *result.Result) {
		if prog != nil {
			s := eng.Stats()
			prog.Send(StatsMsg{ScanID: scanID, Tested: s.Tested.Load(), Healthy: s.Healthy.Load(), Failed: s.Failed.Load(), InFlight: s.InFlight.Load()})
		}
		if !passesColoFilter(r, coloSet) {
			return
		}
		if r.IsHealthy() {
			resultsMu.Lock()
			goodIPs = append(goodIPs, r.IP.String())
			resultsMu.Unlock()
			if cfg.StopAfterHealthy > 0 && healthyForStop.Add(1) >= int64(cfg.StopAfterHealthy) {
				cancel()
			}
		} else if cfg.Emergency {
			resultsMu.Lock()
			badIPs = append(badIPs, r.IP.String())
			resultsMu.Unlock()
		}
		// Only healthy IPs go to the output file; writing every scanned IP
		// would flood the file with thousands of failed probes.
		if writer != nil && r.IsHealthy() {
			if err := writer.Write(r); err != nil {
				sendError(scanID, fmt.Sprintf("Output write failed: %v", err))
			}
		}
		if prog != nil {
			prog.Send(ResultMsg{ScanID: scanID, Result: r})
		}
	})

	if cfg.Emergency {
		resultsMu.Lock()
		goodCopy := append([]string(nil), goodIPs...)
		badCopy := append([]string(nil), badIPs...)
		resultsMu.Unlock()
		runEmergencyExports(scanID, cfg, goodCopy, badCopy, port)
	}
	sendDone(scanID)
}

func runTest(ipFile string, scanID int64) {
	ips, err := loadIPs(ipFile)
	if err != nil {
		sendError(scanID, fmt.Sprintf("Test IPs failed: %v", err))
		sendDone(scanID)
		return
	}
	if len(ips) == 0 {
		sendError(scanID, fmt.Sprintf("Test IPs failed: no valid IPs found in %s", ipFile))
		sendDone(scanID)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	scans.SetCancel(cancel)
	defer scans.Clear(cancel)
	defer cancel()

	engCfg := engine.Config{
		Concurrency: 20,
		ProbeConfig: prober.Config{
			Port:       443,
			Mode:       prober.ModeHTTP,
			Tries:      6,
			Timeout:    10 * time.Second,
			SNI:        "speed.cloudflare.com",
			SpeedBytes: 512 * 1024,
		},
	}
	eng := engine.New(engCfg)

	eng.RunList(ctx, ips, func(r *result.Result) {
		if prog != nil {
			s := eng.Stats()
			prog.Send(ResultMsg{ScanID: scanID, Result: r})
			prog.Send(StatsMsg{ScanID: scanID, Tested: s.Tested.Load(), Healthy: s.Healthy.Load(), Failed: s.Failed.Load(), InFlight: s.InFlight.Load()})
		}
	})

	sendDone(scanID)
}

func runColos(scanID int64) {
	src, err := ipsrc.New(true, false, nil)
	if err != nil {
		sendError(scanID, fmt.Sprintf("Colo discovery failed: %v", err))
		sendColosDone(scanID)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	scans.SetCancel(cancel)
	defer scans.Clear(cancel)
	defer cancel()

	engCfg := engine.Config{
		Concurrency: 80,
		ProbeConfig: prober.Config{
			Port:       443,
			Mode:       prober.ModeHTTP,
			Tries:      2,
			Timeout:    5 * time.Second,
			SpeedBytes: 0,
		},
	}
	eng := engine.New(engCfg)
	ipStream := src.Stream(ctx, 300)

	eng.Run(ctx, ipStream, func(r *result.Result) {
		if prog != nil {
			s := eng.Stats()
			prog.Send(StatsMsg{ScanID: scanID, Tested: s.Tested.Load(), Healthy: s.Healthy.Load(), Failed: s.Failed.Load(), InFlight: s.InFlight.Load()})
		}
		if !r.IsHealthy() || r.Colo == "" {
			return
		}
		if prog != nil {
			prog.Send(ResultMsg{ScanID: scanID, Result: r})
		}
	})

	sendColosDone(scanID)
}

func sendError(scanID int64, text string) {
	if prog != nil {
		prog.Send(ErrorMsg{ScanID: scanID, Text: text})
	}
}

func sendDone(scanID int64) {
	if prog != nil {
		prog.Send(DoneMsg{ScanID: scanID})
	}
}

func sendColosDone(scanID int64) {
	if prog != nil {
		prog.Send(ColosDoneMsg{ScanID: scanID})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func buildColoSet(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	set := make(map[string]bool)
	for _, c := range strings.Split(raw, ",") {
		c = strings.TrimSpace(strings.ToUpper(c))
		if c != "" {
			set[c] = true
		}
	}
	return set
}

func passesColoFilter(r *result.Result, set map[string]bool) bool {
	if set == nil {
		return true
	}
	return set[strings.ToUpper(r.Colo)]
}

func loadIPs(path string) ([]net.IP, error) {
	var f *os.File
	var err error
	if path == "" || path == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
	}
	var ips []net.IP
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "ip") {
			continue
		}
		field := strings.SplitN(line, ",", 2)[0]
		if ip := net.ParseIP(strings.TrimSpace(field)); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, sc.Err()
}

func speedSampleForMode(mode prober.Mode) int64 {
	if mode != prober.ModeHTTP {
		return 0
	}
	// 64 KB is enough to detect IPs that stall on real data while still
	// completing reliably on restricted/high-latency networks. 256 KB was too
	// large: on throttled connections it consistently timed out, making every
	// IP appear unhealthy even when the trace GET succeeded fine.
	return 64 * 1024
}

func parseTimeout(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if timeout, err := time.ParseDuration(raw); err == nil {
		return timeout
	}
	if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}

func emergencyIPStream(ctx context.Context, src *ipsrc.Source, count int) <-chan net.IP {
	out := make(chan net.IP, 64)
	go func() {
		defer close(out)
		sent := 0
		seen := map[string]struct{}{}
		bad, _ := history.LoadBad(".")
		good, _ := history.LoadGood(".")
		for _, rec := range good {
			if count > 0 && sent >= count {
				return
			}
			if history.ShouldSkipBad(bad, rec.IP) {
				continue
			}
			ip := net.ParseIP(rec.IP)
			if ip == nil {
				continue
			}
			seen[rec.IP] = struct{}{}
			select {
			case <-ctx.Done():
				return
			case out <- ip:
				sent++
			}
		}
		for ip := range src.Stream(ctx, count) {
			if count > 0 && sent >= count {
				return
			}
			key := ip.String()
			if _, ok := seen[key]; ok || history.ShouldSkipBad(bad, key) {
				continue
			}
			seen[key] = struct{}{}
			select {
			case <-ctx.Done():
				return
			case out <- ip:
				sent++
			}
		}
	}()
	return out
}

func runEmergencyExports(scanID int64, cfg ScanConfig, goodIPs, badIPs []string, port int) {
	if err := history.SaveResults(".", goodIPs, badIPs, port); err != nil {
		sendError(scanID, fmt.Sprintf("history save failed: %v", err))
	}
	if err := output.WriteLines("good_ips.txt", goodIPs); err != nil {
		sendError(scanID, fmt.Sprintf("good_ips.txt failed: %v", err))
	}
	ipPorts := make([]string, 0, len(goodIPs))
	for _, ip := range goodIPs {
		ipPorts = append(ipPorts, net.JoinHostPort(ip, strconv.Itoa(port)))
	}
	if err := output.WriteLines("ip_port.txt", ipPorts); err != nil {
		sendError(scanID, fmt.Sprintf("ip_port.txt failed: %v", err))
	}

	base := strings.TrimSpace(cfg.BaseConfig)
	if base == "" || len(goodIPs) == 0 {
		_ = history.SaveLastWorking(".", goodIPs, nil)
		return
	}
	ips := make([]net.IP, 0, len(goodIPs))
	for _, s := range goodIPs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	generated, err := configgen.Generate(base, ips)
	if err != nil {
		sendError(scanID, fmt.Sprintf("config generation failed: %v", err))
		return
	}
	if err := output.WriteLines("generated_configs.txt", generated); err != nil {
		sendError(scanID, fmt.Sprintf("generated_configs.txt failed: %v", err))
	}
	working, failed, stable := validateEmergencyConfigs(scanID, generated)
	_ = output.WriteLines("working_configs.txt", working)
	_ = output.WriteLines("failed_configs.txt", failed)
	_ = output.WriteLines("stable_configs.txt", stable)
	_ = history.SaveLastWorking(".", goodIPs, stable)
}

func validateEmergencyConfigs(scanID int64, configs []string) (working, failed, stable []string) {
	limit := len(configs)
	if limit > 10 {
		limit = 10
	}
	for i := 0; i < limit; i++ {
		raw := configs[i]
		cfg, err := xraytest.ParseVLESS(raw)
		if err != nil {
			failed = append(failed, raw)
			sendError(scanID, "Xray validation skipped for non-VLESS configs; generated_configs.txt was still written")
			continue
		}
		ctx := context.Background()
		vr := xraytest.ValidateConfig(ctx, cfg, 20*time.Second)
		if prog != nil {
			prog.Send(ConfigProgressMsg{Result: vr, Done: i + 1, Total: limit})
		}
		if !vr.Success {
			failed = append(failed, raw)
			continue
		}
		working = append(working, raw)
		successes := 1
		for attempt := 1; attempt < 3; attempt++ {
			time.Sleep(500 * time.Millisecond)
			if xraytest.ValidateConfig(ctx, cfg, 15*time.Second).Success {
				successes++
			}
		}
		if successes == 3 {
			stable = append(stable, raw)
		}
	}
	return working, failed, stable
}
