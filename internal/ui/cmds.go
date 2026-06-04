package ui

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/matinsenpai/senpaiscanner/internal/config"
	"github.com/matinsenpai/senpaiscanner/internal/engine"
	"github.com/matinsenpai/senpaiscanner/internal/history"
	"github.com/matinsenpai/senpaiscanner/internal/ipsrc"
	"github.com/matinsenpai/senpaiscanner/internal/output"
	"github.com/matinsenpai/senpaiscanner/internal/prober"
	"github.com/matinsenpai/senpaiscanner/internal/result"
	"github.com/matinsenpai/senpaiscanner/internal/xraytest"
)

// scanCancel holds the cancel function for the active scan so the TUI can
// abort it when the user presses esc/q.
var scanCancel context.CancelFunc
var scanIDCounter atomic.Int64

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
		if scanCancel != nil {
			scanCancel()
		}
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
	scanCancel = cancel
	defer cancel()

	speedBytes := speedSampleForMode(mode)
	engCfg := engine.Config{
		Concurrency: concurrency,
		ProbeConfig: prober.Config{
			Port:             port,
			Mode:             mode,
			Tries:            tries,
			Timeout:          timeout,
			SNI:              cfg.SNI,
			SpeedBytes:       0,
			RequireWebSocket: mode == prober.ModeHTTP && speedBytes > 0,
		},
	}
	eng := engine.New(engCfg)

	coloSet := buildColoSet(cfg.ColoFilter)

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
	var scanMu sync.Mutex
	var scanResults []*result.Result
	sendResult := func(r *result.Result) {
		if !passesColoFilter(r, coloSet) {
			return
		}
		if prog != nil {
			prog.Send(ResultMsg{ScanID: scanID, Result: r})
		}
	}
	eng.Run(ctx, ipStream, func(r *result.Result) {
		scanMu.Lock()
		scanResults = append(scanResults, r)
		scanMu.Unlock()
		if prog != nil {
			s := eng.Stats()
			prog.Send(StatsMsg{ScanID: scanID, Tested: s.Tested.Load(), Healthy: s.Healthy.Load(), Failed: s.Failed.Load(), InFlight: s.InFlight.Load()})
		}
		sendResult(r)
	})
	if ctx.Err() == nil && speedBytes > 0 {
		sendSpeedResult := func(r *result.Result) {
			scanResults = upsertPhase1Result(scanResults, r)
			sendResult(r)
		}
		runCappedSpeedTests(ctx, scanResults, concurrency, engCfg.ProbeConfig, speedBytes, config.MaxSpeedTestCandidates, prober.SpeedTest, sendSpeedResult, &phase1DiscoveryStats{}, nil)
	}
	if writer != nil {
		for _, r := range result.TopN(scanResults, 0) {
			if passesColoFilter(r, coloSet) {
				if err := writer.Write(r); err != nil {
					sendError(scanID, fmt.Sprintf("Output write failed: %v", err))
					break
				}
			}
		}
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
	scanCancel = cancel
	defer cancel()

	engCfg := engine.Config{
		Concurrency: 20,
		ProbeConfig: prober.Config{
			Port:             443,
			Mode:             prober.ModeHTTP,
			Tries:            6,
			Timeout:          10 * time.Second,
			SNI:              "speed.cloudflare.com",
			SpeedBytes:       512 * 1024,
			RequireWebSocket: true,
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
	scanCancel = cancel
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

// runConfigPhase1 runs Phase 1 of "Scan with Config": a fast connectivity scan
// that finds healthy Cloudflare IPs (or validates IPs from a file), then signals
// the UI to start Phase 2 (xray validation) with the best candidates.
func runConfigPhase1(opts configPhase1Options) {
	var probeCfg prober.Config
	var err error
	if strings.TrimSpace(opts.rawURL) == "" {
		probeCfg = defaultPhase1ProbeConfig(opts.timeout)
	} else {
		probeCfg, err = configProbeFromURL(opts.rawURL, opts.timeout)
		if err != nil {
			if prog != nil {
				prog.Send(ConfigPhase1ErrMsg{Err: fmt.Sprintf("invalid URL: %v", err)})
			}
			return
		}
	}
	ports := opts.ports
	if len(ports) == 0 {
		ports = []int{probeCfg.Port}
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	defer cancel()

	var phase1Results []*result.Result
	phase1Index := make(map[string]int)
	callback := func(r *result.Result) {
		key := fmt.Sprintf("%s:%d", r.IP.String(), r.Port)
		if idx, ok := phase1Index[key]; ok {
			phase1Results[idx] = r
		} else {
			phase1Index[key] = len(phase1Results)
			phase1Results = append(phase1Results, r)
		}
		if liveResultWriter != nil {
			liveResultWriter.AddPhase1(r)
		}
		if prog != nil {
			prog.Send(ConfigPhase1ResultMsg{Result: r})
		}
	}

	goodRecords, historyErr := history.LoadGoodLimit(".", config.MaxPreviousGoodIPs)
	if historyErr != nil && prog != nil {
		prog.Send(ConfigPhase1WarningMsg{Text: fmt.Sprintf("warning: ignoring corrupt %s: %v", history.GoodIPsFile, historyErr)})
	}
	previous := make([]net.IP, 0, len(goodRecords))
	for _, rec := range goodRecords {
		if ip := net.ParseIP(rec.IP); ip != nil {
			previous = append(previous, ip)
		}
	}
	if prog != nil {
		prog.Send(ConfigPhase1StatsMsg{PreviousLoaded: len(previous)})
	}

	var ipStream <-chan net.IP
	neighbor := neighborScanOpts{maxSpeedCandidates: config.MaxSpeedTestCandidates, speedBytes: config.SpeedTestBytes}
	if opts.fromFile {
		ips, err := loadDefaultIPsFile()
		if err != nil {
			if prog != nil {
				prog.Send(ConfigPhase1ErrMsg{Err: err.Error()})
			}
			return
		}
		if len(ips) == 0 {
			if prog != nil {
				prog.Send(ConfigPhase1ErrMsg{Err: "ips.txt is empty — add one IP per line"})
			}
			return
		}
		ch := make(chan net.IP, len(ips))
		for _, ip := range ips {
			ch <- ip
		}
		close(ch)
		ipStream = ch
	} else {
		src, err := ipsrc.New(true, false, nil)
		if err != nil {
			if prog != nil {
				prog.Send(ConfigPhase1DoneMsg{})
			}
			return
		}
		ipStream = prioritizedIPStream(ctx, previous, src.Stream(ctx, opts.count))
		neighbor = neighborScanOpts{
			enabled:            true,
			nets:               src.IPv4Nets(),
			maxSeeds:           ipsrc.DefaultNeighborSeedLimit,
			perHit:             ipsrc.DefaultNeighborPerHit,
			maxTotal:           ipsrc.DefaultNeighborMaxTotal,
			previous:           ipSet(previous),
			previousExpandable: ipSet(previous[:minInt(len(previous), config.MaxPreviousExpandSeeds)]),
			onStats: func(stats phase1DiscoveryStats) {
				if liveResultWriter != nil {
					liveResultWriter.SetDiscoveryStats(stats)
				}
				if prog != nil {
					prog.Send(ConfigPhase1StatsMsg{Discovery: stats})
				}
			},
		}
	}
	runConfigPortProbes(ctx, ipStream, ports, opts.concurrency, probeCfg, callback, neighbor)
	if err := history.SaveGoodResults(".", phase1Results); err != nil && prog != nil {
		prog.Send(ConfigPhase1WarningMsg{Text: fmt.Sprintf("warning: failed to save %s: %v", history.GoodIPsFile, err)})
	}

	if prog != nil {
		prog.Send(ConfigPhase1DoneMsg{})
	}
}

type configProbeJob struct {
	ip       net.IP
	port     int
	neighbor bool
}

type phase1DiscoveryStats struct {
	SeedsExpanded, NeighborQueued, NeighborTested     int
	PreviousLoaded, PreviousRetested, PreviousHealthy int
	SpeedTestCandidates, SpeedTested                  int
}

type neighborScanOpts struct {
	enabled            bool
	nets               []*net.IPNet
	maxSeeds           int
	perHit             int
	maxTotal           int
	previous           map[string]struct{}
	previousExpandable map[string]struct{}
	maxSpeedCandidates int
	speedBytes         int64
	onStats            func(phase1DiscoveryStats)
}

type probeFunc func(context.Context, net.IP, prober.Config) *result.Result
type speedTestFunc func(context.Context, *result.Result, prober.Config, int64)

func runConfigPortProbes(ctx context.Context, ips <-chan net.IP, ports []int, concurrency int, base prober.Config, callback func(*result.Result), neighbor neighborScanOpts) {
	runConfigPortProbesWithProbe(ctx, ips, ports, concurrency, base, callback, neighbor, prober.Probe, prober.SpeedTest)
}

func runConfigPortProbesWithProbe(ctx context.Context, ips <-chan net.IP, ports []int, concurrency int, base prober.Config, callback func(*result.Result), neighbor neighborScanOpts, probe probeFunc, speedFns ...speedTestFunc) {
	if concurrency <= 0 {
		concurrency = 50
	}
	if neighbor.enabled {
		if neighbor.maxSeeds <= 0 {
			neighbor.maxSeeds = ipsrc.DefaultNeighborSeedLimit
		}
		if neighbor.perHit <= 0 {
			neighbor.perHit = ipsrc.DefaultNeighborPerHit
		}
		if neighbor.maxTotal <= 0 {
			neighbor.maxTotal = ipsrc.DefaultNeighborMaxTotal
		}
	}
	if neighbor.maxSpeedCandidates <= 0 {
		neighbor.maxSpeedCandidates = config.MaxSpeedTestCandidates
	}
	if neighbor.speedBytes <= 0 {
		neighbor.speedBytes = base.SpeedBytes
	}
	basicCfg := base
	basicCfg.SpeedBytes = 0

	jobs := make(chan configProbeJob)
	results := make(chan *result.Result, concurrency)
	seen := make(map[string]struct{})
	var queue []configProbeJob
	var pending int
	stats := phase1DiscoveryStats{PreviousLoaded: len(neighbor.previous)}
	neighborJobs := make(map[string]struct{})
	previousRetested := make(map[string]struct{})
	var allResults []*result.Result

	jobKey := func(ip net.IP, port int) string { return fmt.Sprintf("%s:%d", ip.String(), port) }
	submit := func(ip net.IP, port int, isNeighbor bool) bool {
		key := jobKey(ip, port)
		if _, ok := seen[key]; ok {
			return false
		}
		seen[key] = struct{}{}
		if isNeighbor {
			neighborJobs[key] = struct{}{}
		}
		queue = append(queue, configProbeJob{ip: ip, port: port, neighbor: isNeighbor})
		pending++
		return true
	}
	enqueueIP := func(ip net.IP) {
		for _, port := range ports {
			submit(ip, port, false)
		}
	}

	enqueueBestNeighbors := func() {
		if !neighbor.enabled || len(neighbor.nets) == 0 {
			return
		}
		for _, seed := range result.TopN(allResults, 0) {
			if stats.SeedsExpanded >= neighbor.maxSeeds || stats.NeighborQueued >= neighbor.maxTotal {
				break
			}
			ip := seed.IP.String()
			if _, wasPrevious := neighbor.previous[ip]; wasPrevious {
				if _, allowed := neighbor.previousExpandable[ip]; !allowed {
					continue
				}
			}
			addedForSeed := 0
			for _, nip := range ipsrc.NeighborsIn24(seed.IP, neighbor.nets, 254) {
				if addedForSeed >= neighbor.perHit || stats.NeighborQueued >= neighbor.maxTotal {
					break
				}
				addedIP := false
				for _, port := range ports {
					if stats.NeighborQueued >= neighbor.maxTotal {
						break
					}
					if submit(nip, port, true) {
						stats.NeighborQueued++
						addedIP = true
					}
				}
				if addedIP {
					addedForSeed++
				}
			}
			if addedForSeed > 0 {
				stats.SeedsExpanded++
			}
		}
		if neighbor.onStats != nil {
			neighbor.onStats(stats)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				r := probe(ctx, job.ip, basicCfg.WithPort(job.port))
				select {
				case results <- r:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	input := ips
	expansionStarted := !neighbor.enabled
	for {
		if input == nil && pending == 0 && len(queue) == 0 {
			if !expansionStarted {
				expansionStarted = true
				enqueueBestNeighbors()
				if len(queue) > 0 {
					continue
				}
			}
			break
		}
		var send chan<- configProbeJob
		var next configProbeJob
		if len(queue) > 0 {
			send, next = jobs, queue[0]
		}
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case ip, ok := <-input:
			if !ok {
				input = nil
				continue
			}
			enqueueIP(ip)
		case send <- next:
			queue[0] = configProbeJob{}
			queue = queue[1:]
		case r := <-results:
			pending--
			if r == nil {
				continue
			}
			key := jobKey(r.IP, r.Port)
			if _, ok := neighborJobs[key]; ok {
				stats.NeighborTested++
				delete(neighborJobs, key)
			}
			if _, ok := neighbor.previous[r.IP.String()]; ok {
				if _, counted := previousRetested[r.IP.String()]; !counted {
					previousRetested[r.IP.String()] = struct{}{}
					stats.PreviousRetested++
					if r.IsHealthyForPhase1(result.DefaultMaxPhase1AvgLatency) {
						stats.PreviousHealthy++
					}
				}
			}
			allResults = append(allResults, r)
			callback(r)
			if neighbor.onStats != nil {
				neighbor.onStats(stats)
			}
		}
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil || neighbor.speedBytes <= 0 {
		return
	}
	speedFn := prober.SpeedTest
	if len(speedFns) > 0 && speedFns[0] != nil {
		speedFn = speedFns[0]
	}
	runCappedSpeedTests(ctx, allResults, concurrency, basicCfg, neighbor.speedBytes, neighbor.maxSpeedCandidates, speedFn, callback, &stats, neighbor.onStats)
}

func runCappedSpeedTests(ctx context.Context, results []*result.Result, concurrency int, cfg prober.Config, bytes int64, limit int, speed speedTestFunc, callback func(*result.Result), stats *phase1DiscoveryStats, onStats func(phase1DiscoveryStats)) {
	if concurrency <= 0 {
		concurrency = 1
	}
	candidates := result.TopN(results, limit)
	stats.SpeedTestCandidates = len(candidates)
	if onStats != nil {
		onStats(*stats)
	}
	if len(candidates) == 0 || ctx.Err() != nil {
		return
	}
	workers := concurrency
	if workers > len(candidates) {
		workers = len(candidates)
	}
	jobs := make(chan *result.Result)
	done := make(chan *result.Result, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for original := range jobs {
				if ctx.Err() != nil {
					return
				}
				updated := *original
				speed(ctx, &updated, cfg.WithPort(updated.Port), bytes)
				select {
				case done <- &updated:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() { wg.Wait(); close(done) }()
	go func() {
		defer close(jobs)
		for _, candidate := range candidates {
			select {
			case jobs <- candidate:
			case <-ctx.Done():
				return
			}
		}
	}()
	for updated := range done {
		stats.SpeedTested++
		callback(updated)
		if onStats != nil {
			onStats(*stats)
		}
	}
}

func prioritizedIPStream(ctx context.Context, first []net.IP, rest <-chan net.IP) <-chan net.IP {
	out := make(chan net.IP)
	go func() {
		defer close(out)
		seen := make(map[string]struct{})
		send := func(ip net.IP) bool {
			if ip == nil {
				return true
			}
			key := ip.String()
			if _, ok := seen[key]; ok {
				return true
			}
			seen[key] = struct{}{}
			select {
			case out <- ip:
				return true
			case <-ctx.Done():
				return false
			}
		}
		for _, ip := range first {
			if !send(ip) {
				return
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case ip, ok := <-rest:
				if !ok {
					return
				}
				if !send(ip) {
					return
				}
			}
		}
	}()
	return out
}

func ipSet(ips []net.IP) map[string]struct{} {
	set := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if ip != nil {
			set[ip.String()] = struct{}{}
		}
	}
	return set
}

func defaultPhase1ProbeConfig(timeout time.Duration) prober.Config {
	return prober.Config{
		Port:       443,
		Mode:       prober.ModeHTTP,
		Tries:      3,
		Timeout:    timeout,
		SNI:        "speed.cloudflare.com",
		SpeedBytes: config.SpeedTestBytes,
	}
}

func configProbeFromURL(rawURL string, timeout time.Duration) (prober.Config, error) {
	cfg, err := xraytest.ParseProxyURL(rawURL)
	if err != nil {
		return prober.Config{}, err
	}

	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Host
	}

	probeCfg := prober.Config{
		Port:               cfg.Port,
		Mode:               prober.ModeHTTP,
		Tries:              3,
		Timeout:            timeout,
		SNI:                sni,
		InsecureSkipVerify: true,
	}
	if cfg.Network == "ws" {
		probeCfg.WebSocketHost = cfg.Host
		probeCfg.WebSocketPath = cfg.Path
		probeCfg.RequireWebSocket = true
	}
	return probeCfg, nil
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

func ipsFileSearchPaths() []string {
	seen := make(map[string]struct{})
	add := func(paths *[]string, path string) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		*paths = append(*paths, path)
	}

	var paths []string
	if wd, err := os.Getwd(); err == nil {
		add(&paths, filepath.Join(wd, "ips.txt"))
	}
	if exe, err := os.Executable(); err == nil {
		add(&paths, filepath.Join(filepath.Dir(exe), "ips.txt"))
	}
	return paths
}

func loadDefaultIPsFile() ([]net.IP, error) {
	for _, path := range ipsFileSearchPaths() {
		ips, err := loadIPs(path)
		if err == nil {
			return ips, nil
		}
	}
	return nil, fmt.Errorf("ips.txt not found — place it next to the binary or run folder")
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
	return config.SpeedTestBytes
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
