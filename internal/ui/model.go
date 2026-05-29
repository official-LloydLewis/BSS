package ui

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/official-LloydLewis/SenPaiScanner/internal/banner"
	"github.com/official-LloydLewis/SenPaiScanner/internal/config"
	"github.com/official-LloydLewis/SenPaiScanner/internal/configgen"
	"github.com/official-LloydLewis/SenPaiScanner/internal/engine"
	"github.com/official-LloydLewis/SenPaiScanner/internal/ipsrc"
	"github.com/official-LloydLewis/SenPaiScanner/internal/prober"
	"github.com/official-LloydLewis/SenPaiScanner/internal/result"
	"github.com/official-LloydLewis/SenPaiScanner/internal/xraytest"
)

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

// ResultMsg carries a completed probe result from the engine.
type ResultMsg struct {
	ScanID int64
	Result *result.Result
}

// StatsMsg carries live engine counters.
type StatsMsg struct {
	ScanID                            int64
	Tested, Healthy, Failed, InFlight int64
}

// DoneMsg signals the scan has finished.
type DoneMsg struct{ ScanID int64 }

// ErrorMsg carries a user-visible background task error.
type ErrorMsg struct {
	ScanID int64
	Text   string
}

// ColosDoneMsg signals the colo discovery finished.
type ColosDoneMsg struct{ ScanID int64 }

// tickMsg drives banner animation and stat refresh.
type tickMsg time.Time

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

var (
	styleBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#F6821F"))

	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F6821F"))

	styleSelected = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFE066")).
			Background(lipgloss.Color("#1A1A2E"))

	styleNormal = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CCCCCC"))

	styleDim = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#555555"))

	styleGood = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#27AE60")).Bold(true)

	styleExcellent = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00E5FF")).Bold(true)

	styleVersion = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#C46A1B")).Faint(true)

	styleWarn = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F39C12"))

	styleBad = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E74C3C"))

	styleAccent = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F6821F")).Bold(true)

	styleHint = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#444466")).Italic(true)

	styleHeader = lipgloss.NewStyle().
			Bold(true).Foreground(lipgloss.Color("#888888"))

	styleSep = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#333333"))
)

// ---------------------------------------------------------------------------
// ScanConfig holds form state.
// ---------------------------------------------------------------------------

type ScanConfig struct {
	Count            string
	Concurrency      string
	Timeout          string
	Tries            string
	Port             string
	Mode             string // tcp|tls|http
	CIDR             string
	OutputFile       string
	ColoFilter       string
	SNI              string
	StopAfterHealthy int
	Emergency        bool
	BaseConfig       string
	UseV4            bool
	UseV6            bool
}

func defaultScanConfig() ScanConfig {
	return ScanConfig{
		Count:       strconv.Itoa(config.ScanDefaults.Count),
		Concurrency: strconv.Itoa(config.ScanDefaults.Concurrency),
		Timeout:     config.ScanDefaults.Timeout.String(),
		Tries:       strconv.Itoa(config.ScanDefaults.Tries),
		Port:        strconv.Itoa(config.ScanDefaults.Port),
		Mode:        config.ScanDefaults.Mode,
		UseV4:       config.ScanDefaults.UseV4,
		UseV6:       config.ScanDefaults.UseV6,
	}
}

// ---------------------------------------------------------------------------
// Quick Scan setup rows
// ---------------------------------------------------------------------------

type quickPreset struct {
	label string
	value string // empty = custom
}

var quickCountPresets = []quickPreset{
	{"5,000", "5000"},
	{"20,000", "20000"},
	{"100,000", "100000"},
	{"Custom", ""},
}

var quickWorkersPresets = []quickPreset{
	{"50  — default (restricted net)", "50"},
	{"100 — balanced", "100"},
	{"200 — fast (good connections)", "200"},
	{"Custom", ""},
}

var quickTimeoutPresets = []quickPreset{
	{"2s  — aggressive (fast net)", "2s"},
	{"3s  — balanced", "3s"},
	{"5s  — default (restricted net)", "5s"},
	{"Custom", ""},
}

// quickSetupRow identifies which row is focused on the Quick Scan setup page.
type quickSetupRow int

const (
	qRowCount   quickSetupRow = 0
	qRowWorkers quickSetupRow = 1
	qRowTimeout quickSetupRow = 2
)

// ---------------------------------------------------------------------------
// AppModel — root Bubble Tea model
// ---------------------------------------------------------------------------

type AppModel struct {
	page   Page
	width  int
	height int

	// animation
	bannerFrame int
	spinner     spinner.Model

	// home menu
	menuIdx int

	// quick scan setup (3-row picker)
	quickRow         quickSetupRow
	quickCountIdx    int
	quickWorkersIdx  int
	quickTimeoutIdx  int
	quickCustomInput textinput.Model
	quickCustomRow   quickSetupRow // which row triggered custom input
	quickCustomMode  bool

	// scan config form
	scanCfg    ScanConfig
	formInputs []textinput.Model
	formFocus  int
	modeIdx    int

	// live scan state
	activeScanID int64
	scanResults  []*result.Result
	sortBy       result.SortBy
	sortIdx      int
	scanStats    StatsMsg
	scanDone     bool
	scanStarted  time.Time
	scanTotal    int

	// colos
	colosResults []*result.Result
	colosDone    bool

	// scan with config
	configInput    textinput.Model
	configResults  []*xraytest.ValidationResult
	configScanning bool
	configDone     bool
	configTotal    int
	// config setup options
	configURL      string
	configCountIdx int // 0=1000, 1=5000, 2=20000
	configTopNIdx  int // 0=10, 1=20, 2=50
	configSetupRow int // which row is focused (0=count, 1=topN)
	// phase 1 state
	configPhase1Results []*result.Result
	configPhase1Done    bool
	configPhase1Stats   StatsMsg

	// emergency scan
	emergencyIgnoreHistory bool

	// shared
	statusMsg string
	version   string
}

type menuEntry struct {
	label string
	desc  string
}

var menuEntries = []menuEntry{
	{"Quick Scan", "scan random Cloudflare IPs"},
	{"Custom Scan", "configure count, mode, CIDR, output…"},
	{"Emergency Scan", "find 10 usable IPs and export ready files"},
	{"Scan with Config", "test IPs with your VLESS/xray config"},
	{"Test IPs", "deep-test a list of IPs from file"},
	{"Discover Colos", "find reachable Cloudflare PoPs"},
	{"About", ""},
	{"Quit", ""},
}

const menuLabelWidth = 16

const (
	menuQuickScan      = 0
	menuCustomScan     = 1
	menuEmergency      = 2
	menuScanWithConfig = 3
	menuTestIPs        = 4
	menuColos          = 5
	menuAbout          = 6
	menuQuit           = 7
)

var modes = []string{"tls", "tcp", "http"}

const (
	excellentLatencyThreshold = 500 * time.Millisecond
	excellentJitterThreshold  = 80 * time.Millisecond
	excellentSpeedThreshold   = 50 * 1024 // bytes/sec
)

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func NewApp(version string) AppModel {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#F6821F"))

	customInput := textinput.New()
	customInput.Placeholder = "e.g. 50000"
	customInput.CharLimit = 10
	customInput.Width = 14

	m := AppModel{
		page:             PageHome,
		spinner:          sp,
		scanCfg:          defaultScanConfig(),
		version:          version,
		width:            120,
		height:           40,
		scanStarted:      time.Now(),
		quickCustomInput: customInput,
	}

	// Config input for "Scan with Config"
	cfgInput := textinput.New()
	cfgInput.Placeholder = "vless://, trojan://, or vmess://..."
	cfgInput.CharLimit = 8192
	cfgInput.Width = 0 // 0 = no fixed width, grows with content
	m.configInput = cfgInput
	m.modeIdx = modeIndex(m.scanCfg.Mode)
	m.buildFormInputs()
	return m
}

func modeIndex(mode string) int {
	for i, candidate := range modes {
		if candidate == mode {
			return i
		}
	}
	return 0
}

func (m *AppModel) buildFormInputs() {
	fields := []struct{ placeholder, value string }{
		{"count (default 500)", m.scanCfg.Count},
		{"concurrency (default 50)", m.scanCfg.Concurrency},
		{"timeout (default 5s)", m.scanCfg.Timeout},
		{"tries per IP (default 4)", m.scanCfg.Tries},
		{"port (default 443)", m.scanCfg.Port},
		{"CIDR filter (e.g. 104.16.0.0/13, empty = all CF)", m.scanCfg.CIDR},
		{"output file (.csv/.json/.txt, empty = none)", m.scanCfg.OutputFile},
		{"colo filter (e.g. FRA,AMS, empty = all)", m.scanCfg.ColoFilter},
		{"SNI override (empty = auto-rotate)", m.scanCfg.SNI},
	}

	inputs := make([]textinput.Model, len(fields))
	for i, f := range fields {
		ti := textinput.New()
		ti.Placeholder = f.placeholder
		ti.SetValue(f.value)
		ti.CharLimit = 80
		ti.Width = 50
		if i == 0 {
			ti.Focus()
		}
		inputs[i] = ti
	}
	m.formInputs = inputs
	m.formFocus = 0
}

// ---------------------------------------------------------------------------
// tea.Model interface
// ---------------------------------------------------------------------------

func (m AppModel) Init() tea.Cmd {
	return tea.Batch(
		tick(),
		m.spinner.Tick,
		textinput.Blink,
	)
}

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		m.bannerFrame++
		return m, tick()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case ResultMsg:
		if msg.ScanID != m.activeScanID || msg.Result == nil {
			return m, nil
		}
		if m.page == PageLiveColos {
			m.colosResults = append(m.colosResults, msg.Result)
		} else {
			m.scanResults = append(m.scanResults, msg.Result)
			result.Sort(m.scanResults, m.sortBy)
		}
		return m, nil

	case StatsMsg:
		if msg.ScanID == m.activeScanID {
			m.scanStats = msg
		}
		return m, nil

	case ErrorMsg:
		if msg.ScanID == m.activeScanID {
			m.statusMsg = msg.Text
		}
		return m, nil

	case DoneMsg:
		if msg.ScanID == m.activeScanID {
			m.scanDone = true
		}
		return m, nil

	case ColosDoneMsg:
		if msg.ScanID == m.activeScanID {
			m.colosDone = true
		}
		return m, nil

	case ConfigProgressMsg:
		m.configResults = append(m.configResults, msg.Result)
		m.configTotal = msg.Total
		return m, nil

	case ConfigDoneMsg:
		m.configScanning = false
		m.configDone = true
		return m, nil

	case ConfigPhase1ResultMsg:
		m.configPhase1Results = append(m.configPhase1Results, msg.Result)
		return m, nil

	case ConfigPhase1DoneMsg:
		m.configPhase1Done = true
		// Start Phase 2 with top N IPs
		m.page = PageConfigPhase2
		m.configScanning = true
		m.configDone = false
		m.configResults = nil
		topN := configTopNValues[m.configTopNIdx]
		var topIPs []*result.Result
		if topN == 0 {
			// "All" — use all healthy IPs
			topIPs = result.TopN(m.configPhase1Results, 0)
		} else {
			topIPs = result.TopN(m.configPhase1Results, topN)
		}
		m.configTotal = len(topIPs)
		return m, m.startConfigPhase2(topIPs)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m.updateFormInputs(msg)
}

// ---------------------------------------------------------------------------
// Key handling (dispatched by page)
// ---------------------------------------------------------------------------

func (m AppModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.page {
	case PageHome:
		return m.handleHomeKey(msg)
	case PageQuickScanCount:
		return m.handleQuickCountKey(msg)
	case PageScanConfig:
		return m.handleConfigKey(msg)
	case PageLiveScan:
		return m.handleLiveScanKey(msg)
	case PageResults:
		return m.handleResultsKey(msg)
	case PageColos, PageLiveColos:
		return m.handleColosKey(msg)
	case PageAbout:
		if msg.String() == "q" || msg.String() == "esc" || msg.String() == "enter" {
			m.page = PageHome
		}
		return m, nil
	case PageEmergencyScan:
		return m.handleEmergencyKey(msg)
	case PageScanWithConfig:
		return m.handleScanWithConfigKey(msg)
	case PageConfigPhase1:
		return m.handleConfigPhase1Key(msg)
	case PageConfigPhase2:
		return m.handleScanWithConfigKey(msg)
	}
	return m, nil
}

func (m AppModel) handleHomeKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "up", "k":
		if m.menuIdx > 0 {
			m.menuIdx--
		}
	case "down", "j":
		if m.menuIdx < len(menuEntries)-1 {
			m.menuIdx++
		}
	case "enter", " ":
		return m.selectMenuItem()
	}
	return m, nil
}

func (m AppModel) selectMenuItem() (tea.Model, tea.Cmd) {
	switch m.menuIdx {
	case menuQuickScan:
		m.quickRow = qRowCount
		m.quickCountIdx = 0
		m.quickWorkersIdx = 0 // default: 50 (safe for restricted networks)
		m.quickTimeoutIdx = 2 // default: 5s (recommended for restricted networks)
		m.quickCustomMode = false
		m.quickCustomInput.SetValue("")
		m.quickCustomInput.Blur()
		m.scanCfg = defaultScanConfig() // clear any stale custom values
		m.statusMsg = ""
		m.page = PageQuickScanCount
		return m, textinput.Blink
	case menuCustomScan:
		m.statusMsg = ""
		m.buildFormInputs()
		m.page = PageScanConfig
	case menuEmergency:
		m.page = PageEmergencyScan
		m.configInput.SetValue("")
		m.configInput.Placeholder = "optional vless:// trojan:// or vmess:// config (Enter empty for IP-only)"
		m.configInput.Focus()
		m.configResults = nil
		m.statusMsg = ""
		return m, textinput.Blink
	case menuScanWithConfig:
		m.page = PageScanWithConfig
		m.configInput.Placeholder = "vless://..."
		m.configInput.SetValue("")
		m.configInput.Focus()
		m.emergencyIgnoreHistory = false
		m.configResults = nil
		m.configScanning = false
		m.configDone = false
		m.configSetupRow = 0
		m.configCountIdx = 1 // default: 5000
		m.configTopNIdx = 0  // default: 10
		return m, textinput.Blink
	case menuTestIPs:
		m.statusMsg = "Place IPs in 'ips.txt' (one per line) before selecting Test IPs"
		m.activeScanID = nextScanID()
		m.scanResults = nil
		m.scanDone = false
		m.scanStats = StatsMsg{ScanID: m.activeScanID}
		m.scanStarted = time.Now()
		m.scanTotal = 0
		m.page = PageLiveScan
		return m, StartTestCmd("ips.txt", m.activeScanID)
	case menuColos:
		m.activeScanID = nextScanID()
		m.colosResults = nil
		m.colosDone = false
		m.scanStats = StatsMsg{ScanID: m.activeScanID}
		m.page = PageLiveColos
		return m, StartColosCmd(m.activeScanID)
	case menuAbout:
		m.page = PageAbout
	case menuQuit:
		return m, tea.Quit
	}
	return m, nil
}

func (m AppModel) handleQuickCountKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// If the user is typing a custom value, route keys there first.
	if m.quickCustomMode {
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			m.quickCustomMode = false
			m.quickCustomInput.Blur()
			return m, nil
		case "enter":
			val := strings.TrimSpace(m.quickCustomInput.Value())
			return m.applyCustomValue(val)
		}
		return m.updateFormInputs(msg)
	}

	presets := m.presetsForRow(m.quickRow)
	idx := m.idxForRow(m.quickRow)

	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc", "q":
		m.page = PageHome
	case "up", "k":
		if m.quickRow > 0 {
			m.quickRow--
		}
	case "down", "j":
		if int(m.quickRow) < 2 {
			m.quickRow++
		}
	case "left", "h":
		if idx > 0 {
			m.setIdxForRow(m.quickRow, idx-1)
		}
	case "right", "l":
		if idx < len(presets)-1 {
			m.setIdxForRow(m.quickRow, idx+1)
		}
	case "enter", " ":
		p := presets[idx]
		if p.value == "" {
			// Activate custom input for this row
			m.quickCustomRow = m.quickRow
			m.quickCustomMode = true
			m.quickCustomInput.SetValue("")
			m.quickCustomInput.Placeholder = m.customPlaceholderForRow(m.quickRow)
			m.quickCustomInput.CharLimit = m.customCharLimitForRow(m.quickRow)
			m.quickCustomInput.Focus()
			return m, textinput.Blink
		}
		// If all non-custom rows have a selection, launch
		return m.launchQuickScan()
	}
	return m, nil
}

func (m AppModel) presetsForRow(row quickSetupRow) []quickPreset {
	switch row {
	case qRowWorkers:
		return quickWorkersPresets
	case qRowTimeout:
		return quickTimeoutPresets
	default:
		return quickCountPresets
	}
}

func (m AppModel) idxForRow(row quickSetupRow) int {
	switch row {
	case qRowWorkers:
		return m.quickWorkersIdx
	case qRowTimeout:
		return m.quickTimeoutIdx
	default:
		return m.quickCountIdx
	}
}

func (m *AppModel) setIdxForRow(row quickSetupRow, idx int) {
	switch row {
	case qRowWorkers:
		m.quickWorkersIdx = idx
	case qRowTimeout:
		m.quickTimeoutIdx = idx
	default:
		m.quickCountIdx = idx
	}
}

func (m AppModel) customPlaceholderForRow(row quickSetupRow) string {
	switch row {
	case qRowWorkers:
		return "e.g. 150"
	case qRowTimeout:
		return "e.g. 4s"
	default:
		return "e.g. 50000"
	}
}

func (m AppModel) customCharLimitForRow(row quickSetupRow) int {
	switch row {
	case qRowTimeout:
		return 8
	default:
		return 10
	}
}

// applyCustomValue stores the typed value back into the right row index and
// advances to the next row or launches if on the last row.
func (m AppModel) applyCustomValue(val string) (tea.Model, tea.Cmd) {
	if val == "" {
		// restore placeholder default
		switch m.quickCustomRow {
		case qRowCount:
			val = "5000"
		case qRowWorkers:
			val = "100"
		case qRowTimeout:
			val = "3s"
		}
	}
	// Store in a dedicated custom-value slot by overwriting the last preset's value.
	// We use a simpler approach: just store in scanCfg directly and flag "custom used".
	switch m.quickCustomRow {
	case qRowCount:
		m.scanCfg.Count = val
		m.quickCountIdx = len(quickCountPresets) - 1 // keep "Custom" highlighted
	case qRowWorkers:
		m.scanCfg.Concurrency = val
		m.quickWorkersIdx = len(quickWorkersPresets) - 1
	case qRowTimeout:
		m.scanCfg.Timeout = val
		m.quickTimeoutIdx = len(quickTimeoutPresets) - 1
	}
	m.quickCustomMode = false
	m.quickCustomInput.Blur()
	if m.quickCustomRow < qRowTimeout {
		m.quickRow = m.quickCustomRow + 1
		return m, nil
	}
	m.quickRow = qRowTimeout
	return m.launchQuickScan()
}

func (m AppModel) customValueForRow(row quickSetupRow) string {
	switch row {
	case qRowWorkers:
		return m.scanCfg.Concurrency
	case qRowTimeout:
		return m.scanCfg.Timeout
	default:
		return m.scanCfg.Count
	}
}

func (m AppModel) customLabelForRow(row quickSetupRow) string {
	value := strings.TrimSpace(m.customValueForRow(row))
	if value == "" {
		return "Custom"
	}
	return "Custom: " + value
}

func (m AppModel) customHelpForRow(row quickSetupRow) string {
	switch row {
	case qRowWorkers:
		return "type an integer worker count, e.g. 75 or 150"
	case qRowTimeout:
		return "type a Go duration, e.g. 4s, 1500ms, 8s"
	default:
		return "type an integer IP count, e.g. 50000"
	}
}

func (m AppModel) launchQuickScan() (tea.Model, tea.Cmd) {
	cfg := defaultScanConfig()

	// Count
	cp := quickCountPresets[m.quickCountIdx]
	if cp.value != "" {
		cfg.Count = cp.value
	} else if m.scanCfg.Count != "" {
		cfg.Count = m.scanCfg.Count
	}

	// Workers
	wp := quickWorkersPresets[m.quickWorkersIdx]
	if wp.value != "" {
		cfg.Concurrency = wp.value
	} else if m.scanCfg.Concurrency != "" {
		cfg.Concurrency = m.scanCfg.Concurrency
	}

	// Timeout
	tp := quickTimeoutPresets[m.quickTimeoutIdx]
	if tp.value != "" {
		cfg.Timeout = tp.value
	} else if m.scanCfg.Timeout != "" {
		cfg.Timeout = m.scanCfg.Timeout
	}

	m.scanCfg = cfg
	m.activeScanID = nextScanID()
	m.statusMsg = ""
	m.scanResults = nil
	m.scanDone = false
	m.scanStats = StatsMsg{ScanID: m.activeScanID}
	m.scanStarted = time.Now()
	n, _ := fmt.Sscanf(cfg.Count, "%d", &m.scanTotal)
	if n == 0 {
		m.scanTotal = 0
	}
	m.page = PageLiveScan
	return m, StartScanCmd(cfg, m.activeScanID)
}

func (m AppModel) handleConfigKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.page = PageHome
		return m, nil
	case "tab", "down":
		m.formFocus = (m.formFocus + 1) % len(m.formInputs)
		for i := range m.formInputs {
			if i == m.formFocus {
				m.formInputs[i].Focus()
			} else {
				m.formInputs[i].Blur()
			}
		}
	case "shift+tab", "up":
		m.formFocus = (m.formFocus - 1 + len(m.formInputs)) % len(m.formInputs)
		for i := range m.formInputs {
			if i == m.formFocus {
				m.formInputs[i].Focus()
			} else {
				m.formInputs[i].Blur()
			}
		}
	case "ctrl+left", "ctrl+right":
		if msg.String() == "ctrl+right" {
			m.modeIdx = (m.modeIdx + 1) % len(modes)
		} else {
			m.modeIdx = (m.modeIdx - 1 + len(modes)) % len(modes)
		}
		m.scanCfg.Mode = modes[m.modeIdx]
	case "f2":
		m.scanCfg.UseV4 = !m.scanCfg.UseV4
	case "f3":
		m.scanCfg.UseV6 = !m.scanCfg.UseV6
	case "enter":
		m.saveScanConfig()
		m.activeScanID = nextScanID()
		m.statusMsg = ""
		m.scanResults = nil
		m.scanDone = false
		m.scanStats = StatsMsg{ScanID: m.activeScanID}
		m.scanStarted = time.Now()
		n, _ := fmt.Sscanf(m.scanCfg.Count, "%d", &m.scanTotal)
		if n == 0 {
			m.scanTotal = 0
		}
		m.page = PageLiveScan
		return m, StartScanCmd(m.scanCfg, m.activeScanID)
	}
	return m.updateFormInputs(msg)
}

func (m *AppModel) saveScanConfig() {
	if len(m.formInputs) >= 9 {
		m.scanCfg.Count = m.formInputs[0].Value()
		m.scanCfg.Concurrency = m.formInputs[1].Value()
		m.scanCfg.Timeout = m.formInputs[2].Value()
		m.scanCfg.Tries = m.formInputs[3].Value()
		m.scanCfg.Port = m.formInputs[4].Value()
		m.scanCfg.CIDR = m.formInputs[5].Value()
		m.scanCfg.OutputFile = m.formInputs[6].Value()
		m.scanCfg.ColoFilter = m.formInputs[7].Value()
		m.scanCfg.SNI = m.formInputs[8].Value()
		m.scanCfg.Mode = modes[m.modeIdx]
	}
}

func (m AppModel) handleLiveScanKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "q", "esc":
		if m.scanDone {
			m.page = PageResults
		} else {
			m.page = PageHome
			return m, CancelScanCmd()
		}
	case "s":
		m.sortIdx = (m.sortIdx + 1) % 5
		m.sortBy = result.SortBy(m.sortIdx)
		result.Sort(m.scanResults, m.sortBy)
	case "enter":
		if m.scanDone {
			m.page = PageResults
		}
	case "c":
		m.statusMsg = m.copyHealthyIPsToClipboard()
	}
	return m, nil
}

func (m AppModel) handleResultsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "q", "esc", "enter":
		m.page = PageHome
	case "s":
		m.sortIdx = (m.sortIdx + 1) % 5
		m.sortBy = result.SortBy(m.sortIdx)
		result.Sort(m.scanResults, m.sortBy)
	case "c":
		m.statusMsg = m.copyHealthyIPsToClipboard()
	}
	return m, nil
}

// copyHealthyIPsToClipboard writes one IP per line to the system clipboard
// and returns a short status message to display to the user.
func (m AppModel) copyHealthyIPsToClipboard() string {
	top := result.TopN(m.scanResults, 0) // all healthy IPs, sorted by avg
	if len(top) == 0 {
		return "no healthy IPs to copy"
	}
	var sb strings.Builder
	for _, r := range top {
		sb.WriteString(r.IP.String())
		sb.WriteRune('\n')
	}
	if err := clipboard.WriteAll(sb.String()); err != nil {
		return fmt.Sprintf("clipboard error: %v", err)
	}
	return fmt.Sprintf("✓ copied %d IPs to clipboard", len(top))
}

func (m AppModel) handleColosKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "q", "esc", "enter":
		if m.colosDone || m.page == PageColos {
			m.page = PageHome
		}
	}
	return m, nil
}

// updateFormInputs forwards keypresses to the focused text input(s).
func (m AppModel) updateFormInputs(msg tea.Msg) (AppModel, tea.Cmd) {
	var cmds []tea.Cmd

	if m.page == PageQuickScanCount && m.quickCustomMode {
		var cmd tea.Cmd
		m.quickCustomInput, cmd = m.quickCustomInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	if m.page == PageScanConfig && len(m.formInputs) > 0 {
		for i := range m.formInputs {
			var cmd tea.Cmd
			m.formInputs[i], cmd = m.formInputs[i].Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

func (m AppModel) View() string {
	switch m.page {
	case PageHome:
		return m.viewHome()
	case PageQuickScanCount:
		return m.viewQuickScanCount()
	case PageScanConfig:
		return m.viewScanConfig()
	case PageLiveScan:
		return m.viewLiveScan()
	case PageResults:
		return m.viewResults()
	case PageLiveColos:
		return m.viewLiveColos()
	case PageAbout:
		return m.viewAbout()
	case PageEmergencyScan:
		return m.viewEmergencyScan()
	case PageScanWithConfig:
		return m.viewScanWithConfig()
	case PageConfigPhase1:
		return m.viewConfigPhase1()
	case PageConfigPhase2:
		return m.viewScanWithConfig()
	}
	return ""
}

// ---------------------------------------------------------------------------
// Home page
// ---------------------------------------------------------------------------

func (m AppModel) viewHome() string {
	var sb strings.Builder

	// Animated banner (shrink if terminal too narrow)
	art := banner.Render(m.bannerFrame / 2)
	sb.WriteString(art)
	sb.WriteRune('\n')

	// Version — keep newlines outside styled output; lipgloss pads blank lines with spaces.
	sb.WriteString(styleVersion.Render("  " + m.versionLabel()))
	sb.WriteString("\n\n")

	// Menu
	for i, item := range menuEntries {
		cursor := "  "
		labelStyle := styleNormal
		if i == m.menuIdx {
			cursor = styleAccent.Render("▶ ")
			labelStyle = styleSelected
		}

		line := "  " + cursor + labelStyle.Render(fmt.Sprintf("%-*s", menuLabelWidth, item.label))
		if item.desc != "" {
			line += "  " + styleDim.Render(item.desc)
		}
		sb.WriteString(line)
		sb.WriteRune('\n')
	}

	sb.WriteRune('\n')
	sb.WriteString(styleHint.Render("  ↑/↓ navigate   enter select   q quit"))
	sb.WriteRune('\n')

	return sb.String()
}

// ---------------------------------------------------------------------------
// Quick Scan setup page (3-row picker: Count / Workers / Timeout)
// ---------------------------------------------------------------------------

func (m AppModel) viewQuickScanCount() string {
	var sb strings.Builder

	separator := fmt.Sprintf("  %v\n\n", strings.Repeat("─", 64))

	sb.WriteString(styleTitle.Render("\n  ⚡  Quick Scan Setup\n"))
	sb.WriteString(separator)

	type rowDef struct {
		label   string
		presets []quickPreset
		selIdx  int
		row     quickSetupRow
		hint    string
	}

	rows := []rowDef{
		{
			label:   "  Count   ",
			presets: quickCountPresets,
			selIdx:  m.quickCountIdx,
			row:     qRowCount,
			hint:    "number of Cloudflare IPs to probe",
		},
		{
			label:   "  Workers ",
			presets: quickWorkersPresets,
			selIdx:  m.quickWorkersIdx,
			row:     qRowWorkers,
			hint:    "parallel goroutines — higher is faster but harder on slow networks",
		},
		{
			label:   "  Timeout ",
			presets: quickTimeoutPresets,
			selIdx:  m.quickTimeoutIdx,
			row:     qRowTimeout,
			hint:    "per-probe deadline — raise this if you see lots of timeouts",
		},
	}

	for _, r := range rows {
		focused := m.quickRow == r.row
		labelStyle := styleHeader
		if focused {
			labelStyle = styleAccent
		}
		sb.WriteString(labelStyle.Render(r.label))

		// Render preset pills
		for i, p := range r.presets {
			label := strings.SplitN(p.label, " —", 2)[0] // short label only
			// trim trailing spaces
			label = strings.TrimRight(label, " ")
			if p.value == "" {
				label = m.customLabelForRow(r.row)
			}

			if i == r.selIdx {
				if p.value == "" && m.quickCustomMode && m.quickCustomRow == r.row {
					// Active custom input
					sb.WriteString(fmt.Sprintf("%s%s%s",
						styleAccent.Render("["),
						m.quickCustomInput.View(),
						styleAccent.Render("]"),
					))
				} else {
					sb.WriteString(styleSelected.Render(fmt.Sprintf(" %s ", label)))
				}
			} else {
				sb.WriteString(styleDim.Render(fmt.Sprintf(" %s ", label)))
			}
			if i < len(r.presets)-1 {
				sb.WriteString(styleSep.Render(" │ "))
			}
		}
		sb.WriteRune('\n')

		// Show hint only for the focused row
		if focused {
			sb.WriteString(styleHint.Render("    " + r.hint + "\n"))
		}
		sb.WriteRune('\n')
	}

	if m.quickCustomMode {
		sb.WriteString(styleHint.Render("  " + m.customHelpForRow(m.quickCustomRow) + "   enter confirm   esc cancel"))
	} else {
		sb.WriteString(styleHint.Render("  ↑/↓ row   ←/→ option   enter select/start   esc back"))
	}
	sb.WriteRune('\n')
	return sb.String()
}

// ---------------------------------------------------------------------------
// Scan Config page
// ---------------------------------------------------------------------------

func (m AppModel) viewScanConfig() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("\n  ⚙  Custom Scan Configuration\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n",
		styleSep.Render("  "+strings.Repeat("─", 56)),
	))

	labels := []string{
		"Count      ", "Workers    ", "Timeout    ", "Tries      ", "Port       ",
		"CIDR       ", "Output     ", "Colo Filter", "SNI        ",
	}

	for i, inp := range m.formInputs {
		prefix := "  "
		label := styleHeader.Render(labels[i] + "  ")
		if i == m.formFocus {
			prefix = styleAccent.Render("  ▶ ")
			label = styleAccent.Render(labels[i] + "  ")
		}
		sb.WriteString(fmt.Sprintf("%s%s%s\n", prefix, label, inp.View()))
	}

	// Mode toggle
	sb.WriteRune('\n')
	sb.WriteString(styleHeader.Render("  Mode        "))
	for i, mode := range modes {
		if i == m.modeIdx {
			sb.WriteString(styleSelected.Render(fmt.Sprintf(" %s ", strings.ToUpper(mode))))
		} else {
			sb.WriteString(styleDim.Render(fmt.Sprintf(" %s ", strings.ToUpper(mode))))
		}
		sb.WriteString("  ")
	}
	sb.WriteString(fmt.Sprintf("%s\n", styleDim.Render("  ←/→ to cycle")))

	// IPv4/v6 toggles
	v4s := styleGood.Render("ON")
	if !m.scanCfg.UseV4 {
		v4s = styleBad.Render("OFF")
	}
	v6s := styleGood.Render("ON")
	if !m.scanCfg.UseV6 {
		v6s = styleBad.Render("OFF")
	}
	sb.WriteString(fmt.Sprintf("%s%s%s\n", styleHeader.Render("  IPv4         "), v4s, styleDim.Render("  F2 toggle")))
	sb.WriteString(fmt.Sprintf("%s%s%s\n", styleHeader.Render("  IPv6         "), v6s, styleDim.Render("  F3 toggle")))

	sb.WriteRune('\n')
	sb.WriteString(styleHint.Render("  tab/↑↓ navigate   enter start scan   esc back"))
	sb.WriteRune('\n')

	return sb.String()
}

// ---------------------------------------------------------------------------
// Live Scan page
// ---------------------------------------------------------------------------

func (m AppModel) viewLiveScan() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("\n  ⚡  Live Scan\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", minInt(m.width-4, 70)))))

	// Stats row
	elapsed := time.Since(m.scanStarted).Round(time.Second)
	rateStr := "—"
	if elapsed.Seconds() > 0 && m.scanStats.Tested > 0 {
		rateStr = fmt.Sprintf("%.0f/s", float64(m.scanStats.Tested)/elapsed.Seconds())
	}

	icon := m.spinner.View()
	if m.scanDone {
		icon = styleGood.Render("✓")
	}

	progBar := ""
	if m.scanTotal > 0 {
		pct := float64(m.scanStats.Tested) / float64(m.scanTotal) * 100
		bw := 22
		filled := int(pct / 100 * float64(bw))
		progBar = "  [" + styleAccent.Render(strings.Repeat("█", filled)) +
			styleDim.Render(strings.Repeat("░", bw-filled)) + "]" +
			fmt.Sprintf(" %.0f%%", pct)
	}

	sb.WriteString(fmt.Sprintf("  %s  tested: %s  healthy: %s  failed: %s  flying: %s  rate: %s  %s%s\n\n",
		icon,
		styleAccent.Render(fmt.Sprintf("%d", m.scanStats.Tested)),
		styleGood.Render(fmt.Sprintf("%d", m.scanStats.Healthy)),
		styleBad.Render(fmt.Sprintf("%d", m.scanStats.Failed)),
		styleDim.Render(fmt.Sprintf("%d", m.scanStats.InFlight)),
		styleDim.Render(rateStr),
		styleDim.Render(elapsed.String()),
		progBar,
	))

	// Table header
	hdr := fmt.Sprintf("  %-18s  %-9s  %7s  %9s  %8s  %9s  %5s  %-6s",
		"IP", "QUALITY", "LOSS", "AVG(ms)", "JTR(ms)", "DL(KB/s)", "TLS", "COLO")
	sb.WriteString(fmt.Sprintf("%s\n%s\n", styleHeader.Render(hdr), styleSep.Render("  "+strings.Repeat("─", 84))))

	maxRows := m.height - 14
	if maxRows < 3 {
		maxRows = 3
	}
	rows := m.scanResults
	if len(rows) > maxRows {
		rows = rows[:maxRows]
	}

	for _, r := range rows {
		tlsIcon := "✗"
		if r.TLSOk {
			tlsIcon = "✓"
		}
		colo := r.Colo
		if colo == "" {
			colo = "—"
		}
		line := fmt.Sprintf("  %-18s  %-9s  %6.1f%%  %9.2f  %8.2f  %9.1f  %5s  %-6s",
			r.IP.String(), qualityLabel(r), r.Loss(),
			float64(r.Avg().Milliseconds()),
			float64(r.Jitter().Milliseconds()),
			r.Throughput/1024,
			tlsIcon, colo)
		sb.WriteString(qualityStyle(r).Render(line) + "\n")
	}

	sb.WriteRune('\n')
	sortNames := []string{"avg", "loss", "jitter", "colo", "speed"}
	hint := fmt.Sprintf("  s sort(→%s)   c copy IPs   q/esc back", sortNames[m.sortIdx%5])
	if m.scanDone {
		hint = fmt.Sprintf("  s sort(→%s)   c copy IPs   enter/q → results", sortNames[m.sortIdx%5])
	}
	if m.statusMsg != "" {
		sb.WriteString(styleGood.Render("  "+m.statusMsg) + "\n")
	}
	sb.WriteString(styleHint.Render(hint))
	return sb.String()
}

// ---------------------------------------------------------------------------
// Results page
// ---------------------------------------------------------------------------

func (m AppModel) viewResults() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("\n  ✅  Scan Results\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", 60))))

	top := result.TopN(m.scanResults, 20)
	if len(top) == 0 {
		sb.WriteString(styleWarn.Render("  No healthy IPs found. Try raising timeout, lowering workers, or using a different SNI.\n"))
	} else {
		hdr := fmt.Sprintf("  %-5s  %-18s  %-9s  %7s  %9s  %8s  %9s  %5s  %-6s",
			"RANK", "IP", "QUALITY", "LOSS", "AVG(ms)", "JTR(ms)", "DL(KB/s)", "TLS", "COLO")
		sb.WriteString(fmt.Sprintf("%s\n%s\n", styleHeader.Render(hdr), styleSep.Render("  "+strings.Repeat("─", 92))))

		for i, r := range top {
			tlsIcon := "✗"
			if r.TLSOk {
				tlsIcon = "✓"
			}
			colo := r.Colo
			if colo == "" {
				colo = "—"
			}
			line := fmt.Sprintf("  %2d.   %-18s  %-9s  %6.1f%%  %9.2f  %8.2f  %9.1f  %5s  %-6s",
				i+1, r.IP.String(), qualityLabel(r), r.Loss(),
				float64(r.Avg().Milliseconds()),
				float64(r.Jitter().Milliseconds()),
				r.Throughput/1024,
				tlsIcon, colo)
			sb.WriteString(qualityStyle(r).Render(line) + "\n")
		}
	}

	total := len(m.scanResults)
	healthy := 0
	for _, r := range m.scanResults {
		if r.IsHealthy() {
			healthy++
		}
	}
	sb.WriteString("\n")
	sb.WriteString(styleDim.Render(fmt.Sprintf("  Total probed: %d   healthy: %d   unhealthy: %d\n", total, healthy, total-healthy)))
	if m.scanCfg.OutputFile != "" {
		sb.WriteString(styleDim.Render(fmt.Sprintf("  Saved → %s\n", m.scanCfg.OutputFile)))
	}
	if m.scanCfg.Emergency {
		sb.WriteString(styleDim.Render("  Emergency files → good_ips.txt, ip_port.txt"))
		if strings.TrimSpace(m.scanCfg.BaseConfig) != "" {
			sb.WriteString(styleDim.Render(", generated_configs.txt, working_configs.txt, stable_configs.txt"))
		}
		sb.WriteString("\n")
		if len(m.configResults) > 0 {
			sb.WriteString("\n")
			sb.WriteString(styleHeader.Render(fmt.Sprintf("  %-18s  %-6s  %-9s  %8s  %10s\n", "IP", "Xray", "Stability", "Latency", "Speed")))
			sb.WriteString(styleSep.Render("  " + strings.Repeat("─", 62) + "\n"))
			for _, vr := range m.configResults {
				xray := "fail"
				stability := "failed"
				if vr.Success {
					xray = "ok"
					stability = "tested"
				}
				speed := "—"
				if vr.Throughput > 0 {
					speed = fmt.Sprintf("%.1fKB/s", vr.Throughput/1024)
				}
				line := fmt.Sprintf("  %-18s  %-6s  %-9s  %8s  %10s\n", vr.IP, xray, stability, vr.Latency.Round(time.Millisecond), speed)
				if vr.Success {
					sb.WriteString(styleGood.Render(line))
				} else {
					sb.WriteString(styleBad.Render(line))
				}
			}
		}
	}
	sb.WriteString("\n")
	if m.statusMsg != "" {
		sb.WriteString(styleGood.Render("  "+m.statusMsg) + "\n")
	}
	sb.WriteString(styleHint.Render("  s sort   c copy IPs   enter/q → home menu"))
	return sb.String()
}

// ---------------------------------------------------------------------------
// Live Colos page
// ---------------------------------------------------------------------------

func (m AppModel) viewLiveColos() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("\n  🌍  Discovering Cloudflare PoPs\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", 56))))

	if !m.colosDone {
		sb.WriteString(fmt.Sprintf("  %s probing IPs via /cdn-cgi/trace…\n\n", m.spinner.View()))
	} else {
		sb.WriteString(styleGood.Render("  ✓ Discovery complete\n\n"))
	}

	PrintColoTableBufWithWidth(&sb, m.colosResults, m.width)

	sb.WriteRune('\n')
	sb.WriteString(styleHint.Render("  q/esc → home menu"))
	return sb.String()
}

// ---------------------------------------------------------------------------
// About page
// ---------------------------------------------------------------------------

func (m AppModel) viewAbout() string {
	var sb strings.Builder
	sb.WriteString(banner.Render(m.bannerFrame / 2))
	sb.WriteRune('\n')
	sb.WriteString(styleTitle.Render("  SenPai Scanner "))
	sb.WriteString(styleVersion.Render(m.versionLabel()))
	sb.WriteString("\n\n")
	sb.WriteString(styleNormal.Render("  A Cloudflare IP scanner built for high-latency, restricted networks."))
	sb.WriteRune('\n')

	sb.WriteString(styleNormal.Render("  Probes Cloudflare's edge nodes via TCP/TLS/HTTP, measures loss,"))
	sb.WriteRune('\n')

	sb.WriteString(styleNormal.Render("  jitter, and identifies the colo (PoP) behind each IP."))
	sb.WriteString("\n\n")

	sb.WriteString(styleDim.Render("  github.com/official-LloydLewis/SenPaiScanner"))
	sb.WriteString("\n\n")
	sb.WriteString(styleHint.Render("  enter/q → back"))
	return sb.String()
}

// ---------------------------------------------------------------------------
// Exported helpers for non-TUI callers
// ---------------------------------------------------------------------------

// PrintTable prints a sorted results table to stdout.
func PrintTable(results []*result.Result, top int) {
	sorted := make([]*result.Result, len(results))
	copy(sorted, results)
	result.Sort(sorted, result.SortByAvg)
	if top > 0 && top < len(sorted) {
		sorted = sorted[:top]
	}

	hdr := fmt.Sprintf("  %-18s  %-9s  %7s  %9s  %8s  %9s  %4s  %-5s",
		"IP", "QUALITY", "LOSS", "AVG(ms)", "JTR(ms)", "DL(KB/s)", "TLS", "COLO")
	fmt.Println(hdr)
	fmt.Println("  " + strings.Repeat("─", 84))
	for _, r := range sorted {
		tls := "✗"
		if r.TLSOk {
			tls = "✓"
		}
		colo := r.Colo
		if colo == "" {
			colo = "—"
		}
		fmt.Printf("  %-18s  %-9s  %6.1f%%  %9.2f  %8.2f  %9.1f  %4s  %-5s\n",
			r.IP.String(), qualityLabel(r), r.Loss(),
			float64(r.Avg().Milliseconds()),
			float64(r.Jitter().Milliseconds()),
			r.Throughput/1024,
			tls, colo)
	}
	fmt.Println()
}

// SimpleProgress prints a one-liner progress update.
func SimpleProgress(tested, healthy, total int64) {
	if total > 0 {
		fmt.Printf("\r  tested: %d/%d (%.0f%%)  healthy: %d",
			tested, total, float64(tested)/float64(total)*100, healthy)
	} else {
		fmt.Printf("\r  tested: %d  healthy: %d", tested, healthy)
	}
}

// PrintColoTableBuf writes a colo summary into sb.
func PrintColoTableBuf(sb *strings.Builder, results []*result.Result) {
	PrintColoTableBufWithWidth(sb, results, 80)
}

// PrintColoTableBufWithWidth writes a colo summary into sb while keeping the
// best-IP column compact enough for narrow terminal widths.
func PrintColoTableBufWithWidth(sb *strings.Builder, results []*result.Result, width int) {
	type cs struct {
		count  int
		avgSum int64
		bestMS int64
		bestIP string
	}
	byC := map[string]*cs{}
	for _, r := range results {
		if !r.IsHealthy() || r.Colo == "" {
			continue
		}
		s, ok := byC[r.Colo]
		if !ok {
			s = &cs{bestMS: r.Avg().Milliseconds(), bestIP: r.IP.String()}
			byC[r.Colo] = s
		}
		s.count++
		s.avgSum += r.Avg().Milliseconds()
		if r.Avg().Milliseconds() < s.bestMS {
			s.bestMS = r.Avg().Milliseconds()
			s.bestIP = r.IP.String()
		}
	}
	if len(byC) == 0 {
		sb.WriteString(styleDim.Render("  No colos discovered yet…\n"))
		return
	}
	type row struct {
		colo   string
		count  int
		avgMs  float64
		bestMs int64
		bestIP string
	}
	var rows []row
	for colo, s := range byC {
		rows = append(rows, row{colo, s.count, float64(s.avgSum) / float64(s.count), s.bestMS, s.bestIP})
	}
	// sort by bestMs
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && rows[j].bestMs < rows[j-1].bestMs; j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
	ipWidth := minInt(39, width-42)
	if ipWidth < 15 {
		ipWidth = 15
	}
	separatorWidth := 41 + ipWidth
	sb.WriteString(styleHeader.Render(fmt.Sprintf("  %-6s  %6s  %9s  %9s  %-*s\n",
		"COLO", "COUNT", "AVG(ms)", "BEST(ms)", ipWidth, "BEST IP")))
	sb.WriteString(styleSep.Render("  " + strings.Repeat("─", separatorWidth) + "\n"))
	for _, r := range rows {
		line := fmt.Sprintf("  %-6s  %6d  %9.2f  %9d  %-*s\n",
			r.colo, r.count, r.avgMs, r.bestMs, ipWidth, compactText(r.bestIP, ipWidth))
		sb.WriteString(styleGood.Render(line))
	}
}

// ColoTable prints colo summary to stdout.
func ColoTable(results []*result.Result) {
	var sb strings.Builder
	PrintColoTableBuf(&sb, results)
	fmt.Print(sb.String())
}

// ---------------------------------------------------------------------------
// Command factories (implemented in cmds.go)
// ---------------------------------------------------------------------------

// StartScanCmd, CancelScanCmd, StartTestCmd, StartColosCmd are defined in cmds.go.

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func tick() tea.Cmd {
	return tea.Tick(80*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m AppModel) versionLabel() string {
	version := strings.TrimSpace(m.version)
	if version == "" {
		version = "4.0.0"
	}
	version = strings.TrimPrefix(strings.TrimPrefix(version, "v"), "V")
	return "V" + version
}

func qualityLabel(r *result.Result) string {
	if isExcellentIP(r) {
		return "EXCELLENT"
	}
	if r != nil && r.IsHealthy() {
		return "OK"
	}
	return "FAIL"
}

func isExcellentIP(r *result.Result) bool {
	if r == nil || !r.IsHealthy() {
		return false
	}
	return r.Loss() == 0 &&
		r.Avg() > 0 && r.Avg() < excellentLatencyThreshold &&
		r.Jitter() < excellentJitterThreshold &&
		r.SpeedTested && r.Throughput > excellentSpeedThreshold
}

func qualityStyle(r *result.Result) lipgloss.Style {
	switch {
	case isExcellentIP(r):
		return styleExcellent
	case r != nil && r.IsHealthy():
		return styleGood
	default:
		return styleBad
	}
}

// ---------------------------------------------------------------------------
// Scan with Config page
// ---------------------------------------------------------------------------

func (m AppModel) viewScanWithConfig() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("\n  ⚡  Scan with Config\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", minInt(m.width-4, 70)))))

	if !m.configScanning && !m.configDone {
		// Row 0: URL input
		if m.configSetupRow == 0 {
			sb.WriteString(styleAccent.Render("  Config") + "  ")
		} else {
			sb.WriteString(styleDim.Render("  Config") + "  ")
		}
		sb.WriteString(m.configInput.View() + "\n")
		sb.WriteString(styleDim.Render("           your VLESS/Trojan/VMess share URL (max 8192 chars)") + "\n")
		if summary := configSummaryLine(m.configInput.Value()); summary != "" {
			sb.WriteString(styleDim.Render("           "+summary) + "\n")
		}
		if m.statusMsg != "" {
			sb.WriteString(styleWarn.Render("           "+m.statusMsg) + "\n")
		}
		sb.WriteString("\n")

		// Row 1: Count
		if m.configSetupRow == 1 {
			sb.WriteString(styleAccent.Render("  Count "))
		} else {
			sb.WriteString(styleDim.Render("  Count "))
		}
		for i, label := range configCountLabels {
			if i == m.configCountIdx {
				sb.WriteString(styleSelected.Render(" " + label + " "))
			} else {
				sb.WriteString(styleNormal.Render("  " + label + "  "))
			}
			if i < len(configCountLabels)-1 {
				sb.WriteString(styleDim.Render("│"))
			}
		}
		sb.WriteString("\n")
		sb.WriteString(styleDim.Render("           IPs to probe in Phase 1") + "\n\n")

		// Row 2: Top N
		if m.configSetupRow == 2 {
			sb.WriteString(styleAccent.Render("  Top N "))
		} else {
			sb.WriteString(styleDim.Render("  Top N "))
		}
		for i, label := range configTopNLabels {
			if i == m.configTopNIdx {
				sb.WriteString(styleSelected.Render(" " + label + " "))
			} else {
				sb.WriteString(styleNormal.Render("  " + label + "  "))
			}
			if i < len(configTopNLabels)-1 {
				sb.WriteString(styleDim.Render("│"))
			}
		}
		sb.WriteString("\n")
		sb.WriteString(styleDim.Render("           best IPs to validate with xray") + "\n\n")

		sb.WriteString(styleHint.Render("  ↑/↓ row   ←/→ option   p paste   ctrl+v paste when supported   enter start   esc back") + "\n")
		return sb.String()
	}

	// Stats row
	done := len(m.configResults)
	total := m.configTotal
	if total == 0 {
		total = 10
	}
	success := m.configSuccessCount()
	failed := m.configFailCount()
	skipped := m.configSkipCount()

	icon := m.spinner.View()
	if m.configDone {
		icon = styleGood.Render("✓")
	}

	// Progress bar
	pct := float64(done) / float64(total) * 100
	bw := 22
	filled := int(pct / 100 * float64(bw))
	progBar := "[" + styleAccent.Render(strings.Repeat("█", filled)) +
		styleDim.Render(strings.Repeat("░", bw-filled)) + "]" +
		fmt.Sprintf(" %.0f%%", pct)

	sb.WriteString(fmt.Sprintf("  %s  tested: %s  healthy: %s  failed: %s  skipped: %s  %s\n\n",
		icon,
		styleAccent.Render(fmt.Sprintf("%d/%d", done, total)),
		styleGood.Render(fmt.Sprintf("%d", success)),
		styleBad.Render(fmt.Sprintf("%d", failed)),
		styleWarn.Render(fmt.Sprintf("%d", skipped)),
		progBar,
	))

	// Table header
	hdr := fmt.Sprintf("  %-15s %-8s %-10s %-8s %-24s",
		"IP", "TYPE", "SPEED", "LATENCY", "STATUS")
	sb.WriteString(fmt.Sprintf("%s\n%s\n", styleHeader.Render(hdr), styleSep.Render("  "+strings.Repeat("─", 70))))

	// Results
	maxRows := m.height - 12
	if maxRows < 3 {
		maxRows = 3
	}
	rows := m.configResults
	if len(rows) > maxRows {
		rows = rows[:maxRows]
	}

	for _, r := range rows {
		if r.Success {
			mbps := r.Throughput * 8 / 1000000
			line := fmt.Sprintf("  %-15s %-8s %-10s %-8s %-24s",
				compactText(r.IP, 15), compactText(r.Transport, 8), fmt.Sprintf("%.1fMbps", mbps), fmt.Sprintf("%dms", r.Latency.Milliseconds()), "ok")
			sb.WriteString(styleGood.Render(line) + "\n")
		} else {
			reason := compactText(shortValidationReason(r.Error), 24)
			statusStyle := styleBad
			if r.Skipped {
				statusStyle = styleWarn
			}
			line := fmt.Sprintf("  %-15s %-8s %-10s %-8s %-24s",
				compactText(r.IP, 15), compactText(r.Transport, 8), "—", "—", reason)
			sb.WriteString(statusStyle.Render(line) + "\n")
		}
	}

	sb.WriteRune('\n')
	if m.configDone && done > 0 && success == 0 && skipped == 0 {
		sb.WriteString(styleWarn.Render("  All configs failed validation. Check base config, SNI/Host, path, security, and Xray availability.") + "\n")
	}
	if m.configDone {
		sb.WriteString(styleHint.Render("  q/esc back to menu") + "\n")
	}

	return sb.String()
}

func (m AppModel) configSuccessCount() int {
	count := 0
	for _, r := range m.configResults {
		if r.Success {
			count++
		}
	}
	return count
}

func (m AppModel) configFailCount() int {
	count := 0
	for _, r := range m.configResults {
		if !r.Success && !r.Skipped {
			count++
		}
	}
	return count
}

func (m AppModel) configSkipCount() int {
	count := 0
	for _, r := range m.configResults {
		if r.Skipped {
			count++
		}
	}
	return count
}

func compactText(s string, width int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		s = "—"
	}
	if width <= 0 || len(s) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	return s[:width-1] + "…"
}

func shortValidationReason(err string) string {
	err = strings.TrimSpace(strings.ToLower(err))
	switch {
	case err == "":
		return "invalid config"
	case strings.Contains(err, "parse") || strings.Contains(err, "not a") || strings.Contains(err, "missing"):
		return "parse error"
	case strings.Contains(err, "xray missing") || strings.Contains(err, "xray binary"):
		return "xray missing"
	case strings.Contains(err, "unsupported vmess"):
		return "unsupported vmess validation"
	case strings.Contains(err, "timeout") || strings.Contains(err, "deadline"):
		return "timeout"
	case strings.Contains(err, "handshake"):
		return "handshake failed"
	case strings.Contains(err, "no response") || strings.Contains(err, "connection refused") || strings.Contains(err, "connection reset") || strings.Contains(err, "eof"):
		return "no response"
	case strings.Contains(err, "invalid"):
		return "invalid config"
	default:
		return err
	}
}

func configSummaryLine(raw string) string {
	summary, err := xraytest.ParseShareSummary(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return fmt.Sprintf("parsed: protocol=%s server=%s port=%d transport=%s sni=%s host=%s path=%s",
		compactText(summary.Protocol, 12), compactText(summary.Server, 32), summary.Port,
		compactText(summary.Transport, 12), compactText(summary.SNI, 32), compactText(summary.Host, 32), compactText(summary.Path, 32))
}

func (m AppModel) pasteConfigFromClipboard() AppModel {
	text, err := clipboard.ReadAll()
	if err != nil {
		m.statusMsg = fmt.Sprintf("clipboard paste failed: %v", err)
		return m
	}
	text = strings.TrimSpace(text)
	if len(text) > 8192 {
		text = text[:8192]
		m.statusMsg = "pasted first 8192 characters from clipboard"
	} else {
		m.statusMsg = "pasted from clipboard"
	}
	m.configInput.SetValue(text)
	if summary := configSummaryLine(text); summary != "" {
		m.statusMsg = "pasted config — " + summary
	} else if text != "" {
		m.statusMsg = "pasted; parse error"
	}
	return m
}

func (m AppModel) handleScanWithConfigKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		if m.configScanning || m.configDone {
			m.page = PageHome
			m.configScanning = false
			m.configDone = false
			return m, nil
		}
		m.page = PageHome
		return m, nil
	case "q":
		if m.configDone {
			m.page = PageHome
			m.configDone = false
			return m, nil
		}
	case "up", "k":
		if !m.configScanning && !m.configDone {
			if m.configSetupRow > 0 {
				m.configSetupRow--
			}
			// Focus/blur text input
			if m.configSetupRow == 0 {
				m.configInput.Focus()
			} else {
				m.configInput.Blur()
			}
		}
	case "down", "j":
		if !m.configScanning && !m.configDone {
			if m.configSetupRow < 2 {
				m.configSetupRow++
			}
			if m.configSetupRow == 0 {
				m.configInput.Focus()
			} else {
				m.configInput.Blur()
			}
		}
	case "left", "h":
		if !m.configScanning && !m.configDone {
			if m.configSetupRow == 1 && m.configCountIdx > 0 {
				m.configCountIdx--
			} else if m.configSetupRow == 2 && m.configTopNIdx > 0 {
				m.configTopNIdx--
			}
		}
	case "right", "l":
		if !m.configScanning && !m.configDone {
			if m.configSetupRow == 1 && m.configCountIdx < len(configCountLabels)-1 {
				m.configCountIdx++
			} else if m.configSetupRow == 2 && m.configTopNIdx < len(configTopNLabels)-1 {
				m.configTopNIdx++
			}
		}
	case "p", "ctrl+v":
		if !m.configScanning && !m.configDone {
			m.configSetupRow = 0
			m.configInput.Focus()
			m = m.pasteConfigFromClipboard()
			return m, nil
		}
	case "enter":
		if !m.configScanning && !m.configDone {
			rawURL := strings.TrimSpace(m.configInput.Value())
			if rawURL == "" {
				return m, nil
			}
			if _, err := xraytest.ParseShareSummary(rawURL); err != nil {
				m.statusMsg = fmt.Sprintf("parse error: %v", err)
				return m, nil
			}
			m.configURL = rawURL
			// Start Phase 1
			m.page = PageConfigPhase1
			m.configPhase1Results = nil
			m.configPhase1Done = false
			count := configCountValues[m.configCountIdx]
			return m, m.startConfigPhase1(count)
		}
	}

	// Forward key to text input when on row 0
	if !m.configScanning && !m.configDone && m.configSetupRow == 0 {
		var cmd tea.Cmd
		m.configInput, cmd = m.configInput.Update(msg)
		return m, cmd
	}
	return m, nil
}

// ConfigDoneMsg signals all config validations are complete.
type ConfigDoneMsg struct{}

// ConfigBatchResultMsg is no longer used — results come one by one via ConfigProgressMsg.
type ConfigBatchResultMsg struct {
	Results []*xraytest.ValidationResult
}

// ConfigProgressMsg carries a single result during scanning.
type ConfigProgressMsg struct {
	Result *xraytest.ValidationResult
	Done   int
	Total  int
}

func (m AppModel) startConfigScan(rawURL string) tea.Cmd {
	return func() tea.Msg {
		go runConfigScan(rawURL)
		return nil
	}
}

func runConfigScan(rawURL string) {
	cfg, err := xraytest.ParseVLESS(rawURL)
	if err != nil {
		if prog != nil {
			prog.Send(ConfigDoneMsg{})
		}
		return
	}

	// Top CF IPs to test
	testIPs := []string{
		"104.18.5.1", "104.17.0.1", "172.66.40.1",
		"172.67.186.127", "104.21.19.146", "104.16.0.1",
		"104.19.229.21", "104.18.10.1", "104.17.100.1",
		"104.16.200.1",
	}

	ctx := context.Background()
	total := len(testIPs)

	for i, ip := range testIPs {
		swapped := cfg.WithAddress(ip)
		r := xraytest.ValidateConfig(ctx, swapped, 20*time.Second)
		if prog != nil {
			prog.Send(ConfigProgressMsg{
				Result: r,
				Done:   i + 1,
				Total:  total,
			})
		}
	}

	if prog != nil {
		prog.Send(ConfigDoneMsg{})
	}
}

// ---------------------------------------------------------------------------
// Config Setup presets
// ---------------------------------------------------------------------------

var configCountValues = []int{1000, 5000, 20000}
var configCountLabels = []string{"1,000", "5,000", "20,000"}
var configTopNValues = []int{10, 25, 50, 0}
var configTopNLabels = []string{"10", "25", "50", "All"}

// ---------------------------------------------------------------------------
// Config Setup page
// ---------------------------------------------------------------------------

func (m AppModel) viewConfigSetup() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("\n  ⚡  Scan with Config — Setup\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", minInt(m.width-4, 70)))))

	sb.WriteString(styleNormal.Render("  Phase 1: Fast connectivity scan to find reachable IPs") + "\n")
	sb.WriteString(styleNormal.Render("  Phase 2: Test top IPs with your actual xray config") + "\n\n")

	// Count row
	countLabel := "  Count   "
	for i, label := range configCountLabels {
		if i == m.configCountIdx && m.configSetupRow == 0 {
			sb.WriteString(styleSelected.Render(" " + label + " "))
		} else {
			sb.WriteString(styleNormal.Render("  " + label + "  "))
		}
		if i < len(configCountLabels)-1 {
			sb.WriteString(styleDim.Render("│"))
		}
	}
	sb.WriteString("\n")
	if m.configSetupRow == 0 {
		sb.WriteString(styleAccent.Render(countLabel) + styleDim.Render("IPs to probe in Phase 1") + "\n\n")
	} else {
		sb.WriteString(styleDim.Render(countLabel+"IPs to probe in Phase 1") + "\n\n")
	}

	// Top N row
	topLabel := "  Top N   "
	for i, label := range configTopNLabels {
		if i == m.configTopNIdx && m.configSetupRow == 1 {
			sb.WriteString(styleSelected.Render(" " + label + " "))
		} else {
			sb.WriteString(styleNormal.Render("  " + label + "  "))
		}
		if i < len(configTopNLabels)-1 {
			sb.WriteString(styleDim.Render("│"))
		}
	}
	sb.WriteString("\n")
	if m.configSetupRow == 1 {
		sb.WriteString(styleAccent.Render(topLabel) + styleDim.Render("best IPs to validate with xray") + "\n\n")
	} else {
		sb.WriteString(styleDim.Render(topLabel+"best IPs to validate with xray") + "\n\n")
	}

	sb.WriteString(styleHint.Render("  ↑/↓ row   ←/→ option   p paste   ctrl+v paste when supported   enter start   esc back") + "\n")

	return sb.String()
}

func (m AppModel) handleConfigSetupKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.page = PageScanWithConfig
		return m, nil
	case "up", "k":
		if m.configSetupRow > 0 {
			m.configSetupRow--
		}
	case "down", "j":
		if m.configSetupRow < 1 {
			m.configSetupRow++
		}
	case "left", "h":
		if m.configSetupRow == 0 && m.configCountIdx > 0 {
			m.configCountIdx--
		} else if m.configSetupRow == 1 && m.configTopNIdx > 0 {
			m.configTopNIdx--
		}
	case "right", "l":
		if m.configSetupRow == 0 && m.configCountIdx < len(configCountLabels)-1 {
			m.configCountIdx++
		} else if m.configSetupRow == 1 && m.configTopNIdx < len(configTopNLabels)-1 {
			m.configTopNIdx++
		}
	case "enter":
		// Start Phase 1
		m.page = PageConfigPhase1
		m.configPhase1Results = nil
		m.configPhase1Done = false
		m.configPhase1Stats = StatsMsg{}
		count := configCountValues[m.configCountIdx]
		return m, m.startConfigPhase1(count)
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Config Phase 1 — fast connectivity scan
// ---------------------------------------------------------------------------

type ConfigPhase1ResultMsg struct {
	Result *result.Result
}

type ConfigPhase1StatsMsg = StatsMsg

type ConfigPhase1DoneMsg struct{}

func (m AppModel) viewConfigPhase1() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("\n  ⚡  Phase 1 — Finding reachable IPs\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", minInt(m.width-4, 70)))))

	icon := m.spinner.View()
	if m.configPhase1Done {
		icon = styleGood.Render("✓")
	}

	healthy := 0
	for _, r := range m.configPhase1Results {
		if r.IsHealthy() {
			healthy++
		}
	}

	sb.WriteString(fmt.Sprintf("  %s  tested: %s  healthy: %s  target: %s\n\n",
		icon,
		styleAccent.Render(fmt.Sprintf("%d", len(m.configPhase1Results))),
		styleGood.Render(fmt.Sprintf("%d", healthy)),
		styleDim.Render(fmt.Sprintf("%d", configCountValues[m.configCountIdx])),
	))

	if m.configPhase1Done {
		topN := configTopNValues[m.configTopNIdx]
		sb.WriteString(styleGood.Render(fmt.Sprintf("  Found %d healthy IPs. Starting Phase 2 with top %d...\n", healthy, topN)))
	} else {
		sb.WriteString(styleNormal.Render("  Scanning Cloudflare IP ranges for connectivity...\n"))
	}

	sb.WriteString("\n" + styleHint.Render("  q/esc cancel") + "\n")
	return sb.String()
}

func (m AppModel) handleConfigPhase1Key(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		scans.Cancel()
		m.page = PageHome
		return m, nil
	}
	return m, nil
}

func (m AppModel) startConfigPhase1(count int) tea.Cmd {
	return func() tea.Msg {
		go runConfigPhase1(count)
		return nil
	}
}

func runConfigPhase1(count int) {
	src, err := ipsrc.New(true, false, nil)
	if err != nil {
		if prog != nil {
			prog.Send(ConfigPhase1DoneMsg{})
		}
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	scans.SetCancel(cancel)
	defer scans.Clear(cancel)
	defer cancel()

	engCfg := engine.Config{
		Concurrency: 100,
		ProbeConfig: prober.Config{
			Port:       443,
			Mode:       prober.ModeHTTP,
			Tries:      2,
			Timeout:    3 * time.Second,
			SpeedBytes: 0, // no download in Phase 1 — just connectivity
		},
	}
	eng := engine.New(engCfg)
	ipStream := src.Stream(ctx, count)

	eng.Run(ctx, ipStream, func(r *result.Result) {
		if prog != nil {
			prog.Send(ConfigPhase1ResultMsg{Result: r})
		}
	})

	if prog != nil {
		prog.Send(ConfigPhase1DoneMsg{})
	}
}

// ---------------------------------------------------------------------------
// Config Phase 2 — xray validation of top IPs
// ---------------------------------------------------------------------------

func (m AppModel) startConfigPhase2(topIPs []*result.Result) tea.Cmd {
	url := m.configURL
	return func() tea.Msg {
		go runConfigPhase2(url, topIPs)
		return nil
	}
}

func runConfigPhase2(rawURL string, topIPs []*result.Result) {
	summary, parseErr := xraytest.ParseShareSummary(rawURL)
	total := len(topIPs)
	xrayAvailable := xraytest.XrayAvailable()
	firstErr := ""
	defer func() {
		writeConfigDebugLog(total, xrayAvailable, firstErr)
		if prog != nil {
			prog.Send(ConfigDoneMsg{})
		}
	}()

	if parseErr != nil {
		firstErr = fmt.Sprintf("parse error: %v", parseErr)
		for i, r := range topIPs {
			vr := &xraytest.ValidationResult{IP: r.IP.String(), Error: firstErr, Transport: "—"}
			if prog != nil {
				prog.Send(ConfigProgressMsg{Result: vr, Done: i + 1, Total: total})
			}
		}
		return
	}

	if !xrayAvailable {
		firstErr = "xray missing"
		for i, r := range topIPs {
			vr := &xraytest.ValidationResult{IP: r.IP.String(), Port: summary.Port, Transport: summary.Transport, Skipped: true, Error: firstErr}
			if prog != nil {
				prog.Send(ConfigProgressMsg{Result: vr, Done: i + 1, Total: total})
			}
		}
		return
	}

	ctx := context.Background()
	scheme := strings.ToLower(summary.Protocol)
	for i, r := range topIPs {
		ip := r.IP.String()
		vr := validateShareForIP(ctx, rawURL, scheme, ip, 20*time.Second)
		if !vr.Success && !vr.Skipped && firstErr == "" {
			firstErr = vr.Error
		}
		if prog != nil {
			prog.Send(ConfigProgressMsg{Result: vr, Done: i + 1, Total: total})
		}
	}
}

func validateShareForIP(ctx context.Context, rawURL, scheme, ip string, timeout time.Duration) *xraytest.ValidationResult {
	switch scheme {
	case "vless":
		cfg, err := xraytest.ParseVLESS(rawURL)
		if err != nil {
			return &xraytest.ValidationResult{IP: ip, Error: fmt.Sprintf("parse error: %v", err)}
		}
		return xraytest.ValidateConfig(ctx, cfg.WithAddress(ip), timeout)
	case "trojan":
		cfg, err := xraytest.ParseTrojan(rawURL)
		if err != nil {
			return &xraytest.ValidationResult{IP: ip, Error: fmt.Sprintf("parse error: %v", err)}
		}
		copy := *cfg
		copy.Address = ip
		return xraytest.ValidateTrojanConfig(ctx, &copy, timeout)
	case "vmess":
		summary, _ := xraytest.ParseShareSummary(rawURL)
		return &xraytest.ValidationResult{IP: ip, Port: summary.Port, Transport: summary.Transport, Skipped: true, Error: "unsupported vmess validation"}
	default:
		return &xraytest.ValidationResult{IP: ip, Error: "invalid config"}
	}
}

func writeConfigDebugLog(generatedCount int, xrayAvailable bool, firstErr string) {
	if firstErr == "" {
		firstErr = "none"
	}
	content := fmt.Sprintf("generated_config_count=%d\nxray_available=%t\nfirst_error_reason=%s\n", generatedCount, xrayAvailable, firstErr)
	_ = os.WriteFile("scan_config_debug.log", []byte(content), 0644)
}

func (m AppModel) viewEmergencyScan() string {
	var sb strings.Builder
	sb.WriteString(styleTitle.Render("\n  🚨  Emergency Scan\n"))
	sb.WriteString(fmt.Sprintf("%s\n\n", styleSep.Render("  "+strings.Repeat("─", minInt(m.width-4, 70)))))
	sb.WriteString(styleNormal.Render("  Finds up to 10 healthy IPv4 Cloudflare IPs quickly and writes:\n"))
	sb.WriteString(styleDim.Render("    good_ips.txt, ip_port.txt, generated_configs.txt (when config is provided)\n\n"))
	sb.WriteString(styleHeader.Render("  Base config (optional)  "))
	sb.WriteString(m.configInput.View() + "\n")
	sb.WriteString(styleDim.Render("  Leave empty for IP-only emergency output. Supports vless://, trojan://, vmess:// generation.\n\n"))
	if m.statusMsg != "" {
		sb.WriteString(styleWarn.Render("  "+m.statusMsg) + "\n\n")
	}
	sb.WriteString(styleHint.Render("  enter start   esc back"))
	return sb.String()
}

func (m AppModel) handleEmergencyKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.page = PageHome
		return m, nil
	case "enter":
		base := strings.TrimSpace(m.configInput.Value())
		if base != "" {
			if _, err := configgen.Generate(base, []net.IP{net.ParseIP("104.18.0.1")}); err != nil {
				m.statusMsg = fmt.Sprintf("Invalid base config: %v", err)
				return m, nil
			}
		}
		cfg := ScanConfig{Count: "1000", Concurrency: "50", Timeout: "5s", Tries: "2", Port: "443", Mode: "http", UseV4: true, UseV6: false, StopAfterHealthy: 10, Emergency: true, BaseConfig: base}
		m.scanCfg = cfg
		m.activeScanID = nextScanID()
		m.statusMsg = "Emergency scan running; exports will be written in the current directory."
		m.scanResults = nil
		m.configResults = nil
		m.scanDone = false
		m.scanStats = StatsMsg{ScanID: m.activeScanID}
		m.scanStarted = time.Now()
		m.scanTotal = 1000
		m.page = PageLiveScan
		return m, StartScanCmd(cfg, m.activeScanID)
	}
	var cmd tea.Cmd
	m.configInput, cmd = m.configInput.Update(msg)
	return m, cmd
}
