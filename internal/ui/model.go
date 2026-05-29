package ui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/matinsenpai/senpaiscanner/internal/banner"
	"github.com/matinsenpai/senpaiscanner/internal/config"
	"github.com/matinsenpai/senpaiscanner/internal/result"
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
	Count       string
	Concurrency string
	Timeout     string
	Tries       string
	Port        string
	Mode        string // tcp|tls|http
	CIDR        string
	OutputFile  string
	ColoFilter  string
	SNI         string
	UseV4       bool
	UseV6       bool
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
	{"Test IPs", "deep-test a list of IPs from file"},
	{"Discover Colos", "find reachable Cloudflare PoPs"},
	{"About", ""},
	{"Quit", ""},
}

const menuLabelWidth = 16

const (
	menuQuickScan  = 0
	menuCustomScan = 1
	menuTestIPs    = 2
	menuColos      = 3
	menuAbout      = 4
	menuQuit       = 5
)

var modes = []string{"tls", "tcp", "http"}

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
	sb.WriteString(styleDim.Render(fmt.Sprintf("  v%s", m.version)))
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

	sb.WriteString(banner.Render(m.bannerFrame / 2))
	sb.WriteRune('\n')
	sb.WriteString(styleTitle.Render("  ⚡  Quick Scan Setup\n"))
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
	hdr := fmt.Sprintf("  %-18s  %7s  %9s  %8s  %9s  %5s  %-6s",
		"IP", "LOSS", "AVG(ms)", "JTR(ms)", "DL(KB/s)", "TLS", "COLO")
	sb.WriteString(fmt.Sprintf("%s\n%s\n", styleHeader.Render(hdr), styleSep.Render("  "+strings.Repeat("─", 72))))

	maxRows := m.height - 14
	if maxRows < 3 {
		maxRows = 3
	}
	rows := m.scanResults
	if len(rows) > maxRows {
		rows = rows[:maxRows]
	}

	for _, r := range rows {
		tlsIcon := styleBad.Render("✗")
		if r.TLSOk {
			tlsIcon = styleGood.Render("✓")
		}
		colo := r.Colo
		if colo == "" {
			colo = "—"
		}
		line := fmt.Sprintf("  %-18s  %6.1f%%  %9.2f  %8.2f  %9.1f  %5s  %-6s",
			r.IP.String(), r.Loss(),
			float64(r.Avg().Milliseconds()),
			float64(r.Jitter().Milliseconds()),
			r.Throughput/1024,
			tlsIcon, colo)

		switch {
		case r.IsHealthy() && r.Loss() == 0 && r.Avg().Milliseconds() < 200:
			sb.WriteString(fmt.Sprintf("%s\n", styleGood.Render(line)))
		case !r.IsHealthy():
			sb.WriteString(fmt.Sprintf("%s\n", styleBad.Render(line)))
		default:
			sb.WriteString(fmt.Sprintf("%s\n", styleWarn.Render(line)))
		}
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
		hdr := fmt.Sprintf("  %-18s  %7s  %9s  %8s  %9s  %5s  %-6s",
			"IP", "LOSS", "AVG(ms)", "JTR(ms)", "DL(KB/s)", "TLS", "COLO")
		sb.WriteString(fmt.Sprintf("%s\n%s\n", styleHeader.Render(hdr), styleSep.Render("  "+strings.Repeat("─", 72))))

		for i, r := range top {
			tlsIcon := "✗"
			if r.TLSOk {
				tlsIcon = "✓"
			}
			colo := r.Colo
			if colo == "" {
				colo = "—"
			}
			rank := styleAccent.Render(fmt.Sprintf(" %2d. ", i+1))
			line := fmt.Sprintf("%-18s  %6.1f%%  %9.2f  %8.2f  %9.1f  %5s  %-6s",
				r.IP.String(), r.Loss(),
				float64(r.Avg().Milliseconds()),
				float64(r.Jitter().Milliseconds()),
				r.Throughput/1024,
				tlsIcon, colo)
			sb.WriteString(fmt.Sprintf("%s%s\n", rank, styleGood.Render(line)))
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

	PrintColoTableBuf(&sb, m.colosResults)

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
	sb.WriteString(styleTitle.Render("  SenPai Scanner\n"))
	sb.WriteString(styleDim.Render(fmt.Sprintf("  version %s", m.version)))
	sb.WriteString("\n\n")
	sb.WriteString(styleNormal.Render("  A Cloudflare IP scanner built for high-latency, restricted networks.\n"))
	sb.WriteString(styleNormal.Render("  Probes Cloudflare's edge nodes via TCP/TLS/HTTP, measures loss,\n"))
	sb.WriteString(styleNormal.Render("  jitter, and identifies the colo (PoP) behind each IP.\n\n"))
	sb.WriteString(styleDim.Render("  github.com/matinsenpai/senpaiscanner\n\n"))
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

	hdr := fmt.Sprintf("  %-18s  %7s  %9s  %8s  %9s  %4s  %-5s",
		"IP", "LOSS", "AVG(ms)", "JTR(ms)", "DL(KB/s)", "TLS", "COLO")
	fmt.Println(hdr)
	fmt.Println("  " + strings.Repeat("─", 72))
	for _, r := range sorted {
		tls := "✗"
		if r.TLSOk {
			tls = "✓"
		}
		colo := r.Colo
		if colo == "" {
			colo = "—"
		}
		fmt.Printf("  %-18s  %6.1f%%  %9.2f  %8.2f  %9.1f  %4s  %-5s\n",
			r.IP.String(), r.Loss(),
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
	sb.WriteString(styleHeader.Render(fmt.Sprintf("  %-6s  %6s  %9s  %9s  %s\n",
		"COLO", "COUNT", "AVG(ms)", "BEST(ms)", "BEST IP")))
	sb.WriteString(styleSep.Render("  " + strings.Repeat("─", 52) + "\n"))
	for _, r := range rows {
		line := fmt.Sprintf("  %-6s  %6d  %9.2f  %9d  %s\n",
			r.colo, r.count, r.avgMs, r.bestMs, r.bestIP)
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
