package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

const (
	defaultTerminalWidth  = 120
	defaultTerminalHeight = 40
)

// fixedFrame constrains every render to the current terminal dimensions. Bubble
// Tea redraws this complete frame in the alternate screen, so high-frequency
// updates cannot append lines and push persistent content out of view.
func fixedFrame(view string, width, height int) string {
	if width <= 0 {
		width = defaultTerminalWidth
	}
	if height <= 0 {
		height = defaultTerminalHeight
	}

	view = strings.ReplaceAll(view, "\r\n", "\n")
	view = strings.TrimSuffix(view, "\n")
	lines := strings.Split(view, "\n")
	if len(lines) > height {
		// Treat the final line as the persistent status/navigation bar.
		// Content is clipped above it instead of pushing it off-screen.
		last := lines[len(lines)-1]
		lines = append(lines[:height-1], last)
	}
	for i, line := range lines {
		if lipgloss.Width(line) > width {
			lines[i] = ansi.Truncate(line, width, "")
		}
	}
	for len(lines) < height {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func clamp(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
