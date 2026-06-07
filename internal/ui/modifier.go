package ui

import (
	"fmt"
	"strings"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/matinsenpai/senpaiscanner/internal/banner"
	"github.com/matinsenpai/senpaiscanner/internal/modifier"
)

const modifierRowCount = 7

func (m AppModel) handleModifierKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key == "ctrl+c" {
		if !m.modifierEditing {
			m.page = PageHome
			return m, nil
		}
		key = "esc"
	}

	if m.modifierEditing {
		if m.modifierSaving {
			switch key {
			case "esc":
				m.modifierEditing = false
				m.modifierSaving = false
				m.modifierSavePath.Blur()
				return m, nil
			case "enter":
				path := strings.TrimSpace(m.modifierSavePath.Value())
				if path == "" {
					path = "modified-configs.txt"
					m.modifierSavePath.SetValue(path)
				}
				if m.modifierResult == "" {
					m.statusMsg = "Generate configs before saving."
				} else if err := modifier.Save(path, m.modifierResult); err != nil {
					m.statusMsg = fmt.Sprintf("Save failed: %v", err)
				} else {
					m.statusMsg = fmt.Sprintf("Saved generated configs to %s", path)
				}
				m.modifierEditing = false
				m.modifierSaving = false
				m.modifierSavePath.Blur()
				return m, nil
			}
			return m.updateFormInputs(msg)
		}

		switch key {
		case "esc", "ctrl+s":
			m.modifierEditing = false
			m.modifierConfig.Blur()
			m.modifierInput.Blur()
			return m, nil
		}
		return m.updateFormInputs(msg)
	}

	switch key {
	case "q", "esc":
		m.page = PageHome
	case "up", "k":
		if m.modifierRow > 0 {
			m.modifierRow--
		}
	case "down", "j":
		if m.modifierRow < modifierRowCount-1 {
			m.modifierRow++
		}
	case "left", "h":
		if m.modifierRow == 1 {
			m.cycleModifierType(-1)
		}
	case "right", "l":
		if m.modifierRow == 1 {
			m.cycleModifierType(1)
		}
	case "enter", " ":
		return m.activateModifierRow()
	}
	return m, nil
}

func (m AppModel) activateModifierRow() (tea.Model, tea.Cmd) {
	switch m.modifierRow {
	case 0:
		m.modifierEditing = true
		m.modifierConfig.Focus()
		return m, nil
	case 1:
		m.cycleModifierType(1)
	case 2:
		m.modifierEditing = true
		m.modifierInput.Focus()
		return m, nil
	case 3:
		output, err := modifier.Generate(modifier.Options{
			Configs:   m.modifierConfig.Value(),
			Type:      m.modifierType,
			InputData: m.modifierInput.Value(),
		})
		if err != nil {
			m.statusMsg = fmt.Sprintf("Generate failed: %v", err)
			return m, nil
		}
		m.modifierResult = output
		m.statusMsg = fmt.Sprintf("Successfully generated %d configs.", countLines(output))
	case 4:
		if m.modifierResult == "" {
			m.statusMsg = "Generate configs before copying."
		} else if err := clipboard.WriteAll(m.modifierResult); err != nil {
			m.statusMsg = fmt.Sprintf("Clipboard unavailable: %v. Result remains visible.", err)
		} else {
			m.statusMsg = "Generated configs copied to clipboard."
		}
	case 5:
		m.modifierEditing = true
		m.modifierSaving = true
		m.modifierSavePath.Focus()
		return m, nil
	case 6:
		m.page = PageHome
	}
	return m, nil
}

func (m *AppModel) cycleModifierType(delta int) {
	const typeCount = int(modifier.SNISpoof) + 1
	value := (int(m.modifierType) + delta + typeCount) % typeCount
	m.modifierType = modifier.InputType(value)
	m.modifierInput.SetValue("")
	m.modifierResult = ""
	m.statusMsg = ""
	m.updateModifierPlaceholder()
}

func (m *AppModel) updateModifierPlaceholder() {
	switch m.modifierType {
	case modifier.IPRanges:
		m.modifierInput.Placeholder = "Each CIDR range on a new line (maximum 5,000 outputs)"
	case modifier.IPList:
		m.modifierInput.Placeholder = "IPs may be separated by lines or other text"
	case modifier.ConfigsList:
		m.modifierInput.Placeholder = "Target configs, one per line"
	case modifier.SNISpoof:
		m.modifierInput.Placeholder = "Spoof endpoint, for example 127.0.0.1:40443"
	}
}

func (m AppModel) viewModifier() string {
	var sb strings.Builder
	if m.width >= 76 && m.height >= 30 {
		sb.WriteString(banner.Render(m.bannerFrame / 2))
		sb.WriteRune('\n')
	}
	sb.WriteString(styleTitle.Render("  V2ray Config Modifier"))
	sb.WriteRune('\n')
	sb.WriteString(styleSep.Render("  " + strings.Repeat("─", clamp(m.width-4, 8, 72))))
	sb.WriteString("\n\n")

	rows := []string{
		"Config",
		fmt.Sprintf("Input Type  ‹ %s ›", m.modifierType.String()),
		"Input Data",
		"Generate Configs",
		"Copy result to clipboard",
		fmt.Sprintf("Save result to file  (%s)", m.modifierSavePath.Value()),
		"Back",
	}
	for i, row := range rows {
		cursor := "  "
		rowStyle := styleNormal
		if i == m.modifierRow && !m.modifierEditing {
			cursor = styleAccent.Render("▶ ")
			rowStyle = styleSelected
		}
		sb.WriteString("  " + cursor + rowStyle.Render(fmt.Sprintf("%d. %s", i+1, row)) + "\n")
	}

	sb.WriteString("\n")
	switch {
	case m.modifierEditing && !m.modifierSaving && m.modifierRow == 0:
		sb.WriteString(styleHeader.Render("  Config input — multiline paste supported (ctrl+s or esc to finish)") + "\n")
		sb.WriteString("  " + m.modifierConfig.View() + "\n")
	case m.modifierEditing && !m.modifierSaving && m.modifierRow == 2:
		sb.WriteString(styleHeader.Render(fmt.Sprintf("  %s input — multiline paste supported (ctrl+s or esc to finish)", m.modifierType.String())) + "\n")
		sb.WriteString("  " + m.modifierInput.View() + "\n")
	case m.modifierSaving:
		sb.WriteString(styleHeader.Render("  Output file path (enter to save, esc to cancel)") + "\n")
		sb.WriteString("  " + m.modifierSavePath.View() + "\n")
	default:
		sb.WriteString(styleDim.Render(fmt.Sprintf("  Configs: %d line(s)   Input: %d line(s)   Result: %d config(s)", countNonEmptyLines(m.modifierConfig.Value()), countNonEmptyLines(m.modifierInput.Value()), countLines(m.modifierResult))) + "\n")
		if m.modifierResult != "" {
			previewCount := clamp(m.height-21, 1, 8)
			sb.WriteString(styleHeader.Render("  Result preview") + "\n")
			for _, line := range previewLines(m.modifierResult, previewCount) {
				sb.WriteString("  " + styleDim.Render(line) + "\n")
			}
		}
	}

	if m.statusMsg != "" {
		sb.WriteString("\n" + styleWarn.Render("  "+m.statusMsg) + "\n")
	}
	if m.modifierEditing {
		sb.WriteString(styleHint.Render("  esc/ctrl+c cancel or finish"))
	} else {
		sb.WriteString(styleHint.Render("  ↑/↓ navigate   ←/→ input type   enter select   esc back"))
	}
	return sb.String()
}

func countLines(value string) int {
	if strings.TrimSpace(value) == "" {
		return 0
	}
	return len(strings.Split(value, "\n"))
}

func countNonEmptyLines(value string) int {
	count := 0
	for _, line := range strings.Split(value, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func previewLines(value string, limit int) []string {
	lines := strings.Split(value, "\n")
	if len(lines) <= limit {
		return lines
	}
	return append(lines[:limit], fmt.Sprintf("… and %d more", len(lines)-limit))
}
