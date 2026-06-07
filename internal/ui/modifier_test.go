package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/matinsenpai/senpaiscanner/internal/modifier"
)

func TestModifierMenuOpensCompactPage(t *testing.T) {
	m := NewApp("test")
	m.menuIdx = menuModifier
	model, _ := m.selectMenuItem()
	got := model.(AppModel)
	if got.page != PageModifier {
		t.Fatalf("page = %v, want PageModifier", got.page)
	}
	view := ansiRE.ReplaceAllString(got.viewModifier(), "")
	for _, label := range []string{"1. Config", "2. Input Type", "3. Input Data", "4. Generate Configs", "5. Copy result to clipboard", "6. Save result to file", "7. Back"} {
		if !strings.Contains(view, label) {
			t.Fatalf("modifier view missing %q", label)
		}
	}
}

func TestModifierGenerateRowUsesInternalGenerator(t *testing.T) {
	m := NewApp("test")
	m.page = PageModifier
	m.modifierType = modifier.IPList
	m.modifierConfig.SetValue(baseModifierVLESS)
	m.modifierInput.SetValue("1.1.1.1\n1.0.0.1")
	m.modifierRow = 3

	model, _ := m.activateModifierRow()
	got := model.(AppModel)
	if countLines(got.modifierResult) != 2 {
		t.Fatalf("generated result = %q, want 2 configs", got.modifierResult)
	}
	if !strings.Contains(got.statusMsg, "Successfully generated 2 configs") {
		t.Fatalf("status = %q", got.statusMsg)
	}
}

const baseModifierVLESS = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&type=ws&host=example.com#base"

func TestModifierKeyboardNavigationAndCancel(t *testing.T) {
	m := NewApp("test")
	m.page = PageModifier
	m.modifierRow = 1
	m.modifierType = modifier.IPRanges

	model, _ := m.handleModifierKey(keyMsg("right"))
	m = model.(AppModel)
	if m.modifierType != modifier.IPList {
		t.Fatalf("right key type = %v, want IP List", m.modifierType)
	}
	model, _ = m.handleModifierKey(keyMsg("down"))
	m = model.(AppModel)
	if m.modifierRow != 2 {
		t.Fatalf("down key row = %d, want 2", m.modifierRow)
	}
	model, _ = m.handleModifierKey(keyMsg("enter"))
	m = model.(AppModel)
	if !m.modifierEditing {
		t.Fatal("enter on Input Data did not start editing")
	}
	model, _ = m.handleModifierKey(keyMsg("ctrl+c"))
	m = model.(AppModel)
	if m.modifierEditing || m.page != PageModifier {
		t.Fatalf("ctrl+c should cancel input without leaving modifier: editing=%v page=%v", m.modifierEditing, m.page)
	}
}

func keyMsg(key string) tea.KeyMsg {
	switch key {
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
	}
}
