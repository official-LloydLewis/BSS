package ui

import (
	"strings"
	"testing"

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
