package modifier

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const baseVLESS = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&type=ws&host=example.com&path=%2F#base"

func TestGenerateIPList(t *testing.T) {
	output, err := Generate(Options{Configs: baseVLESS, Type: IPList, InputData: "IPs: 1.1.1.1\n1.1.1.1\n2606:4700:4700::1111"})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(output, "\n")
	if len(lines) != 2 {
		t.Fatalf("generated %d configs, want 2: %q", len(lines), output)
	}
	if !strings.Contains(lines[0], "@1.1.1.1:443") || !strings.Contains(lines[1], "@[2606:4700:4700::1111]:443") {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestGenerateIPRanges(t *testing.T) {
	output, err := Generate(Options{Configs: baseVLESS, Type: IPRanges, InputData: "192.0.2.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(output, "\n")
	if len(lines) != 4 {
		t.Fatalf("generated %d configs, want 4", len(lines))
	}
	for i, line := range lines {
		want := "@192.0.2." + string(rune('0'+i)) + ":443"
		if !strings.Contains(line, want) {
			t.Fatalf("config %d missing %q: %q", i, want, line)
		}
	}
}

func TestGenerateConfigsList(t *testing.T) {
	targets := strings.Join([]string{
		"trojan://password@203.0.113.10:443?security=tls#one",
		vmessLink(t, "203.0.113.11", 8443),
	}, "\n")
	output, err := Generate(Options{Configs: baseVLESS, Type: ConfigsList, InputData: targets})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "@203.0.113.10:443") || !strings.Contains(output, "@203.0.113.11:443") {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestGenerateSNISpoof(t *testing.T) {
	output, err := Generate(Options{Configs: baseVLESS, Type: SNISpoof, InputData: "127.0.0.1:40443"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "@127.0.0.1:40443") {
		t.Fatalf("spoof endpoint was not applied: %q", output)
	}
	if !strings.Contains(output, "host=example.com") {
		t.Fatalf("config query was not preserved: %q", output)
	}
}

func TestGenerateMultilineConfigs(t *testing.T) {
	configs := baseVLESS + "\n\n  " + vmessLink(t, "example.net", 443) + "  \ninvalid://ignored"
	output, err := Generate(Options{Configs: configs, Type: IPList, InputData: "198.51.100.7"})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(output, "\n")
	if len(lines) != 2 {
		t.Fatalf("generated %d configs, want 2: %q", len(lines), output)
	}
	fields, err := decodeVMess(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	if fields.Address != "198.51.100.7" {
		t.Fatalf("vmess address = %q, want 198.51.100.7", fields.Address)
	}
}

func TestGenerateRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config string
		want   string
	}{
		{name: "unsupported", config: "not-a-config", want: "no valid base configs"},
		{name: "malformed supported link", config: "vless://missing-endpoint", want: "invalid config endpoint"},
		{name: "malformed vmess", config: "vmess://not-base64", want: "decode vmess base64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Generate(Options{Configs: tt.config, Type: IPList, InputData: "1.1.1.1"})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func vmessLink(t *testing.T, address string, port int) string {
	t.Helper()
	payload := map[string]any{"v": "2", "ps": "test", "add": address, "port": port, "id": "12345678-1234-1234-1234-123456789abc", "net": "ws"}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(data)
}
