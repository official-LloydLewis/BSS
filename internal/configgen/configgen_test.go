package configgen

import (
	"net"
	"strings"
	"testing"
)

func TestGenerateVLESSPreservesParts(t *testing.T) {
	base := "vless://UUID@example.com:443?security=tls&sni=example.com&type=ws&host=example.com&path=/abc#name"
	got, err := Generate(base, []net.IP{net.ParseIP("104.18.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	want := "vless://UUID@104.18.0.1:443?security=tls&sni=example.com&type=ws&host=example.com&path=/abc#name"
	if got[0] != want {
		t.Fatalf("got %q want %q", got[0], want)
	}
}

func TestGenerateTrojanPreservesQueryAndFragment(t *testing.T) {
	base := "trojan://pass@example.com:443?security=tls&sni=example.com&type=ws&path=%2Fabc#my-name"
	got, err := Generate(base, []net.IP{net.ParseIP("172.67.1.2")})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "trojan://pass@172.67.1.2:443?security=tls&sni=example.com&type=ws&path=%2Fabc#my-name" {
		t.Fatal(got[0])
	}
}

func TestGenerateIPv6(t *testing.T) {
	base := "vless://UUID@example.com:443?security=tls#name"
	got, err := Generate(base, []net.IP{net.ParseIP("2606:4700::1")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got[0], "@[2606:4700::1]:443") {
		t.Fatal(got[0])
	}
	if !strings.HasSuffix(got[0], "?security=tls#name") {
		t.Fatal(got[0])
	}
}

func TestGenerateVMessUsesStandardBase64(t *testing.T) {
	base := "vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6InV1aWQiLCJuZXQiOiJ3cyJ9"
	got, err := Generate(base, []net.IP{net.ParseIP("104.18.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	encoded := strings.TrimPrefix(got[0], "vmess://")
	if len(encoded)%4 != 0 {
		t.Fatalf("vmess output should use padded standard base64, got %q", encoded)
	}
}

func TestGenerateInvalid(t *testing.T) {
	if _, err := Generate("http://example.com", []net.IP{net.ParseIP("1.1.1.1")}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := Generate("vless://uuid", []net.IP{net.ParseIP("1.1.1.1")}); err == nil {
		t.Fatal("expected missing host error")
	}
}
