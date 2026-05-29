package configgen

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var ErrUnsupportedScheme = errors.New("unsupported config scheme")

// Generate returns one share URL per IP with only the server/address replaced.
func Generate(base string, ips []net.IP) ([]string, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		return nil, fmt.Errorf("empty config")
	}
	if strings.HasPrefix(strings.ToLower(base), "vmess://") {
		return generateVMess(base, ips)
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "vless" && scheme != "trojan" {
		return nil, ErrUnsupportedScheme
	}
	if u.Host == "" || u.User == nil {
		return nil, fmt.Errorf("missing user or server address")
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		copy := *u
		copy.Host = replaceHostPreservePort(u, ip.String())
		out = append(out, copy.String())
	}
	return out, nil
}

func replaceHostPreservePort(u *url.URL, host string) string {
	port := u.Port()
	if port == "" {
		return formatHost(host)
	}
	return net.JoinHostPort(host, port)
}

func formatHost(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

func generateVMess(base string, ips []net.IP) ([]string, error) {
	payload := strings.TrimSpace(strings.TrimPrefix(base, "vmess://"))
	decoded, err := decodeVmess(payload)
	if err != nil {
		return nil, fmt.Errorf("decode vmess: %w", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(decoded, &obj); err != nil {
		return nil, fmt.Errorf("parse vmess json: %w", err)
	}
	if _, ok := obj["add"]; !ok {
		if _, ok := obj["address"]; !ok {
			return nil, fmt.Errorf("missing vmess address")
		}
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		copy := make(map[string]any, len(obj))
		for k, v := range obj {
			copy[k] = v
		}
		if _, ok := copy["add"]; ok {
			copy["add"] = ip.String()
		} else {
			copy["address"] = ip.String()
		}
		b, err := json.Marshal(copy)
		if err != nil {
			return nil, err
		}
		out = append(out, "vmess://"+base64.RawStdEncoding.EncodeToString(b))
	}
	return out, nil
}

func decodeVmess(s string) ([]byte, error) {
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}
