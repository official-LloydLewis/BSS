package modifier

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type configType int

const (
	unknownConfig configType = iota
	vmessConfig
	vlessConfig
	wireguardConfig
	trojanConfig
)

type vmessFields struct {
	Address string          `json:"add"`
	Port    json.RawMessage `json:"port,omitempty"`
}

// ParseConfigs returns valid supported share links from multiline input.
func ParseConfigs(input string) []string {
	var configs []string
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(line)
		if detectConfigType(line) != unknownConfig {
			configs = append(configs, line)
		}
	}
	return configs
}

func detectConfigType(config string) configType {
	switch {
	case strings.HasPrefix(config, "vmess://"):
		return vmessConfig
	case strings.HasPrefix(config, "vless://"):
		return vlessConfig
	case strings.HasPrefix(config, "wireguard://"):
		return wireguardConfig
	case strings.HasPrefix(config, "trojan://"):
		return trojanConfig
	default:
		return unknownConfig
	}
}

func extractAddress(config string) (string, error) {
	switch detectConfigType(config) {
	case vmessConfig:
		fields, err := decodeVMess(config)
		if err != nil || strings.TrimSpace(fields.Address) == "" {
			return "", fmt.Errorf("invalid vmess config")
		}
		return fields.Address, nil
	case vlessConfig, wireguardConfig, trojanConfig:
		u, err := url.Parse(config)
		if err != nil || u.Hostname() == "" || u.Port() == "" {
			return "", fmt.Errorf("invalid config endpoint")
		}
		return u.Hostname(), nil
	default:
		return "", fmt.Errorf("unsupported config")
	}
}

func replaceEndpoint(config, address, port string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", fmt.Errorf("empty address")
	}

	if detectConfigType(config) == vmessConfig {
		payload, err := decodeVMessMap(config)
		if err != nil {
			return "", err
		}
		payload["add"] = address
		if port != "" {
			portNumber, err := strconv.Atoi(port)
			if err != nil {
				return "", fmt.Errorf("invalid port %q", port)
			}
			payload["port"] = portNumber
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return "", fmt.Errorf("encode vmess config: %w", err)
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(encoded), nil
	}

	u, err := url.Parse(config)
	if err != nil || u.Hostname() == "" || u.Port() == "" {
		return "", fmt.Errorf("invalid config endpoint")
	}
	if port == "" {
		port = u.Port()
	}
	u.Host = net.JoinHostPort(address, port)
	return u.String(), nil
}

func decodeVMess(config string) (vmessFields, error) {
	var fields vmessFields
	data, err := decodeVMessBytes(config)
	if err != nil {
		return fields, err
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fields, fmt.Errorf("decode vmess JSON: %w", err)
	}
	return fields, nil
}

func decodeVMessMap(config string) (map[string]any, error) {
	data, err := decodeVMessBytes(config)
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("decode vmess JSON: %w", err)
	}
	return payload, nil
}

func decodeVMessBytes(config string) ([]byte, error) {
	raw := strings.TrimPrefix(config, "vmess://")
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(raw)
	}
	if err != nil {
		return nil, fmt.Errorf("decode vmess base64: %w", err)
	}
	return data, nil
}
