package xraytest

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// VLESSConfig holds parsed parameters from a VLESS share URL.
type VLESSConfig struct {
	UUID       string
	Address    string
	Port       int
	Encryption string
	Flow       string

	// Transport
	Network     string // ws, grpc, xhttp, tcp
	Path        string
	Host        string
	ServiceName string // gRPC
	Mode        string // gRPC multi/gun, xhttp auto
	Authority   string // gRPC

	// TLS
	Security    string // tls, reality, none
	SNI         string
	Fingerprint string
	ALPN        []string
	Insecure    bool

	// Metadata
	Remark string
}

// ParseVLESS parses a vless:// share URL into a VLESSConfig.
func ParseVLESS(raw string) (*VLESSConfig, error) {
	if !strings.HasPrefix(raw, "vless://") {
		return nil, fmt.Errorf("not a vless:// URL")
	}

	// vless://UUID@address:port?params#remark
	// URL parse doesn't handle the UUID as userinfo well, so we do it manually
	raw = strings.TrimPrefix(raw, "vless://")

	// Split remark
	remark := ""
	if idx := strings.LastIndex(raw, "#"); idx != -1 {
		remark = raw[idx+1:]
		raw = raw[:idx]
	}
	remark, _ = url.QueryUnescape(remark)

	// Split params
	params := url.Values{}
	if idx := strings.Index(raw, "?"); idx != -1 {
		var err error
		params, err = url.ParseQuery(raw[idx+1:])
		if err != nil {
			return nil, fmt.Errorf("parsing query params: %w", err)
		}
		raw = raw[:idx]
	}

	// Split UUID@address:port
	atIdx := strings.Index(raw, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("missing @ in URL")
	}
	uuid := raw[:atIdx]
	hostPort := raw[atIdx+1:]

	// Parse host:port
	host, portStr, err := splitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("parsing host:port %q: %w", hostPort, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}

	cfg := &VLESSConfig{
		UUID:        uuid,
		Address:     host,
		Port:        port,
		Encryption:  paramOr(params, "encryption", "none"),
		Flow:        params.Get("flow"),
		Network:     paramOr(params, "type", "tcp"),
		Security:    paramOr(params, "security", "none"),
		SNI:         params.Get("sni"),
		Fingerprint: paramOr(params, "fp", ""),
		Insecure:    params.Get("insecure") == "1" || params.Get("allowInsecure") == "1",
		Remark:      remark,
	}

	// Transport-specific
	switch cfg.Network {
	case "ws":
		cfg.Path = paramOr(params, "path", "/")
		cfg.Host = paramOr(params, "host", cfg.SNI)
	case "grpc":
		cfg.ServiceName = params.Get("serviceName")
		cfg.Authority = params.Get("authority")
		cfg.Mode = paramOr(params, "mode", "gun")
	case "xhttp", "splithttp":
		cfg.Path = paramOr(params, "path", "/")
		cfg.Host = paramOr(params, "host", cfg.SNI)
		cfg.Mode = paramOr(params, "mode", "auto")
	}

	// ALPN
	if alpnStr := params.Get("alpn"); alpnStr != "" {
		cfg.ALPN = strings.Split(alpnStr, ",")
	}

	return cfg, nil
}

// WithAddress returns a copy of the config with the address replaced.
// Port is preserved. This is used to swap in a candidate CF IP.
func (c *VLESSConfig) WithAddress(newAddr string) *VLESSConfig {
	copy := *c
	copy.Address = newAddr
	return &copy
}

// ToShareURL reconstructs a vless:// share URL from the config.
func (c *VLESSConfig) ToShareURL() string {
	params := url.Values{}
	params.Set("encryption", c.Encryption)
	params.Set("security", c.Security)
	params.Set("type", c.Network)

	if c.SNI != "" {
		params.Set("sni", c.SNI)
	}
	if c.Fingerprint != "" {
		params.Set("fp", c.Fingerprint)
	}
	if c.Insecure {
		params.Set("allowInsecure", "1")
	}
	if len(c.ALPN) > 0 {
		params.Set("alpn", strings.Join(c.ALPN, ","))
	}

	switch c.Network {
	case "ws":
		params.Set("path", c.Path)
		if c.Host != "" {
			params.Set("host", c.Host)
		}
	case "grpc":
		params.Set("serviceName", c.ServiceName)
		if c.Authority != "" {
			params.Set("authority", c.Authority)
		}
		if c.Mode != "" {
			params.Set("mode", c.Mode)
		}
	case "xhttp", "splithttp":
		params.Set("path", c.Path)
		if c.Host != "" {
			params.Set("host", c.Host)
		}
		if c.Mode != "" {
			params.Set("mode", c.Mode)
		}
	}

	remark := url.QueryEscape(c.Remark)
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", c.UUID, c.Address, c.Port, params.Encode(), remark)
}

func splitHostPort(hostPort string) (string, string, error) {
	// Handle IPv6 [addr]:port
	if strings.HasPrefix(hostPort, "[") {
		end := strings.Index(hostPort, "]")
		if end == -1 {
			return "", "", fmt.Errorf("missing ] in IPv6 address")
		}
		host := hostPort[1:end]
		if end+1 >= len(hostPort) || hostPort[end+1] != ':' {
			return "", "", fmt.Errorf("missing port after IPv6 address")
		}
		return host, hostPort[end+2:], nil
	}

	// Regular host:port
	lastColon := strings.LastIndex(hostPort, ":")
	if lastColon == -1 {
		return "", "", fmt.Errorf("missing port")
	}
	return hostPort[:lastColon], hostPort[lastColon+1:], nil
}

func paramOr(params url.Values, key, fallback string) string {
	v := params.Get(key)
	if v == "" {
		return fallback
	}
	return v
}

// TrojanConfig holds parsed parameters from a trojan:// share URL.
type TrojanConfig struct {
	Password string
	Address  string
	Port     int

	Network     string
	Path        string
	Host        string
	ServiceName string
	Mode        string
	Authority   string

	Security    string
	SNI         string
	Fingerprint string
	ALPN        []string
	Insecure    bool
	Remark      string
}

// ParseTrojan parses a trojan:// share URL into a TrojanConfig.
func ParseTrojan(raw string) (*TrojanConfig, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse trojan URL: %w", err)
	}
	if strings.ToLower(u.Scheme) != "trojan" {
		return nil, fmt.Errorf("not a trojan:// URL")
	}
	if u.User == nil || u.Host == "" {
		return nil, fmt.Errorf("missing password or server address")
	}
	password, _ := u.User.Password()
	if password == "" {
		password = u.User.Username()
	}
	if password == "" {
		return nil, fmt.Errorf("missing password")
	}
	host := u.Hostname()
	portStr := u.Port()
	if host == "" || portStr == "" {
		return nil, fmt.Errorf("missing host or port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	params := u.Query()
	cfg := &TrojanConfig{
		Password:    password,
		Address:     host,
		Port:        port,
		Network:     paramOr(params, "type", "tcp"),
		Security:    paramOr(params, "security", "tls"),
		SNI:         params.Get("sni"),
		Fingerprint: params.Get("fp"),
		Insecure:    params.Get("insecure") == "1" || params.Get("allowInsecure") == "1",
		Remark:      u.Fragment,
	}
	if cfg.SNI == "" {
		cfg.SNI = params.Get("peer")
	}
	switch cfg.Network {
	case "ws":
		cfg.Path = paramOr(params, "path", "/")
		cfg.Host = paramOr(params, "host", cfg.SNI)
	case "grpc":
		cfg.ServiceName = params.Get("serviceName")
		cfg.Authority = params.Get("authority")
		cfg.Mode = paramOr(params, "mode", "gun")
	}
	if alpnStr := params.Get("alpn"); alpnStr != "" {
		cfg.ALPN = strings.Split(alpnStr, ",")
	}
	return cfg, nil
}
