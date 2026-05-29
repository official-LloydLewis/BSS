package xraytest

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sync/atomic"
	"time"
)

var portCounter atomic.Int32

func init() { portCounter.Store(20000) }

func nextPort() int { return int(portCounter.Add(1)) }

// ValidationResult holds the outcome of testing a VLESS config through xray.
type ValidationResult struct {
	IP         string
	Port       int
	Success    bool
	Latency    time.Duration
	Throughput float64
	BytesRecv  int64
	Error      string
	Transport  string
	Retries    int
}

// XrayAvailable reports whether an external xray binary is available.
func XrayAvailable() bool {
	_, err := exec.LookPath("xray")
	return err == nil
}

// ValidateConfig starts an external xray process with the given config, sends
// test traffic through it, and returns the result. Retries once on failure.
func ValidateConfig(ctx context.Context, cfg *VLESSConfig, timeout time.Duration) *ValidationResult {
	res := validateOnce(ctx, cfg, timeout)
	if !res.Success && XrayAvailable() {
		time.Sleep(500 * time.Millisecond)
		res2 := validateOnce(ctx, cfg, timeout)
		res2.Retries = 1
		if res2.Success {
			return res2
		}
		res.Retries = 1
	}
	return res
}

func validateOnce(ctx context.Context, cfg *VLESSConfig, timeout time.Duration) *ValidationResult {
	result := &ValidationResult{IP: cfg.Address, Port: cfg.Port, Transport: cfg.Network}
	path, err := exec.LookPath("xray")
	if err != nil {
		result.Error = "xray binary not found; validation skipped"
		return result
	}

	socksPort := nextPort()
	configJSON, err := BuildXrayConfig(cfg, socksPort)
	if err != nil {
		result.Error = fmt.Sprintf("build config: %v", err)
		return result
	}
	tmpFile, err := os.CreateTemp("", "xray-test-*.json")
	if err != nil {
		result.Error = fmt.Sprintf("create temp file: %v", err)
		return result
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write(configJSON); err != nil {
		tmpFile.Close()
		result.Error = fmt.Sprintf("write config: %v", err)
		return result
	}
	_ = tmpFile.Close()

	procCtx, cancelProc := context.WithCancel(ctx)
	defer cancelProc()
	cmd := exec.CommandContext(procCtx, path, "run", "-config", tmpFile.Name())
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Sprintf("start xray: %v", err)
		return result
	}
	defer func() {
		cancelProc()
		_ = cmd.Wait()
	}()

	if !waitForPort(socksPort, 3*time.Second) {
		result.Error = "socks port not ready after 3s"
		return result
	}

	proxyURL := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)
	testCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	bytesRecv, err := downloadThroughProxy(testCtx, proxyURL, 1024*1024)
	elapsed := time.Since(start)
	if err != nil {
		result.Error = fmt.Sprintf("download: %v", err)
		result.Latency = elapsed
		return result
	}
	result.Success = true
	result.Latency = elapsed
	result.BytesRecv = bytesRecv
	if elapsed.Seconds() > 0 {
		result.Throughput = float64(bytesRecv) / elapsed.Seconds()
	}
	return result
}

func downloadThroughProxy(ctx context.Context, proxyAddr string, bytes int64) (int64, error) {
	transport := &http.Transport{
		Proxy:               func(req *http.Request) (*url.URL, error) { return url.Parse(proxyAddr) },
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	u := fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", bytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return n, err
	}
	return n, nil
}

func waitForPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
