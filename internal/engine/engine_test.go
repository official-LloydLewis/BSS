package engine

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/prober"
	"github.com/matinsenpai/senpaiscanner/internal/result"
)

func TestRunCancellationWhileSemaphoreWouldBlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng := New(Config{Concurrency: 1, ProbeConfig: prober.Config{Port: 1, Mode: prober.ModeTCP, Tries: 1, Timeout: 200 * time.Millisecond}})
	ips := make(chan net.IP)
	done := make(chan struct{})
	go func() {
		eng.Run(ctx, ips, func(*result.Result) {})
		close(done)
	}()
	ips <- net.ParseIP("203.0.113.1")
	ips <- net.ParseIP("203.0.113.2")
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}
