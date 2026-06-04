package ipsrc

import "net"

// Default neighbor-scan limits for Phase 1 random scans. A healthy IPv4 seed
// may expand its entire /24, but the global cap prevents unbounded scan growth.
const (
	DefaultNeighborRadius    = 32 // retained for compatibility with smaller outward searches
	DefaultNeighborSeedLimit = 5
	DefaultNeighborPerHit    = 64
	DefaultNeighborMaxTotal  = 1000
)

// NeighborsIn24 returns up to limit usable addresses in the IPv4 seed's /24.
// The network (.0) and broadcast (.255) addresses are never returned. When
// nets is non-empty, candidates must also belong to one of those networks.
func NeighborsIn24(ip net.IP, nets []*net.IPNet, limit int) []net.IP {
	ip4 := ip.To4()
	if ip4 == nil || limit <= 0 {
		return nil
	}
	if limit > 254 {
		limit = 254
	}
	out := make([]net.IP, 0, limit)
	for host := 1; host <= 254 && len(out) < limit; host++ {
		candidate := net.IPv4(ip4[0], ip4[1], ip4[2], byte(host))
		if len(nets) > 0 && !containsAnyNet(nets, candidate) {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

// NeighborsAround is retained for callers that want a smaller outward search.
func NeighborsAround(ip net.IP, nets []*net.IPNet, radius, limit int) []net.IP {
	if radius <= 0 || limit <= 0 {
		return nil
	}
	all := NeighborsIn24(ip, nets, 254)
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	out := make([]net.IP, 0, limit)
	for delta := 1; delta <= radius && len(out) < limit; delta++ {
		for _, host := range []int{int(ip4[3]) + delta, int(ip4[3]) - delta} {
			if host < 1 || host > 254 {
				continue
			}
			for _, candidate := range all {
				if int(candidate.To4()[3]) == host {
					out = append(out, candidate)
					break
				}
			}
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

func containsAnyNet(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
