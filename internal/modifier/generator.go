package modifier

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

const DefaultOutputLimit = 5000

var ipCandidateRE = regexp.MustCompile(`[0-9A-Fa-f:.]+`)

func generateFromRanges(configs []string, input string, limit int) (string, error) {
	ranges, err := parseRanges(input)
	if err != nil {
		return "", err
	}
	if limit <= 0 {
		limit = DefaultOutputLimit
	}

	var output []string
	for _, config := range configs {
		for _, prefix := range ranges {
			for address := prefix.Masked().Addr(); prefix.Contains(address) && len(output) < limit; address = address.Next() {
				modified, err := replaceEndpoint(config, address.String(), "")
				if err != nil {
					return "", err
				}
				output = append(output, modified)
			}
			if len(output) >= limit {
				break
			}
		}
		if len(output) >= limit {
			break
		}
	}
	return finishOutput(output)
}

func generateFromIPList(configs []string, input string) (string, error) {
	addresses := parseIPList(input)
	if len(addresses) == 0 {
		return "", fmt.Errorf("no valid IPs found in the input")
	}
	return generateForAddresses(configs, addresses)
}

func generateFromConfigsList(configs []string, input string) (string, error) {
	var addresses []string
	for _, target := range strings.Split(input, "\n") {
		address, err := extractAddress(strings.TrimSpace(target))
		if err == nil {
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("no valid config addresses found in the input")
	}
	return generateForAddresses(configs, addresses)
}

func generateForAddresses(configs, addresses []string) (string, error) {
	var output []string
	for _, config := range configs {
		for _, address := range addresses {
			modified, err := replaceEndpoint(config, address, "")
			if err != nil {
				return "", err
			}
			output = append(output, modified)
		}
	}
	return finishOutput(output)
}

func parseRanges(input string) ([]netip.Prefix, error) {
	var ranges []netip.Prefix
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("invalid IP range: %s", line)
		}
		ranges = append(ranges, prefix)
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("please enter at least one IP range")
	}
	return ranges, nil
}

func parseIPList(input string) []string {
	seen := make(map[netip.Addr]bool)
	var addresses []string
	for _, candidate := range ipCandidateRE.FindAllString(input, -1) {
		address, err := netip.ParseAddr(candidate)
		if err != nil || seen[address] {
			continue
		}
		seen[address] = true
		addresses = append(addresses, address.String())
	}
	return addresses
}

func finishOutput(configs []string) (string, error) {
	if len(configs) == 0 {
		return "", fmt.Errorf("no configs were generated")
	}
	return strings.Join(configs, "\n"), nil
}
