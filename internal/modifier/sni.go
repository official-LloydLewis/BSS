package modifier

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func generateSNISpoof(configs []string, input string) (string, error) {
	address, port, err := parseSpoofEndpoint(input)
	if err != nil {
		return "", err
	}

	output := make([]string, 0, len(configs))
	for _, config := range configs {
		modified, err := replaceEndpoint(config, address, port)
		if err != nil {
			return "", err
		}
		output = append(output, modified)
	}
	return finishOutput(output)
}

func parseSpoofEndpoint(input string) (string, string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", fmt.Errorf("please enter both spoof IP and port")
	}

	address, port, err := net.SplitHostPort(input)
	if err != nil {
		fields := strings.Fields(input)
		if len(fields) == 2 {
			address, port = fields[0], fields[1]
		} else {
			return "", "", fmt.Errorf("enter spoof endpoint as IP:port")
		}
	}
	if strings.TrimSpace(address) == "" {
		return "", "", fmt.Errorf("please enter both spoof IP and port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", fmt.Errorf("invalid spoof port")
	}
	return address, port, nil
}
