package modifier

import "fmt"

// InputType selects how endpoint addresses are supplied to Generate.
type InputType int

const (
	IPRanges InputType = iota
	IPList
	ConfigsList
	SNISpoof
)

// String returns the user-facing name of an input type.
func (t InputType) String() string {
	switch t {
	case IPRanges:
		return "IP Ranges"
	case IPList:
		return "IP List"
	case ConfigsList:
		return "Configs List"
	case SNISpoof:
		return "SNI Spoof"
	default:
		return "Unknown"
	}
}

// Options contains the inputs used to generate modified configs.
type Options struct {
	Configs     string
	Type        InputType
	InputData   string
	OutputLimit int
}

// Generate applies the selected transformation and returns one config per line.
func Generate(opts Options) (string, error) {
	configs := ParseConfigs(opts.Configs)
	if len(configs) == 0 {
		return "", fmt.Errorf("no valid base configs found")
	}

	switch opts.Type {
	case IPRanges:
		return generateFromRanges(configs, opts.InputData, opts.OutputLimit)
	case IPList:
		return generateFromIPList(configs, opts.InputData)
	case ConfigsList:
		return generateFromConfigsList(configs, opts.InputData)
	case SNISpoof:
		return generateSNISpoof(configs, opts.InputData)
	default:
		return "", fmt.Errorf("unknown input type")
	}
}
