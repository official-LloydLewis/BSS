package modifier

import "os"

// Save writes generated configs to a text file.
func Save(path, output string) error {
	return os.WriteFile(path, []byte(output), 0644)
}
