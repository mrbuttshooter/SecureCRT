package credentials

import "os"

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path) // #nosec G304 -- test-controlled path
}
