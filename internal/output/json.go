package output

import (
	"encoding/json"
	"io"

	"github.com/vulnverified/sweep/internal/engine"
)

// WriteJSON writes the scan result as indented JSON to w.
func WriteJSON(w io.Writer, result *engine.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
