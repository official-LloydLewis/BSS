package output

import "testing"

func TestDetectFormatKnownExtensions(t *testing.T) {
	cases := map[string]Format{
		"out.csv":   FormatCSV,
		"out.json":  FormatJSON,
		"out.jsonl": FormatJSON,
		"out.txt":   FormatTXT,
	}
	for path, want := range cases {
		got, err := DetectFormat(path)
		if err != nil {
			t.Fatalf("DetectFormat(%q) unexpected error: %v", path, err)
		}
		if got != want {
			t.Fatalf("DetectFormat(%q)=%v want %v", path, got, want)
		}
	}
}

func TestDetectFormatRejectsUnknownExtension(t *testing.T) {
	if _, err := DetectFormat("out.unknown"); err == nil {
		t.Fatal("expected unknown extension error")
	}
}
