package outbound

import "testing"

func TestParseVlessUUIDModeDetectsX365(t *testing.T) {
	cleaned, x365 := parseVlessUUIDMode("  00112233-4455-6677-8899-aabbccddeeff#x365  ")
	if cleaned != "00112233-4455-6677-8899-aabbccddeeff" || !x365 {
		t.Fatalf("cleaned=%q x365=%v", cleaned, x365)
	}
}

func TestParseVlessUUIDModeIsCaseInsensitive(t *testing.T) {
	cleaned, x365 := parseVlessUUIDMode("00112233-4455-6677-8899-aabbccddeeff#X365")
	if cleaned != "00112233-4455-6677-8899-aabbccddeeff" || !x365 {
		t.Fatalf("cleaned=%q x365=%v", cleaned, x365)
	}
}

func TestParseVlessUUIDModeLeavesStandardUUIDUnchanged(t *testing.T) {
	const uuid = "00112233-4455-6677-8899-aabbccddeeff"
	cleaned, x365 := parseVlessUUIDMode(uuid)
	if cleaned != uuid || x365 {
		t.Fatalf("cleaned=%q x365=%v", cleaned, x365)
	}
}
