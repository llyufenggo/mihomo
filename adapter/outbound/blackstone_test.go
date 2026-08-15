package outbound

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func encodeBlackstoneOuterFixture(plaintext string) string {
	raw := []byte(plaintext)
	for index := range raw {
		raw[index] ^= blackstonePrivKey[index%len(blackstonePrivKey)]
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func requireBlackstoneErrorWithoutPanic(t *testing.T, action func() error, message string) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s panicked: %v", message, recovered)
		}
	}()
	if err := action(); err == nil {
		t.Fatalf("%s returned no error", message)
	}
}

func TestProcessAPIDataRejectsNonObjectDataWithoutPanic(t *testing.T) {
	handler := &Blackstone{}
	fixture := encodeBlackstoneOuterFixture(`{"data":"not-an-object"}`)
	requireBlackstoneErrorWithoutPanic(t, func() error {
		_, err := handler.processApiData(fixture)
		return err
	}, "non-object data")
}

func TestProcessAPIDataRejectsMissingSmartWithoutPanic(t *testing.T) {
	handler := &Blackstone{}
	fixture := encodeBlackstoneOuterFixture(`{"data":{}}`)
	requireBlackstoneErrorWithoutPanic(t, func() error {
		_, err := handler.processApiData(fixture)
		return err
	}, "missing smart")
}

func TestProcessAPIDataRejectsInvalidOuterJSON(t *testing.T) {
	handler := &Blackstone{}
	fixture := encodeBlackstoneOuterFixture(`not-json`)
	_, err := handler.processApiData(fixture)
	if err == nil || !strings.Contains(err.Error(), "outer JSON") {
		t.Fatalf("unexpected invalid JSON error: %v", err)
	}
}

func decodeBlackstoneHeaderFixture(t *testing.T, encoded string) map[string]any {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	for index := range raw {
		raw[index] ^= blackstonePubKey[index%len(blackstonePubKey)]
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("decode header JSON: %v", err)
	}
	return header
}

func TestBlackstoneHeaderPreservesLegacyServiceIdentity(t *testing.T) {
	handler := &Blackstone{option: &BlackstoneOption{NodeID: "must-not-leak"}}
	header := decodeBlackstoneHeaderFixture(t, handler.buildXHeader("fixture-token"))
	expected := map[string]string{
		"X-DEVICE-NAME":  "Lenovo - Lenovo TB-J606F",
		"X-IDENTIFIER":   "ed7295e154b50905",
		"X-TIMESTAMP":    "1779367490",
		"X-CHECK-MOBILE": `{"isRoot":true,"isEmulator":false,"bundleID":"com.heysocks.android"}`,
		"X-OS-VERSION":   "30",
		"X-TOKEN":        "fixture-token",
	}
	for key, value := range expected {
		if header[key] != value {
			t.Fatalf("legacy header %s changed: got=%v want=%q", key, header[key], value)
		}
	}
}

func TestBlackstoneTLSConfigPreservesPinnedIPCompatibility(t *testing.T) {
	config := blackstoneTLSConfig()
	if config.ServerName != "g.just4test.xyz" {
		t.Fatalf("unexpected Blackstone SNI: %q", config.ServerName)
	}
	if !config.InsecureSkipVerify {
		t.Fatal("pinned-IP Blackstone API must preserve legacy certificate handling")
	}
}
