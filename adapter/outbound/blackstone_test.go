package outbound

import (
	"encoding/base64"
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
