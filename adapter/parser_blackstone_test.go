package adapter

import (
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseBlackstoneProxyFromYAMLMapping(t *testing.T) {
	mapping := map[string]any{
		"name":     "fixture-blackstone",
		"type":     "blackstone",
		"server":   "192.0.2.10",
		"port":     60002,
		"udp":      true,
		"cipher":   "aes-128-ctr",
		"node-id":  "fixture-node",
		"password": "fixture-token",
	}

	proxy, err := ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy returned error: %v", err)
	}
	if proxy.Type() != C.Blackstone {
		t.Fatalf("unexpected proxy type: %v", proxy.Type())
	}
	if proxy.Name() != "fixture-blackstone" {
		t.Fatalf("unexpected proxy name: %q", proxy.Name())
	}
	if !proxy.SupportUDP() {
		t.Fatal("blackstone proxy lost udp capability from YAML")
	}
}

func TestStandaloneXHTTPTypeRemainsUnsupported(t *testing.T) {
	_, err := ParseProxy(map[string]any{
		"name":     "legacy-name",
		"type":     "xhttp",
		"server":   "192.0.2.10",
		"port":     443,
		"node-id":  "fixture-node",
		"password": "fixture-token",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupport proxy type: xhttp") {
		t.Fatalf("standalone xhttp must not shadow standard VLESS XHTTP: %v", err)
	}
}
