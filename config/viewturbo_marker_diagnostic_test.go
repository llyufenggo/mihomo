package config

import "testing"

func TestViewTurboMarkerSummary(t *testing.T) {
	proxies := []map[string]any{
		{"type": "ss", "password": "#VT", "server": "must-not-be-logged"},
		{"type": "SS", "password": "secret#vt"},
		{"type": "ss", "password": "ordinary"},
		{"type": "vmess", "password": "#VT"},
	}
	recognized, shadowsocks := viewTurboMarkerSummary(proxies)
	if recognized != 2 || shadowsocks != 3 {
		t.Fatalf("summary = recognized:%d shadowsocks:%d", recognized, shadowsocks)
	}
}
