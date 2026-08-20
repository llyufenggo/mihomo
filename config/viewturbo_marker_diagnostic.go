package config

import "strings"

func viewTurboMarkerSummary(proxies []map[string]any) (recognized int, shadowsocks int) {
	for _, mapping := range proxies {
		proxyType, _ := mapping["type"].(string)
		if !strings.EqualFold(strings.TrimSpace(proxyType), "ss") {
			continue
		}
		shadowsocks++
		password, _ := mapping["password"].(string)
		if strings.HasSuffix(strings.ToUpper(strings.TrimSpace(password)), "#VT") {
			recognized++
		}
	}
	return recognized, shadowsocks
}
