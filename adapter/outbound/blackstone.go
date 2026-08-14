package outbound

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/crypto/chacha20poly1305"
	"gopkg.in/yaml.v3"
)

var (
	blackstonePrivKey = []byte("NiKNssxJcXp7Mh4yjjFGdrcFoC66wcVu5j1LgBevGCm8utV4qg089xdb20tAKu")
	blackstonePubKey  = []byte("jMJaXZXGc1CbTri1UnRdvJ3izp8f0jGhXGr2jjr9nMkBKUZDoh3Avoijc4jQUw")
)

type blackstoneRealConfig struct {
	Name     string
	Type     string
	Server   string
	Port     string
	Password string
	Cipher   string
	TcpFake  string
}

type BlackstoneOption struct {
	BasicOption
	Name     string `proxy:"name"`
	Server   string `proxy:"server"`
	Port     int    `proxy:"port"`
	Password string `proxy:"password"`
	NodeID   string `proxy:"node-id"`
}

type Blackstone struct {
	*Base
	option     *BlackstoneOption
	initMu     sync.Mutex
	isInit     bool
	initErr    error
	bestCfg    blackstoneRealConfig
	lastFetch  time.Time
	ssOutbound C.ProxyAdapter
}

// ========================
// 🛡️ 测速拦截器：极致极简！只拨号原生 YAML IP！
// ========================
type BlackstoneProxyWrapper struct {
	C.Proxy
	adapter *Blackstone
}

func (x *BlackstoneProxyWrapper) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	start := time.Now()

	// 直接拨号 YAML 文件里存在的 x.adapter.addr
	conn, err := x.adapter.dialer.DialContext(ctx, "tcp", x.adapter.addr)
	if err != nil {
		return 0, err
	}
	conn.Close() 

	return uint16(time.Since(start).Milliseconds()), nil
}

func NewBlackstoneProxyWrapper(baseProxy C.Proxy, adapter *Blackstone) C.Proxy {
	return &BlackstoneProxyWrapper{Proxy: baseProxy, adapter: adapter}
}

func NewBlackstone(option BlackstoneOption) (*Blackstone, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Blackstone{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Blackstone,
			ProviderName: option.ProviderName,
			UDP:          true,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

// ========================
// 🚀 按需加载核心：只在真实连接网页时触发
// ========================

func (h *Blackstone) pingRace(ctx context.Context, configs []blackstoneRealConfig) (blackstoneRealConfig, error) {
	if len(configs) == 1 {
		return configs[0], nil
	}
	type raceResult struct {
		cfg blackstoneRealConfig
		err error
	}
	resCh := make(chan raceResult, len(configs))
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for _, cfg := range configs {
		wg.Add(1)
		go func(c blackstoneRealConfig) {
			defer wg.Done()
			addr := net.JoinHostPort(c.Server, c.Port)
			dialCtx, dialCancel := context.WithTimeout(raceCtx, 3*time.Second)
			defer dialCancel()
			
			conn, err := h.dialer.DialContext(dialCtx, "tcp", addr)
			if err == nil {
				conn.Close()
				cancel()
			}
			resCh <- raceResult{cfg: c, err: err}
		}(cfg)
	}

	go func() { wg.Wait(); close(resCh) }()

	var firstErr error
	for res := range resCh {
		if res.err == nil {
			return res.cfg, nil
		}
		if firstErr == nil {
			firstErr = res.err
		}
	}
	return blackstoneRealConfig{}, fmt.Errorf("all dynamic nodes failed tcp ping: %v", firstErr)
}

func (h *Blackstone) lazyInit(ctx context.Context) error {
	h.initMu.Lock()
	defer h.initMu.Unlock()

	if h.isInit {
		if time.Since(h.lastFetch) < 1*time.Hour {
			return h.initErr
		}
		h.isInit = false 
	}

	apiCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	allConfigs, err := h.fetchDynamicConfig(apiCtx, h.option.NodeID, h.option.Password)
	if err != nil {
		h.initErr = err
		return err
	}

	var matchedConfigs []blackstoneRealConfig
	isSingleNode := len(allConfigs) == 1

	for _, cfg := range allConfigs {
		if !isSingleNode && h.option.Name != "" {
			cleanNodeName := strings.ReplaceAll(h.option.Name, "#", " ")
			cleanNodeName = strings.ReplaceAll(cleanNodeName, "-", " ")
			cleanNodeName = strings.ReplaceAll(cleanNodeName, "|", " ")
			keywords := strings.Fields(cleanNodeName)

			isMatch := true
			for _, kw := range keywords {
				if !strings.Contains(cfg.Name, kw) {
					isMatch = false
					break
				}
			}
			if !isMatch {
				continue
			}
		}
		matchedConfigs = append(matchedConfigs, cfg)
	}

	if len(matchedConfigs) == 0 {
		h.initErr = fmt.Errorf("no target node matched for name: %s", h.option.Name)
		return h.initErr
	}

	best, err := h.pingRace(apiCtx, matchedConfigs)
	if err != nil {
		h.initErr = err
		return err
	}

	h.bestCfg = best
	if best.Type == "ss" {
		portInt, err := strconv.Atoi(best.Port)
		if err != nil || portInt < 1 || portInt > 65535 {
			return fmt.Errorf("invalid dynamic Shadowsocks port %q", best.Port)
		}
		ssOpt := ShadowSocksOption{
			BasicOption: h.option.BasicOption, 
			Name:        h.option.Name + "_ss",
			Server:      best.Server,
			Port:        portInt,
			Password:    best.Password + "#BLACKSTONE",
			Cipher:      best.Cipher,
		}
		h.ssOutbound, h.initErr = NewShadowSocks(ssOpt)
		if h.initErr != nil {
			return h.initErr
		}
	}

	h.isInit = true
	h.initErr = nil
	h.lastFetch = time.Now()
	return nil
}

func (h *Blackstone) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := h.lazyInit(ctx); err != nil {
		return nil, err
	}

	if h.ssOutbound != nil {
		return h.ssOutbound.DialContext(ctx, metadata)
	}

	addr := net.JoinHostPort(h.bestCfg.Server, h.bestCfg.Port)
	rawConn, err := h.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	passParts := strings.Split(h.bestCfg.Password, ":")
	if len(passParts) != 2 {
		rawConn.Close()
		return nil, errors.New("invalid blackstone password format")
	}
	part1Str := strings.TrimSpace(passParts[0])
	part2Hex := passParts[1]
	decodedHmacKey, err := hex.DecodeString(part2Hex)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("invalid blackstone HMAC key: %w", err)
	}
	if len(decodedHmacKey) == 0 {
		rawConn.Close()
		return nil, errors.New("invalid blackstone HMAC key: empty key")
	}
	hmacLen := len(decodedHmacKey)
	handshakeLen := 128 + 16 + hmacLen + 1 + 16
	ivLenOffset := 144 + hmacLen

	clientHandshake := make([]byte, handshakeLen)
	decodedTcp, err := hex.DecodeString(h.bestCfg.TcpFake)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("invalid blackstone fake TCP header: %w", err)
	}
	
	copyLen := len(decodedTcp)
	if copyLen > 128 {
		copyLen = 128
	}
	copy(clientHandshake[0:copyLen], decodedTcp[:copyLen])
	if copyLen < 128 {
		if _, err := rand.Read(clientHandshake[copyLen:128]); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("generate blackstone handshake padding: %w", err)
		}
	}
	
	tokenMD5 := md5.Sum([]byte(part1Str + "do not hack this protocol please"))
	copy(clientHandshake[128:144], tokenMD5[:])
	copy(clientHandshake[144:144+hmacLen], decodedHmacKey)

	clientHandshake[ivLenOffset] = 0x10
	clientWriteIV := clientHandshake[ivLenOffset+1 : handshakeLen]
	if _, err := rand.Read(clientWriteIV); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("generate blackstone IV: %w", err)
	}

	aesKey := md5.Sum([]byte(part1Str))
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("create blackstone cipher: %w", err)
	}
	encryptStream := cipher.NewCTR(block, clientWriteIV)

	var destBuf bytes.Buffer
	switch metadata.AddrType() {
	case C.AtypDomainName:
		destBuf.WriteByte(0x03)
		destBuf.WriteByte(byte(len(metadata.RuleHost())))
		destBuf.WriteString(metadata.RuleHost())
	case C.AtypIPv4:
		destBuf.WriteByte(0x01)
		destBuf.Write(metadata.DstIP.AsSlice())
	default:
		destBuf.WriteByte(0x04)
		destBuf.Write(metadata.DstIP.AsSlice())
	}
	binary.Write(&destBuf, binary.BigEndian, metadata.DstPort)

	addrPayload := destBuf.Bytes()
	encryptedAddr := make([]byte, len(addrPayload))
	encryptStream.XORKeyStream(encryptedAddr, addrPayload)

	firstPayload := append(clientHandshake, encryptedAddr...)
	
	rawConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := rawConn.Write(firstPayload); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("write payload failed: %v", err)
	}
	rawConn.SetWriteDeadline(time.Time{})

	xconn := &BlackstoneConn{
		Conn:          rawConn,
		encryptStream: encryptStream,
		block:         block,
		ivLenOffset:   ivLenOffset,
		handshakeDone: false,
	}

	return NewConn(xconn, h), nil
}

func (h *Blackstone) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := h.lazyInit(ctx); err != nil {
		return nil, err
	}
	if h.ssOutbound != nil {
		return h.ssOutbound.ListenPacketContext(ctx, metadata)
	}
	return nil, C.ErrNotSupport
}

func (h *Blackstone) SupportUOT() bool { return false }
func (h *Blackstone) Close() error     { return nil }


// ========================
// 延迟读取防死锁
// ========================
type BlackstoneConn struct {
	net.Conn
	encryptStream cipher.Stream
	decryptStream cipher.Stream
	block         cipher.Block
	ivLenOffset   int
	handshakeDone bool
	readMu        sync.Mutex
}

func (c *BlackstoneConn) Write(b []byte) (n int, err error) {
	buf := make([]byte, len(b))
	c.encryptStream.XORKeyStream(buf, b)
	return c.Conn.Write(buf)
}

func (c *BlackstoneConn) Read(b []byte) (n int, err error) {
	c.readMu.Lock()
	if !c.handshakeDone {
		c.Conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		baseHeader := make([]byte, c.ivLenOffset)
		if _, err := io.ReadFull(c.Conn, baseHeader); err != nil {
			c.readMu.Unlock()
			return 0, err
		}

		markerBuf := make([]byte, 1)
		var shift int
		for {
			if _, err := io.ReadFull(c.Conn, markerBuf); err != nil {
				c.readMu.Unlock()
				return 0, err
			}
			if markerBuf[0] == 0x10 {
				break
			}
			shift++
			if shift > 10 {
				c.readMu.Unlock()
				return 0, errors.New("IV offset padding too large")
			}
		}

		serverReadIV := make([]byte, 16)
		if _, err := io.ReadFull(c.Conn, serverReadIV); err != nil {
			c.readMu.Unlock()
			return 0, err
		}
		c.Conn.SetReadDeadline(time.Time{})

		c.decryptStream = cipher.NewCTR(c.block, serverReadIV)
		c.handshakeDone = true
	}
	c.readMu.Unlock()

	n, err = c.Conn.Read(b)
	if n > 0 {
		c.decryptStream.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}


// ========================
// API 请求解析核心 (+ 修复 <nil> cipher BUG)
// ========================
func (h *Blackstone) fetchDynamicConfig(ctx context.Context, nodeID, token string) ([]blackstoneRealConfig, error) {
	cfNodeIP := "104.21.41.69"
	url := fmt.Sprintf("https://%s/api/v3/proxy/config", cfNodeIP)

	reqMap := map[string]interface{}{
		"fastest_ping":    map[string]interface{}{},
		"energy":          false,
		"id":              nodeID,
		"strategy":        "smart",
	}
	reqJson, err := json.Marshal(reqMap)
	if err != nil {
		return nil, fmt.Errorf("encode blackstone request: %w", err)
	}
	encryptedReq := h.encryptRequestData(string(reqJson))

	payloadMap := map[string]string{"data": encryptedReq}
	payloadJson, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("encode blackstone payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payloadJson))
	if err != nil {
		return nil, fmt.Errorf("create blackstone request: %w", err)
	}
	req.Host = "g.just4test.xyz"
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-version", "520")
	req.Header.Set("x-platform", "android")
	req.Header.Set("user-agent", "okhttp/4.9.2")
	req.Header.Set("x-header", h.buildXHeader(token))

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
				return h.dialer.DialContext(c, "tcp", addr)
			},
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: "g.just4test.xyz",
			},
			ForceAttemptHTTP2: true,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api request failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read blackstone API response: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("api returned status: %d", resp.StatusCode)
	}

	var jsonResp map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &jsonResp); err != nil {
		var encryptedB64 string
		encryptedB64 = strings.Trim(string(bodyBytes), "\"'\n\r\t ")
		return h.processApiData(encryptedB64)
	}

	encryptedData, ok := jsonResp["data"].(string)
	if !ok || encryptedData == "" {
		return nil, errors.New("API response data must be a non-empty string")
	}
	return h.processApiData(encryptedData)
}

func (h *Blackstone) processApiData(encryptedB64 string) ([]blackstoneRealConfig, error) {
	if pad := len(encryptedB64) % 4; pad != 0 {
		encryptedB64 += strings.Repeat("=", 4-pad)
	}

	rawB64, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return nil, err
	}
	for i := range rawB64 {
		rawB64[i] ^= blackstonePrivKey[i%len(blackstonePrivKey)]
	}
	if bytes.HasPrefix(rawB64, []byte("\x1f\x8b")) {
		gr, err := gzip.NewReader(bytes.NewReader(rawB64))
		if err != nil {
			return nil, fmt.Errorf("invalid outer gzip data: %w", err)
		}
		decompressed, readErr := io.ReadAll(gr)
		closeErr := gr.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read outer gzip data: %w", readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close outer gzip data: %w", closeErr)
		}
		rawB64 = decompressed
	}

	var layer1 map[string]interface{}
	if err := json.Unmarshal(rawB64, &layer1); err != nil {
		return nil, fmt.Errorf("invalid outer JSON: %w", err)
	}
	dataObj, ok := layer1["data"].(map[string]interface{})
	if !ok {
		return nil, errors.New("decrypted data field must be an object")
	}
	smartB64, ok := dataObj["smart"].(string)
	if !ok || smartB64 == "" {
		return nil, errors.New("decrypted smart field must be a non-empty string")
	}

	smartRaw, err := base64.StdEncoding.DecodeString(smartB64)
	if err != nil {
		return nil, fmt.Errorf("decode smart data: %w", err)
	}
	smartPlain, err := h.decryptBlackstonePayload(smartRaw)
	if err != nil {
		return nil, err
	}

	var smartData struct {
		Proxies []map[string]interface{} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(smartPlain, &smartData); err != nil {
		return nil, fmt.Errorf("decode smart YAML: %w", err)
	}

	var realConfigs []blackstoneRealConfig
	for _, proxy := range smartData.Proxies {
		pName, _ := proxy["name"].(string)
		pType, _ := proxy["type"].(string)

		if pType == "ss" || pType == "os" {
			cipherStr, _ := proxy["cipher"].(string)
			if cipherStr == "" || cipherStr == "<nil>" {
				if pType == "os" {
					cipherStr = "aes-128-ctr"
				} else {
					cipherStr = "2022-blake3-aes-128-gcm"
				}
			}

			cfg := blackstoneRealConfig{
				Name:     pName,
				Type:     "ss",
				Server:   fmt.Sprintf("%v", proxy["server"]),
				Port:     fmt.Sprintf("%v", proxy["port"]),
				Password: fmt.Sprintf("%v", proxy["password"]),
				Cipher:   cipherStr,
			}
			realConfigs = append(realConfigs, cfg)
		} else if pType == "xhttp" {
			certStr, _ := proxy["certificate"].(string)
			if certStr != "" {
				realCfg, err := h.crackCertificate(certStr)
				if err == nil {
					realCfg.Name = pName
					realConfigs = append(realConfigs, realCfg)
				}
			} else {
				cfg := blackstoneRealConfig{
					Name:     pName,
					Type:     "xhttp",
					Server:   fmt.Sprintf("%v", proxy["server"]),
					Port:     fmt.Sprintf("%v", proxy["port"]),
					Password: fmt.Sprintf("%v", proxy["password"]),
				}
				if fakeNet, ok := proxy["fake-net"].(map[string]interface{}); ok {
					cfg.TcpFake, _ = fakeNet["tcp"].(string)
				}
				realConfigs = append(realConfigs, cfg)
			}
		}
	}

	if len(realConfigs) == 0 {
		return nil, errors.New("api returned no valid nodes")
	}

	return realConfigs, nil
}

func (h *Blackstone) crackCertificate(certPem string) (blackstoneRealConfig, error) {
	re := regexp.MustCompile(`-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+`)
	b64Data := re.ReplaceAllString(certPem, "")
	if pad := len(b64Data) % 4; pad != 0 {
		b64Data += strings.Repeat("=", 4-pad)
	}

	raw, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return blackstoneRealConfig{}, err
	}

	offsets := []int{48, 52, 56, 64}
	for _, offset := range offsets {
		if offset >= len(raw) {
			continue
		}
		plain, err := h.decryptBlackstonePayload(raw[offset:])
		if err == nil {
			var innerData map[string]interface{}
			if json.Unmarshal(plain, &innerData) == nil {
				cfg := blackstoneRealConfig{
					Type:     "xhttp",
					Server:   fmt.Sprintf("%v", innerData["server"]),
					Port:     fmt.Sprintf("%v", innerData["port"]),
					Password: fmt.Sprintf("%v", innerData["password"]),
				}
				if fakeNet, ok := innerData["fake-net"].(map[string]interface{}); ok {
					cfg.TcpFake, _ = fakeNet["tcp"].(string)
				}
				return cfg, nil
			}
		}
	}
	return blackstoneRealConfig{}, errors.New("all asn.1 offsets failed")
}

func (h *Blackstone) buildXHeader(token string) string {
	headerMap := map[string]interface{}{
		"X-DEVICE-NAME":     "FlClash",
		"X-IDENTIFIER":      h.option.NodeID,
		"X-TOKEN":           token,
		"X-TIMESTAMP":       strconv.FormatInt(time.Now().Unix(), 10),
		"X-CHECK-MOBILE":    `{"isRoot":false,"isEmulator":false,"bundleID":"com.follow.clash.llyufeng"}`,
		"X-OS-VERSION":      "ios",
	}
	headerJson, _ := json.Marshal(headerMap)
	return h.encryptRequestData(string(headerJson))
}

func (h *Blackstone) encryptRequestData(dataStr string) string {
	rawBytes := []byte(dataStr)
	res := make([]byte, len(rawBytes))
	for i := 0; i < len(rawBytes); i++ {
		res[i] = rawBytes[i] ^ blackstonePubKey[i%len(blackstonePubKey)]
	}
	return base64.StdEncoding.EncodeToString(res)
}

func (h *Blackstone) decryptBlackstonePayload(rawData []byte) ([]byte, error) {
	if len(rawData) < 1 {
		return nil, errors.New("data too short")
	}
	chunkCount := int(rawData[0])
	headerSize := 1 + chunkCount*8
	if len(rawData) < headerSize {
		return nil, errors.New("header size error")
	}

	type offset struct{ start, end uint32 }
	table := make([]offset, chunkCount)
	for i := 0; i < chunkCount; i++ {
		ptr := 1 + i*8
		table[i].start = binary.BigEndian.Uint32(rawData[ptr : ptr+4])
		table[i].end = binary.BigEndian.Uint32(rawData[ptr+4 : ptr+8])
	}

	payload := rawData[headerSize:]
	isKey := make([]bool, len(payload))
	for _, off := range table {
		for i := off.start; i < off.end; i++ {
			if int(i) < len(isKey) {
				isKey[i] = true
			}
		}
	}

	var keySeedAscii, ciphertext []byte
	for i, b := range payload {
		if isKey[i] {
			keySeedAscii = append(keySeedAscii, b)
		} else {
			ciphertext = append(ciphertext, b)
		}
	}

	secretBytes, err := hex.DecodeString(string(keySeedAscii))
	if err != nil {
		secretBytes = keySeedAscii
	}

	derivedKey := h.vmessKDF(secretBytes, "CHACHA 20 POLY 1305")

	if len(ciphertext) < 12 {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:12]
	actualCt := ciphertext[12:]

	aead, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, actualCt, nil)
	if err != nil {
		return nil, err
	}

	if bytes.HasPrefix(plaintext, []byte("\x1f\x8b")) {
		gr, err := gzip.NewReader(bytes.NewReader(plaintext))
		if err == nil {
			defer gr.Close()
			uncompressed, _ := io.ReadAll(gr)
			return uncompressed, nil
		}
	}

	return plaintext, nil
}

func (h *Blackstone) vmessKDF(secret []byte, paths ...string) []byte {
	creator := func() hash.Hash { return hmac.New(sha256.New, []byte("VMess AEAD KDF")) }
	for _, path := range paths {
		c := creator
		pBytes := []byte(path)
		creator = func() hash.Hash { return hmac.New(c, pBytes) }
	}
	hashVal := creator()
	hashVal.Write(secret)
	return hashVal.Sum(nil)
}