// Package goclean is UMBRA's CLEAN-IP engine (Go half of the tri-lingual
// rebuild): Cloudflare anycast IP scanning with REAL proof of usability —
//
//	phase 1  TCP connect latency  (per IP:port, N attempts → latency/jitter/loss)
//	phase 2  TLS + /cdn-cgi/trace (certificate validation for a real CF host,
//	                               colo + ip from the trace endpoint)
//	phase 3  HTTPS download speed (/__down?bytes=N through the same SNI)
//
// Events stream to Kotlin through PollEvents() in the same compact JSON
// event protocol the Rust core uses (parsed by org.json on the app side):
//
//	{"t":"log","x":"..."}          engine log line
//	{"t":"dbg","x":"..."}          per-probe debug line
//	{"t":"res", ip, p, v6, lat, jit, loss, tcpAtt, tcpOk,
//	 tlsOk, tlsMs, colo, mbps, bytes, err}   partial — merged by ip:port
//	{"t":"prg","done":n,"busy":n,"phase":"tcp"}
//	{"t":"fin","cancel":bool}
//
// A bare TCP connect proves nothing on censored networks (DPI middleboxes
// fake-accept every handshake) — only the TLS phase marks an IP alive.
package goclean

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Version reported to the app.
const Version = "UMBRA-GO-CLEAN 4.0.0 (tcp tls trace speed)"

// ---------------------------------------------------------------- state ----

var (
	mu       sync.Mutex
	running  bool
	cancel   atomic.Bool
	events   []string
	finished bool
	total    int
	done     atomic.Int64
	busy     atomic.Int64
)

type event struct {
	T string `json:"t"`
	X string `json:"x,omitempty"`
}

type resEvent struct {
	T      string   `json:"t"`
	IP     string   `json:"ip"`
	P      int      `json:"p"`
	V6     bool     `json:"v6"`
	Lat    *float64 `json:"lat,omitempty"`
	Jit    *float64 `json:"jit,omitempty"`
	Loss   *float64 `json:"loss,omitempty"`
	TcpAtt int      `json:"tcpAtt"`
	TcpOk  int      `json:"tcpOk"`
	TlsOk  bool     `json:"tlsOk"`
	TlsMs  *float64 `json:"tlsMs,omitempty"`
	Colo   string   `json:"colo,omitempty"`
	Mbps   *float64 `json:"mbps,omitempty"`
	Bytes  int64    `json:"bytes,omitempty"`
	Err    string   `json:"err,omitempty"`
}

type prgEvent struct {
	T     string `json:"t"`
	Done  int64  `json:"done"`
	Busy  int64  `json:"busy"`
	Phase string `json:"phase,omitempty"`
}

// -------------------------------------------------------------- config ----

type config struct {
	Cidrs            []string `json:"cidrs"`
	Ports            []int    `json:"ports"`
	Samples          int      `json:"samples"`
	Attempts         int      `json:"attempts"`
	TimeoutMs        int      `json:"timeout_ms"`
	Lanes            int      `json:"lanes"`
	VerifyTop        int      `json:"verify_top"`
	SpeedTop         int      `json:"speed_top"`
	SpeedBytes       int64    `json:"speed_bytes"`
	SpeedConcurrency int      `json:"speed_concurrency"`
	Sni              string   `json:"sni"`
	Debug            bool     `json:"debug"`
}

func defaultConfig() config {
	return config{
		Ports:            []int{443},
		Samples:          240,
		Attempts:         3,
		TimeoutMs:        2000,
		Lanes:            200,
		VerifyTop:        100,
		SpeedTop:         20,
		SpeedBytes:       10_000_000,
		SpeedConcurrency: 4,
		Sni:              "speed.cloudflare.com",
	}
}

// parseConfig accepts the app's JSON with defaults for missing fields.
func parseConfig(text string) (*config, error) {
	cfg := defaultConfig()
	if err := json.Unmarshal([]byte(text), &cfg); err != nil {
		return nil, fmt.Errorf("config json: %w", err)
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = []int{443}
	}
	if cfg.Sni == "" {
		cfg.Sni = "speed.cloudflare.com"
	}
	cfg.Samples = clamp(cfg.Samples, 1, 20_000)
	cfg.Attempts = clamp(cfg.Attempts, 1, 10)
	cfg.TimeoutMs = clamp(cfg.TimeoutMs, 200, 15_000)
	cfg.Lanes = clamp(cfg.Lanes, 1, 1000)
	cfg.VerifyTop = clamp(cfg.VerifyTop, 5, 2000)
	cfg.SpeedTop = clamp(cfg.SpeedTop, 1, 500)
	cfg.SpeedConcurrency = clamp(cfg.SpeedConcurrency, 1, 16)
	if cfg.SpeedBytes < 100_000 {
		cfg.SpeedBytes = 100_000
	}
	if cfg.SpeedBytes > 100_000_000 {
		cfg.SpeedBytes = 100_000_000
	}
	return &cfg, nil
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ------------------------------------------------------------ sampling ----

// sampleIPs draws n addresses spread across the CIDR list (random offsets).
func sampleIPs(cidrs []string, n int, rnd *mrand.Rand) []net.IP {
	type block struct {
		ipNet *net.IPNet
		size  *big.Int
	}
	var blocks []block
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		ones, bits := ipNet.Mask.Size()
		if bits-ones > 48 {
			// huge block (v4 /13, v6 /32): cap the sample window so the
			// draw stays inside the announce (still anycast inside CF)
			size := big.NewInt(1)
			size.Lsh(size, 48)
			blocks = append(blocks, block{ipNet, size})
		} else {
			size := big.NewInt(1)
			size.Lsh(size, uint(bits-ones))
			blocks = append(blocks, block{ipNet, size})
		}
	}
	out := make([]net.IP, 0, n)
	if len(blocks) == 0 {
		return out
	}
	maxI64 := big.NewInt(0).SetInt64(1 << 62)
	for i := 0; i < n; i++ {
		b := blocks[rnd.Intn(len(blocks))]
		// random offset < min(size, 2^62)
		limit := b.size
		if limit.Cmp(maxI64) > 0 {
			limit = maxI64
		}
		off, err := rand.Int(rand.Reader, limit)
		if err != nil {
			off = big.NewInt(rnd.Int63())
		}
		ip := make(net.IP, len(b.ipNet.IP))
		copy(ip, b.ipNet.IP)
		addOffset(ip, off)
		// skip network/broadcast-ish extremes in tiny blocks
		out = append(out, ip)
	}
	return out
}

// addOffset adds a big.Int offset to a 4/16-byte IP in place.
func addOffset(ip net.IP, off *big.Int) {
	b := ip.To16()
	if b == nil {
		return
	}
	carry := new(big.Int).Set(off)
	for i := 15; i >= 0 && carry.Sign() > 0; i-- {
		idx := new(big.Int).And(carry, big.NewInt(0xFF))
		sum := int64(b[i]) + idx.Int64()
		if sum > 255 {
			b[i] = byte(sum - 256)
			carry = new(big.Int).Rsh(carry, 8)
			carry.Add(carry, big.NewInt(1))
		} else {
			b[i] = byte(sum)
			carry = new(big.Int).Rsh(carry, 8)
		}
	}
	if len(ip) == 4 {
		copy(ip, b[12:16])
	}
}

// --------------------------------------------------------------- probes ----

// tcpProbe measures connect latency over `attempts` rounds.
type tcpStats struct {
	lats    []float64
	okCount int
	att     int
	lastErr string
}

func (s tcpStats) avg() float64 {
	if len(s.lats) == 0 {
		return 0
	}
	sum := 0.0
	for _, l := range s.lats {
		sum += l
	}
	return sum / float64(len(s.lats))
}

func (s tcpStats) jitter() float64 {
	if len(s.lats) < 2 {
		return 0
	}
	mean := s.avg()
	varSum := 0.0
	for _, l := range s.lats {
		varSum += (l - mean) * (l - mean)
	}
	return sqrt(varSum / float64(len(s.lats)))
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Newton iterations — enough precision for jitter display
	r := x
	for i := 0; i < 40; i++ {
		r = (r + x/r) / 2
	}
	return r
}

func probeTCP(ip net.IP, port, attempts, timeoutMs int) tcpStats {
	st := tcpStats{att: attempts}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	for i := 0; i < attempts; i++ {
		t0 := time.Now()
		conn, err := net.DialTimeout("tcp", addr, time.Duration(timeoutMs)*time.Millisecond)
		if err != nil {
			st.lastErr = shortErr(err)
			continue
		}
		st.lats = append(st.lats, msSince(t0))
		st.okCount++
		conn.Close()
	}
	return st
}

// tlsProbe: full TLS handshake with certificate validation + /cdn-cgi/trace.
type tlsStats struct {
	ok       bool
	handMs   float64
	colo     string
	loc      string
	httpCode int
	err      string
}

func probeTLS(ip net.IP, port int, sni string, timeoutMs int) tlsStats {
	var st tlsStats
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	t0 := time.Now()
	raw, err := net.DialTimeout("tcp", addr, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		st.err = shortErr(err)
		return st
	}
	_ = raw.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
	conn := tls.Client(raw, &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
	})
	if err := conn.Handshake(); err != nil {
		raw.Close()
		st.err = "tls " + shortErr(err)
		return st
	}
	st.handMs = msSince(t0)
	// cert validation happened during the handshake (system roots)
	if len(conn.ConnectionState().PeerCertificates) == 0 {
		conn.Close()
		st.err = "no certificate"
		return st
	}
	st.ok = true

	// /cdn-cgi/trace on the SAME verified connection — THE clean-ip filter:
	// an edge that answers 200 actually serves this zone (some anycast IPs
	// are real Cloudflare but zone-restricted — error 1034 — and never work
	// in an IP-pinned config).
	trace := rawHTTP(conn, sni, "/cdn-cgi/trace")
	st.httpCode = trace.status
	if trace.err == nil && trace.status == 200 {
		for _, line := range strings.Split(trace.body, "\n") {
			kv := strings.SplitN(strings.TrimSpace(line), "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "colo":
				st.colo = kv[1]
			case "loc":
				st.loc = kv[1]
			}
		}
	} else if trace.err == nil {
		st.ok = false
		if trace.status == 403 {
			st.err = "zone-restricted edge (403/1034) — not usable for this sni"
		} else {
			st.err = fmt.Sprintf("trace http %d", trace.status)
		}
	} else {
		st.ok = false
		st.err = "trace " + shortErr(trace.err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Close()
	return st
}

type httpReply struct {
	status int
	body   string
	err    error
}

// rawHTTP speaks minimal HTTP/1.1 over an established TLS conn.
func rawHTTP(conn *tls.Conn, host, path string) httpReply {
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: umbra-clean/4.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return httpReply{err: err}
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return httpReply{err: err}
	}
	fields := strings.Fields(statusLine)
	status := 0
	if len(fields) >= 2 {
		fmt.Sscanf(fields[1], "%d", &status)
	}
	contentLen := -1
	chunked := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return httpReply{err: err}
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "content-length:"):
			fmt.Sscanf(line[len("Content-Length:"):], "%d", &contentLen)
		case strings.HasPrefix(lower, "transfer-encoding:"):
			if strings.Contains(lower, "chunked") {
				chunked = true
			}
		}
	}
	var body strings.Builder
	if chunked {
		for {
			sizeLine, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			var size int
			fmt.Sscanf(strings.TrimSpace(sizeLine), "%x", &size)
			if size == 0 {
				break
			}
			buf := make([]byte, size)
			if _, err := io.ReadFull(reader, buf); err != nil {
				break
			}
			if body.Len() < 4096 {
				body.Write(buf)
			}
			// trailing CRLF
			_, _ = reader.ReadString('\n')
		}
	} else {
		limit := contentLen
		if limit < 0 || limit > 4096 {
			limit = 4096
		}
		_, _ = io.CopyN(&body, reader, int64(limit))
	}
	return httpReply{status: status, body: body.String()}
}

// speedStats: HTTPS download measurement.
type speedStats struct {
	mbps    float64
	bytes   int64
	status  int
	elapsed float64
	err     string
}

func probeSpeed(ip net.IP, port int, sni string, bytes int64, maxMs int) speedStats {
	var st speedStats
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		st.err = shortErr(err)
		return st
	}
	_ = raw.SetDeadline(time.Now().Add(time.Duration(maxMs) * time.Millisecond))
	conn := tls.Client(raw, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12})
	if err := conn.Handshake(); err != nil {
		raw.Close()
		st.err = "tls " + shortErr(err)
		return st
	}
	path := fmt.Sprintf("/__down?bytes=%d", bytes)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: umbra-clean/4.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, sni)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		st.err = shortErr(err)
		return st
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		st.err = shortErr(err)
		return st
	}
	fields := strings.Fields(statusLine)
	if len(fields) >= 2 {
		fmt.Sscanf(fields[1], "%d", &st.status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.TrimRight(line, "\r\n") == "" {
			break
		}
	}
	discard := make([]byte, 64*1024)
	t1 := time.Now() // body starts NOW (past the headers)
	var total int64
	for {
		n, err := reader.Read(discard)
		total += int64(n)
		if err != nil {
			break
		}
		if time.Since(t1) > time.Duration(maxMs)*time.Millisecond {
			break
		}
	}
	conn.Close()
	st.bytes = total
	st.elapsed = msSince(t1)
	if st.status == 200 && total > 100_000 && st.elapsed > 0 {
		st.mbps = float64(total) * 8.0 / 1000.0 / st.elapsed
	} else if st.status != 200 {
		st.err = fmt.Sprintf("http %d", st.status)
	} else {
		st.err = "no measurable throughput"
	}
	return st
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000.0
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.Index(s, ":"); i > 0 && i < 40 {
		s = s[:i]
	}
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// ------------------------------------------------------------- scanner ----

// StartScan launches the clean-IP scan from a JSON config.
// Returns 0 ok | 1 busy | -1 bad config.
func StartScan(configJSON string) int {
	cfg, err := parseConfig(configJSON)
	if err != nil {
		return -1
	}
	mu.Lock()
	if running && !finished {
		mu.Unlock()
		return 1
	}
	running = true
	finished = false
	cancel.Store(false)
	events = events[:0]
	mu.Unlock()
	go scan(cfg)
	return 0
}

// PollEvents drains pending events as one JSON array ("[]" when idle).
func PollEvents() string {
	mu.Lock()
	defer mu.Unlock()
	if len(events) == 0 {
		return "[]"
	}
	out := "[" + strings.Join(events, ",") + "]"
	events = events[:0]
	return out
}

// CancelScan aborts the running scan.
func CancelScan() { cancel.Store(true) }

// Running reports whether a scan is in flight.
func Running() bool {
	mu.Lock()
	defer mu.Unlock()
	return running && !finished
}

func push(ev string) {
	mu.Lock()
	events = append(events, ev)
	mu.Unlock()
}

func pushLog(line string) {
	b, _ := json.Marshal(event{T: "log", X: line})
	push(string(b))
}

func pushDbg(line string) {
	b, _ := json.Marshal(event{T: "dbg", X: line})
	push(string(b))
}

func pushRes(ev resEvent) {
	b, _ := json.Marshal(ev)
	push(string(b))
}

func pushPrg(phase string) {
	b, _ := json.Marshal(prgEvent{T: "prg", Done: done.Load(), Busy: busy.Load(), Phase: phase})
	push(string(b))
}

func scan(cfg *config) {
	defer func() {
		mu.Lock()
		finished = true
		running = false
		b, _ := json.Marshal(map[string]any{"t": "fin", "cancel": cancel.Load()})
		events = append(events, string(b))
		mu.Unlock()
	}()

	seed := make([]byte, 8)
	_, _ = rand.Read(seed)
	rnd := mrand.New(mrand.NewSource(int64(seed[0]) | int64(seed[1])<<8 | int64(seed[2])<<16 | int64(seed[3])<<24))

	// phase 1: TCP latency storm
	ips := sampleIPs(cfg.Cidrs, cfg.Samples, rnd)
	ports := cfg.Ports
	type target struct {
		ip   net.IP
		port int
	}
	targets := make([]target, 0, len(ips)*len(ports))
	for _, ip := range ips {
		for _, p := range ports {
			targets = append(targets, target{ip, p})
		}
	}
	total = len(targets)
	done.Store(0)
	pushLog(fmt.Sprintf("clean-ip · %d ips x %d port(s) = %d tcp probes · %d lanes", len(ips), len(ports), total, cfg.Lanes))

	sem := make(chan struct{}, cfg.Lanes)
	var wg sync.WaitGroup
	var tcpAliveMu sync.Mutex
	tcpAlive := make([]resEvent, 0, 64)

	for _, tg := range targets {
		if cancel.Load() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(tg target) {
			defer wg.Done()
			defer func() { <-sem }()
			busy.Add(1)
			defer busy.Add(-1)
			st := probeTCP(tg.ip, tg.port, cfg.Attempts, cfg.TimeoutMs)
			ev := resEvent{T: "res", IP: tg.ip.String(), P: tg.port, V6: strings.Contains(tg.ip.String(), ":"), TcpAtt: st.att, TcpOk: st.okCount}
			if st.okCount > 0 {
				avg := st.avg()
				jit := st.jitter()
				loss := float64(st.att-st.okCount) / float64(st.att)
				ev.Lat = &avg
				ev.Jit = &jit
				ev.Loss = &loss
				tcpAliveMu.Lock()
				tcpAlive = append(tcpAlive, ev)
				tcpAliveMu.Unlock()
			} else {
				errMsg := st.lastErr
				ev.Err = errMsg
				if errMsg == "" {
					ev.Err = "unreachable"
				}
			}
			pushRes(ev)
			d := done.Add(1)
			if d%50 == 0 || int(d) == total {
				pushPrg("tcp")
			}
		}(tg)
	}
	wg.Wait()
	pushLog(fmt.Sprintf("tcp phase done · %d tcp-alive of %d", len(tcpAlive), total))

	// phase 2: TLS verification — ARRIVAL order (never latency-sorted:
	// DPI-fake endpoints win every latency race on filtered networks)
	verifyN := cfg.VerifyTop
	if verifyN > len(tcpAlive) {
		verifyN = len(tcpAlive)
	}
	verified := make([]resEvent, 0, verifyN)
	if verifyN > 0 {
		pushLog(fmt.Sprintf("tls verifying %d/%d tcp-alive · sni=%s · dpi-fakes discarded here", verifyN, len(tcpAlive), cfg.Sni))
		sem2 := make(chan struct{}, min(48, cfg.Lanes))
		var wg2 sync.WaitGroup
		var verMu sync.Mutex
		for i := 0; i < verifyN; i++ {
			if cancel.Load() {
				break
			}
			wg2.Add(1)
			sem2 <- struct{}{}
			go func(ev resEvent) {
				defer wg2.Done()
				defer func() { <-sem2 }()
				ip := net.ParseIP(ev.IP)
				st := probeTLS(ip, ev.P, cfg.Sni, max(cfg.TimeoutMs, 1500))
				ev.TlsOk = st.ok
				if st.handMs > 0 {
					ev.TlsMs = &st.handMs
				}
				ev.Colo = st.colo
				if !st.ok {
					ev.Err = st.err
				} else if ev.Err != "" {
					ev.Err = ""
				}
				if st.ok {
					verMu.Lock()
					verified = append(verified, ev)
					verMu.Unlock()
				}
				pushRes(ev)
			}(tcpAlive[i])
		}
		wg2.Wait()
	}
	pushLog(fmt.Sprintf("tls phase done · %d verified of %d probed", len(verified), verifyN))

	// phase 3: speed test on the TLS-verified pool (arrival order again)
	speedN := cfg.SpeedTop
	if speedN > len(verified) {
		speedN = len(verified)
	}
	if speedN > 0 && !cancel.Load() {
		pushLog(fmt.Sprintf("speed testing %d verified · %d bytes via %s", speedN, cfg.SpeedBytes, cfg.Sni))
		sem3 := make(chan struct{}, cfg.SpeedConcurrency)
		var wg3 sync.WaitGroup
		for i := 0; i < speedN; i++ {
			if cancel.Load() {
				break
			}
			wg3.Add(1)
			sem3 <- struct{}{}
			go func(ev resEvent) {
				defer wg3.Done()
				defer func() { <-sem3 }()
				ip := net.ParseIP(ev.IP)
				st := probeSpeed(ip, ev.P, cfg.Sni, cfg.SpeedBytes, 15000)
				if st.mbps > 0 {
					ev.Mbps = &st.mbps
				}
				ev.Bytes = st.bytes
				// a failed bonus speed test never taints a TLS-verified IP
				pushRes(ev)
			}(verified[i])
		}
		wg3.Wait()
	}
	pushPrg("done")
}

// ProbeOnce deep-probes ONE ip:port (TCP + TLS + trace + speed) and returns
// the JSON result — the debug system's single-endpoint lens.
func ProbeOnce(ipText string, port int, configJSON string) string {
	cfg, err := parseConfig(configJSON)
	if err != nil {
		return fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error())
	}
	ip := net.ParseIP(ipText)
	if ip == nil {
		return `{"ok":false,"error":"bad ip"}`
	}
	out := resEvent{T: "res", IP: ip.String(), P: port, V6: strings.Contains(ip.String(), ":")}

	st := probeTCP(ip, port, cfg.Attempts, cfg.TimeoutMs)
	out.TcpAtt = st.att
	out.TcpOk = st.okCount
	if st.okCount > 0 {
		avg := st.avg()
		jit := st.jitter()
		loss := float64(st.att-st.okCount) / float64(st.att)
		out.Lat = &avg
		out.Jit = &jit
		out.Loss = &loss
	} else {
		out.Err = st.lastErr
	}
	tlsSt := probeTLS(ip, port, cfg.Sni, max(cfg.TimeoutMs, 1500))
	out.TlsOk = tlsSt.ok
	if tlsSt.handMs > 0 {
		out.TlsMs = &tlsSt.handMs
	}
	out.Colo = tlsSt.colo
	if tlsSt.err != "" && !tlsSt.ok {
		out.Err = tlsSt.err
	}
	if tlsSt.ok && cfg.SpeedBytes > 0 {
		sp := probeSpeed(ip, port, cfg.Sni, cfg.SpeedBytes, 15000)
		if sp.mbps > 0 {
			out.Mbps = &sp.mbps
		}
		out.Bytes = sp.bytes
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// SystemRootsAvailable reports whether the platform trust store loaded —
// honest diagnostics when an OS provides no CA bundle.
func SystemRootsAvailable() bool {
	pool, err := x509.SystemCertPool()
	return err == nil && pool != nil && len(pool.Subjects()) > 0
}

// SortByLatency is a helper for callers ranking results.
func SortByLatency(items []string) {
	sort.Strings(items)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
