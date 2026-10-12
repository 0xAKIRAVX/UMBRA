// umbra-clean — desktop companion for UMBRA's CLEAN-IP engine.
// Runs the exact same Go engine the Android app embeds, from any network:
//
//	umbra-clean [-samples 240] [-speed 20] [-probe 1.1.1.1]
//
// Prints the raw event stream so scans can be cross-verified between the
// desktop and the phone (the debug system's second opinion).
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	clean "github.com/0xAKIRAVX/UMBRA/native/goclean"
)

func main() {
	samples := flag.Int("samples", 240, "IPs to draw")
	verify := flag.Int("verify", 60, "TLS-verify cap")
	speed := flag.Int("speed", 10, "speed-test cap")
	speedBytes := flag.Int64("speed-bytes", 10_000_000, "download bytes")
	sni := flag.String("sni", "speed.cloudflare.com", "SNI/Host for TLS + speed")
	probe := flag.String("probe", "", "single ip:port deep probe mode")
	flag.Parse()

	if clean.SystemRootsAvailable() {
		log("platform trust store loaded — real certificate validation")
	} else {
		log("WARNING: no system roots — TLS verification may fail on this platform")
	}

	if *probe != "" {
		parts := strings.Split(*probe, ":")
		ip := parts[0]
		port := 443
		if len(parts) > 1 {
			fmt.Sscanf(parts[1], "%d", &port)
		}
		fmt.Println(clean.ProbeOnce(ip, port, fmt.Sprintf(
			`{"sni":%q,"attempts":3,"timeout_ms":2000,"speed_bytes":%d}`, *sni, *speedBytes)))
		return
	}

	cidrs := flag.Args()
	if len(cidrs) == 0 {
		cidrs = []string{
			// the classic clean-IP ranges (Cloudflare IPv4 announces)
			"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
			"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
			"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
			"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
			"172.64.0.0/13", "131.0.72.0/22",
		}
	}

	cfg := fmt.Sprintf(`{"cidrs":[%s],"ports":[443],"samples":%d,"attempts":3,"timeout_ms":2000,`+
		`"lanes":200,"verify_top":%d,"speed_top":%d,"speed_bytes":%d,"speed_concurrency":4,"sni":%q,"debug":true}`,
		quoteJoin(cidrs), *samples, *verify, *speed, *speedBytes, *sni)

	if rc := clean.StartScan(cfg); rc != 0 {
		fmt.Fprintln(os.Stderr, "start failed:", rc)
		os.Exit(1)
	}
	for {
		payload := clean.PollEvents()
		if payload != "[]" {
			fmt.Println(payload)
		}
		if !clean.Running() {
			fmt.Println(clean.PollEvents()) // final drain (fin event)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func quoteJoin(items []string) string {
	quoted := make([]string, len(items))
	for i, it := range items {
		quoted[i] = fmt.Sprintf("%q", it)
	}
	return strings.Join(quoted, ",")
}

func log(line string) {
	fmt.Fprintln(os.Stderr, line)
}
