//! REAL WARP endpoint validator — the Rust port of the UMBRA WarpProbe
//! (BPB-Warp-Scanner approach):
//!
//!   UDP noise burst (optional, anti-DPI — xray `noises` semantics)
//!   → full WireGuard handshake for the registered account
//!   → ICMP echo request to 1.1.1.1 *inside* the encrypted tunnel
//!   → parse the echo reply
//!
//! An endpoint is only reported alive when the WireGuard handshake answers
//! (the in-tunnel ping is the bonus data-plane proof).

use crate::crypto;
use crate::util;
use crate::wg;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// xorshift64* PRNG seeded from the OS.
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new() -> Rng {
        let mut buf = [0u8; 8];
        let mut seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        if crypto::os_random(&mut buf) {
            seed ^= u64::from_le_bytes(buf);
        }
        seed ^= (std::process::id() as u64) << 32;
        if seed == 0 { seed = 0x9E37_79B9_7F4A_7C15; }
        Rng { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    pub fn next_range(&mut self, lo: u32, hi: u32) -> u32 {
        if hi <= lo { return lo; }
        lo + (self.next_u32() % (hi - lo))
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let v = self.next_u64().to_le_bytes();
            let take = std::cmp::min(8, buf.len() - i);
            buf[i..i + take].copy_from_slice(&v[..take]);
            i += take;
        }
    }
}

/// A registered WARP identity: the handshake key material.
#[derive(Clone)]
pub struct Identity {
    pub static_priv: [u8; 32],
    pub static_pub: [u8; 32],
    pub responder_pub: [u8; 32],
    /// Tunnel source IPv4 (from registration; typically 172.16.0.2).
    pub tunnel_v4: [u8; 4],
    /// Address pinged through the tunnel — Cloudflare anycast DNS.
    pub ping_target: [u8; 4],
}

#[derive(Clone)]
pub struct ProbeConfig {
    pub attempts: u32,
    pub timeout_ms: u64,
    pub inter_attempt_ms: u64,
    pub noise_enabled: bool,
    pub noise_count: u32,
    /// Emit per-probe debug lines (the on-device debug system).
    pub debug: bool,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        ProbeConfig {
            attempts: 3,
            timeout_ms: 2500,
            inter_attempt_ms: 200,
            noise_enabled: true,
            noise_count: 5,
            debug: false,
        }
    }
}

/// Result of probing ONE endpoint (all rounds).
#[derive(Clone, Default)]
pub struct ProbeStats {
    pub attempts: u32,
    pub handshakes: u32,
    pub pings: u32,
    pub cookie_replies: u32,
    pub hs_lats: Vec<f64>,
    pub ping_lats: Vec<f64>,
    pub last_error: String,
    pub debug_lines: Vec<String>,
}

impl ProbeStats {
    pub fn alive(&self) -> bool {
        self.handshakes > 0 || self.cookie_replies > 0
    }

    /// Latency = average ping RTT, falling back to average handshake RTT.
    pub fn avg_latency(&self) -> Option<f64> {
        if !self.ping_lats.is_empty() {
            Some(self.ping_lats.iter().sum::<f64>() / self.ping_lats.len() as f64)
        } else if !self.hs_lats.is_empty() {
            Some(self.hs_lats.iter().sum::<f64>() / self.hs_lats.len() as f64)
        } else {
            None
        }
    }

    pub fn jitter(&self) -> Option<f64> {
        let lat = &self.ping_lats;
        if lat.len() < 2 { return None; }
        let mean = lat.iter().sum::<f64>() / lat.len() as f64;
        let var = lat.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / lat.len() as f64;
        Some(var.sqrt())
    }

    /// loss = fraction of rounds where the endpoint answered NOTHING.
    pub fn loss(&self) -> f64 {
        if self.attempts == 0 { return 1.0; }
        (self.attempts - std::cmp::max(self.pings, self.handshakes)) as f64
            / self.attempts as f64
    }
}

/// v3.9 budget ladder: attempt 0 → full budget; attempt 1+ → half (floor 700 ms).
fn attempt_timeout_ms(attempt_index: u32, base: u64) -> u64 {
    if attempt_index == 0 { return base; }
    let half = base / 2;
    let floor = std::cmp::min(base, 700);
    std::cmp::max(half, floor)
}

/// v3.9: the noise burst rides before the FIRST handshake only; later
/// attempts send a single refresh packet.
fn noise_packets_for(attempt_index: u32, configured: u32) -> u32 {
    if attempt_index == 0 { configured.min(50) } else { configured.min(1) }
}

const NOISE_EXCLUDED_OCTETS: [u8; 5] = [10, 127, 169, 172, 192];

/// Random public unicast destination for the anti-DPI noise burst.
fn random_noise_destination(rng: &mut Rng) -> SocketAddr {
    let mut first = rng.next_range(1, 224) as u8;
    while NOISE_EXCLUDED_OCTETS.contains(&first) {
        first = rng.next_range(1, 224) as u8;
    }
    let ip = Ipv4Addr::new(
        first,
        rng.next_range(0, 256) as u8,
        rng.next_range(0, 256) as u8,
        rng.next_range(0, 256) as u8,
    );
    let port = 1024 + rng.next_range(0, 64_512) as u16;
    SocketAddr::new(IpAddr::V4(ip), port)
}

enum Outcome {
    Full { hs_ms: f64, ping_ms: f64 },
    HandshakeOnly { hs_ms: f64, reason: String },
    CookieReply,
    Failed { reason: String },
}

/// Probes one endpoint [attempts] times with [timeout_ms] per datagram wait.
/// Checks [cancel] between rounds and inside every receive slice (≤200 ms)
/// so a user stop lands within a fifth of a second.
pub fn probe_endpoint(
    ip: &IpAddr,
    port: u16,
    identity: &Identity,
    cfg: &ProbeConfig,
    cancel: &Arc<AtomicBool>,
) -> ProbeStats {
    let mut rng = Rng::new();
    let mut stats = ProbeStats::default();
    let target = SocketAddr::new(*ip, port);

    // socket: v6 target needs a v6 wildcard bind
    let bind_addr: &str = if util::is_v6(ip) { "[::]:0" } else { "0.0.0.0:0" };
    let socket = match UdpSocket::bind(bind_addr).and_then(|s| {
        s.connect(target)?;
        Ok(s)
    }) {
        Ok(s) => s,
        Err(e) => {
            stats.attempts = 1;
            stats.last_error = udp_error_name(&e);
            return stats;
        }
    };
    let noise_socket = if cfg.noise_enabled {
        UdpSocket::bind("0.0.0.0:0").ok()
    } else {
        None
    };

    let max_attempts = cfg.attempts.max(1);
    let mut rounds_run: u32 = 0;
    let mut full_seen = false;
    let mut alive_seen = false;
    let mut bonus_spent = false;

    while rounds_run < max_attempts
        && !(full_seen || bonus_spent)
        && !cancel.load(Ordering::Relaxed)
    {
        let alive_before_round = alive_seen;
        let budget = attempt_timeout_ms(rounds_run, cfg.timeout_ms);
        let noise_now = noise_packets_for(rounds_run, cfg.noise_count);

        if cfg.debug {
            stats.debug_lines.push(format!(
                "probe {} · round {}/{} · budget {}ms · noise {}pkts",
                util::format_ip_port(ip, port),
                rounds_run + 1,
                max_attempts,
                budget,
                noise_now
            ));
        }

        let outcome = probe_once(
            &socket,
            noise_socket.as_ref(),
            identity,
            budget,
            &mut rng,
            noise_now,
            cfg,
            cancel,
            &mut stats,
        );
        rounds_run += 1;
        stats.attempts = rounds_run;
        match outcome {
            Outcome::Full { hs_ms, ping_ms } => {
                stats.handshakes += 1;
                stats.pings += 1;
                stats.ping_lats.push(ping_ms);
                stats.hs_lats.push(hs_ms);
                full_seen = true;
            }
            Outcome::HandshakeOnly { hs_ms, reason } => {
                stats.handshakes += 1;
                stats.hs_lats.push(hs_ms);
                stats.last_error = format!("handshake ok · no data plane ({})", reason);
                alive_seen = true;
            }
            Outcome::CookieReply => {
                stats.cookie_replies += 1;
                stats.last_error = "cookie reply · endpoint alive under load".to_string();
                alive_seen = true;
            }
            Outcome::Failed { reason } => {
                stats.last_error = reason;
            }
        }
        if alive_before_round && !full_seen {
            bonus_spent = true;
        }
        if rounds_run < max_attempts
            && cfg.inter_attempt_ms > 0
            && !(full_seen || bonus_spent)
            && !cancel.load(Ordering::Relaxed)
        {
            // cancellable inter-attempt delay in 50 ms slices
            let mut left = cfg.inter_attempt_ms;
            while left > 0 && !cancel.load(Ordering::Relaxed) {
                let slice = std::cmp::min(50, left);
                std::thread::sleep(Duration::from_millis(slice));
                left -= slice;
            }
        }
    }

    if cancel.load(Ordering::Relaxed) && stats.attempts == 0 {
        stats.attempts = 1;
    }
    stats
}

fn udp_error_name(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => "icmp port-unreachable".to_string(),
        io::ErrorKind::WouldBlock => "timeout".to_string(),
        io::ErrorKind::PermissionDenied => "udp send blocked".to_string(),
        _ => format!("udp {}", classify_io(e)),
    }
}

fn classify_io(e: &io::Error) -> String {
    // short, stable, human-readable — matches the Kotlin failure classes
    let s = e.to_string();
    // strip OS noise: "Os { code: 111, kind: ConnectionRefused, ... }"
    if s.starts_with("Os {") {
        format!("{:?}", e.kind())
            .trim_matches('"')
            .to_string()
    } else {
        s
    }
}

#[allow(clippy::too_many_arguments)]
fn probe_once(
    socket: &UdpSocket,
    noise_socket: Option<&UdpSocket>,
    identity: &Identity,
    budget_ms: u64,
    rng: &mut Rng,
    noise_count: u32,
    cfg: &ProbeConfig,
    cancel: &Arc<AtomicBool>,
    stats: &mut ProbeStats,
) -> Outcome {
    // 1. UDP noise burst — RANDOM destinations, never the probe target.
    if cfg.noise_enabled {
        if let Some(ns) = noise_socket {
            for _ in 0..noise_count {
                let n = rng.next_range(50, 100) as usize;
                let mut pkt = vec![0u8; n];
                rng.fill(&mut pkt);
                let dest = random_noise_destination(rng);
                let _ = ns.send_to(&pkt, dest);
                let d = rng.next_range(1, 5);
                std::thread::sleep(Duration::from_millis(d as u64));
            }
        }
    }

    // 2. handshake initiation (fresh ephemeral + index + timestamp)
    let sender_index = rng.next_u32();
    let mut eph_priv = [0u8; 32];
    if !crypto::os_random(&mut eph_priv) {
        rng.fill(&mut eph_priv);
    }
    let eph_priv = crypto::clamp_scalar(&eph_priv);
    let timestamp = wg::tai64n_now();

    let (init_packet, pending) = wg::build_initiation(
        &identity.static_priv,
        &identity.static_pub,
        &identity.responder_pub,
        sender_index,
        &eph_priv,
        &timestamp,
    );
    let pending = match pending {
        Some(p) => p,
        None => {
            return Outcome::Failed { reason: "identity rejected (bad key)".to_string() }
        }
    };

    let t0 = Instant::now();
    if let Err(e) = socket.send(&init_packet) {
        return Outcome::Failed { reason: format!("send refused ({})", udp_error_name(&e)) };
    }
    if cfg.debug {
        stats.debug_lines.push(format!(
            "→ init 148B idx=0x{:08x} t0+{:.0}ms",
            sender_index,
            t0.elapsed().as_secs_f64() * 1000.0
        ));
    }

    // 3. wait for the response, skipping stray datagrams (QUIC/MASQUE junk)
    let deadline = Instant::now() + Duration::from_millis(budget_ms);
    let mut resp: Option<Vec<u8>> = None;
    let mut resp_instant = Instant::now();
    while resp.is_none() {
        if cancel.load(Ordering::Relaxed) {
            return Outcome::Failed { reason: "cancelled".to_string() };
        }
        let now = Instant::now();
        if now >= deadline {
            return Outcome::Failed { reason: "handshake timeout".to_string() };
        }
        let remaining = deadline - now;
        let slice = std::cmp::min(remaining, Duration::from_millis(200));
        if socket.set_read_timeout(Some(slice)).is_err() {
            return Outcome::Failed { reason: "socket broken".to_string() };
        }
        let mut buf = [0u8; 2048];
        match socket.recv(&mut buf) {
            Ok(len) => {
                if len == wg::RESPONSE_SIZE || len == wg::COOKIE_REPLY_SIZE {
                    resp = Some(buf[..len].to_vec());
                    resp_instant = Instant::now();
                }
                // anything else: junk from a co-hosted service — skip and keep waiting
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => {
                return Outcome::Failed { reason: udp_error_name(&e) };
            }
        }
    }
    let hs_ms = resp_instant.duration_since(t0).as_secs_f64() * 1000.0;
    let resp_bytes = resp.unwrap();

    if cfg.debug {
        stats.debug_lines.push(format!(
            "← {}B type={} hs={:.1}ms {}",
            resp_bytes.len(),
            resp_bytes[0],
            hs_ms,
            hex_preview(&resp_bytes)
        ));
    }

    // 4. consume the response
    let (session, err) = wg::consume_response(&pending, &identity.static_priv, &resp_bytes);
    match session {
        Some(mut session) => {
            // 5. ICMP echo request INSIDE the tunnel
            let ident = (rng.next_range(0, 0x8000) | 0x8000) as u16;
            let inner = wg::icmp_echo_request(&identity.tunnel_v4, &identity.ping_target, ident, 1);
            let transport = session.build_transport(&inner);
            let t1 = Instant::now();
            if let Err(e) = socket.send(&transport) {
                return Outcome::HandshakeOnly {
                    hs_ms,
                    reason: format!("ping send refused ({})", udp_error_name(&e)),
                };
            }
            // wait for the data plane — only a type-4 packet carries the reply
            let ping_deadline = Instant::now() + Duration::from_millis(budget_ms);
            let mut data: Option<Vec<u8>> = None;
            let mut data_instant = Instant::now();
            while data.is_none() {
                if cancel.load(Ordering::Relaxed) {
                    return Outcome::HandshakeOnly { hs_ms, reason: "cancelled".to_string() };
                }
                let now = Instant::now();
                if now >= ping_deadline {
                    return Outcome::HandshakeOnly { hs_ms, reason: "ping timeout".to_string() };
                }
                let remaining = ping_deadline - now;
                let slice = std::cmp::min(remaining, Duration::from_millis(200));
                if socket.set_read_timeout(Some(slice)).is_err() {
                    return Outcome::HandshakeOnly { hs_ms, reason: "socket broken".to_string() };
                }
                let mut buf = [0u8; 2048];
                match socket.recv(&mut buf) {
                    Ok(len) => {
                        if len >= 32 && buf[0] == wg::MSG_TRANSPORT {
                            data = Some(buf[..len].to_vec());
                            data_instant = Instant::now();
                        }
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(e) => {
                        return Outcome::HandshakeOnly {
                            hs_ms,
                            reason: udp_error_name(&e),
                        };
                    }
                }
            }
            let ping_ms = data_instant.duration_since(t1).as_secs_f64() * 1000.0;
            let inner_reply = match session.open_transport(&data.unwrap()) {
                Some(v) => v,
                None => return Outcome::HandshakeOnly { hs_ms, reason: "bad transport reply".to_string() },
            };
            if wg::parse_echo_reply(&inner_reply, ident, 1) {
                Outcome::Full { hs_ms, ping_ms }
            } else {
                Outcome::HandshakeOnly { hs_ms, reason: "not our echo".to_string() }
            }
        }
        None => {
            // type 3 cookie reply still proves a live WARP endpoint (under load)
            if resp_bytes.len() == wg::COOKIE_REPLY_SIZE && resp_bytes[0] == wg::MSG_COOKIE_REPLY {
                Outcome::CookieReply
            } else {
                Outcome::Failed { reason: err }
            }
        }
    }
}

/// First 48 bytes hex — the deep-debug packet preview.
fn hex_preview(data: &[u8]) -> String {
    let n = std::cmp::min(48, data.len());
    let mut s = String::with_capacity(n * 2);
    for b in &data[..n] {
        s.push_str(&format!("{:02x}", b));
    }
    if data.len() > n {
        s.push_str("..");
    }
    s
}

/// DNS-resolves a hostname into endpoint IPs (v4 + v6).
pub fn resolve_host(host: &str, port: u16) -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(addrs) = (host, port).to_socket_addrs() {
        for a in addrs {
            if !out.contains(&a.ip()) {
                out.push(a.ip());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_ladder() {
        assert_eq!(attempt_timeout_ms(0, 2000), 2000);
        assert_eq!(attempt_timeout_ms(1, 2000), 1000);
        assert_eq!(attempt_timeout_ms(2, 2000), 1000);
        assert_eq!(attempt_timeout_ms(1, 900), 700);
        assert_eq!(attempt_timeout_ms(1, 400), 400); // floor capped by base
    }

    #[test]
    fn noise_ladder() {
        assert_eq!(noise_packets_for(0, 5), 5);
        assert_eq!(noise_packets_for(1, 5), 1);
        assert_eq!(noise_packets_for(0, 99), 50);
    }

    #[test]
    fn loss_semantics() {
        // handshake-only endpoint: loss counts only fully-silent rounds
        let mut st = ProbeStats::default();
        st.attempts = 2;
        st.handshakes = 2;
        st.pings = 0;
        assert_eq!(st.loss(), 0.0);
        // fully silent
        let mut st2 = ProbeStats::default();
        st2.attempts = 2;
        assert_eq!(st2.loss(), 1.0);
    }
}
