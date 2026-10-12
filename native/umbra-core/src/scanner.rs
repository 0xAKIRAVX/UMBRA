//! Batch scan manager: a Rust-owned thread pool that storms the endpoint
//! pool with real WG probes and streams events for the Kotlin layer to poll.
//!
//! The JNI surface is deliberately tiny and poll-based (no JVM calls from
//! Rust, ever):
//!   umbra_start_scan(config_json) -> 0 ok | 1 busy | -1 bad config
//!   umbra_poll_events(&ptr, &len) -> JSON array of events (b"[]" when idle)
//!   umbra_cancel_scan()
//!   umbra_probe_once(ip, port, config_json, out, cap) -> deep-debug probe
//!
//! Event objects (compact JSON, parsed by Kotlin org.json):
//!   {"t":"log","x":"..."}                          engine log line
//!   {"t":"dbg","x":"..."}                          per-probe debug line
//!   {"t":"res","ip":"..","p":2408,"v6":false,"att":1,"hs":1,"png":1,
//!    "ck":0,"hms":[23.1],"pms":[45.2],"err":"","rtt":45.2}
//!   {"t":"prg","done":n,"busy":n}                  progress heartbeat
//!   {"t":"fin","cancel":false,"mark":"b64|null"}   scan finished

use crate::probe::{self, Identity, ProbeConfig, ProbeStats};
use crate::util::{self, Json};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

pub struct ScanConfig {
    pub targets: Vec<(IpAddr, u16)>,
    pub identity: Identity,
    pub probe: ProbeConfig,
    pub lanes: usize,
}

enum Event {
    Log(String),
    Dbg(String),
    Result(ResultEvent),
    Progress { done: u64, busy: u64 },
    Finished { cancelled: bool },
}

struct ResultEvent {
    ip: IpAddr,
    port: u16,
    stats: ProbeStats,
}

struct ScanState {
    events: Mutex<Vec<Event>>,
    cancel: Arc<AtomicBool>,
    handles: Mutex<Vec<thread::JoinHandle<()>>>,
    finished: AtomicBool,
    workers_alive: AtomicU64,
    active: AtomicU64,
    done: AtomicU64,
    total: u64,
}

static SCANNER: Mutex<Option<Arc<ScanState>>> = Mutex::new(None);

/// Parses the Kotlin-side scan config JSON.
pub fn parse_config(text: &str) -> Result<ScanConfig, String> {
    let root = util::parse_json(text).ok_or("config is not valid JSON")?;
    let cfg = parse_config_inner(root, true)?;
    Ok(cfg)
}

/// Parses a PROBE-ONCE config (targets optional — the explicit ip:port arg
/// IS the target).
pub fn parse_probe_config(text: &str) -> Result<ScanConfig, String> {
    let root = util::parse_json(text).ok_or("config is not valid JSON")?;
    let mut cfg = parse_config_inner(root, false)?;
    // a single-target placeholder so downstream code never sees an empty pool
    if cfg.targets.is_empty() {
        cfg.targets = vec![(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 2408u16)];
    }
    Ok(cfg)
}

fn parse_config_inner(root: util::Json, require_targets: bool) -> Result<ScanConfig, String> {

    // identity (required)
    let id = root.get("identity").ok_or("missing identity")?;
    let b32 = |v: &Json, name: &str| -> Result<[u8; 32], String> {
        let s = v.get(name).and_then(|x| x.as_str()).ok_or("missing key")?;
        let raw = util::base64_decode(s).ok_or("bad base64")?;
        raw.try_into().map_err(|_| format!("{} must be 32 bytes", name))
    };
    let identity = Identity {
        static_priv: b32(id, "priv")?,
        static_pub: b32(id, "pub")?,
        responder_pub: b32(id, "peer")?,
        tunnel_v4: id
            .get("v4")
            .and_then(|x| x.as_str())
            .and_then(util::parse_v4_bytes)
            .unwrap_or([172, 16, 0, 2]),
        ping_target: root
            .get("ping")
            .and_then(|x| x.as_str())
            .and_then(util::parse_v4_bytes)
            .unwrap_or([1, 1, 1, 1]),
    };

    // targets (required for batch scans; optional for probe-once)
    let targets_json = match root.get("targets").and_then(|x| x.as_arr()) {
        Some(t) => t,
        None => {
            if require_targets {
                return Err("missing targets".to_string());
            }
            &Vec::new() as &Vec<util::Json>
        }
    };
    let mut targets = Vec::with_capacity(targets_json.len());
    for t in targets_json {
        if let Some(arr) = t.as_arr() {
            let ip_text = arr.first().and_then(|x| x.as_str()).ok_or("bad target ip")?;
            let port = arr.get(1).and_then(|x| x.as_u16()).ok_or("bad target port")?;
            let ip = util::parse_ip(ip_text).ok_or("bad target ip")?;
            targets.push((ip, port));
        } else if let Some(text) = t.as_str() {
            let (ip_text, port) = split_host_port(text).ok_or("bad target")?;
            let ip = util::parse_ip(ip_text).ok_or("bad target ip")?;
            targets.push((ip, port));
        }
    }
    if targets.is_empty() && require_targets {
        return Err("empty targets".to_string());
    }

    let f = |name: &str, default: f64| -> f64 {
        root.get(name).and_then(|x| x.as_f64()).unwrap_or(default)
    };
    let probe = ProbeConfig {
        attempts: f("attempts", 3.0).clamp(1.0, 7.0) as u32,
        timeout_ms: f("timeout_ms", 2500.0).max(200.0) as u64,
        inter_attempt_ms: f("inter_ms", 200.0) as u64,
        noise_enabled: root.get("noise").and_then(|x| x.as_bool()).unwrap_or(true),
        noise_count: f("noise_count", 5.0).clamp(0.0, 50.0) as u32,
        debug: root.get("debug").and_then(|x| x.as_bool()).unwrap_or(false),
    };
    let lanes = f("lanes", 128.0).clamp(1.0, 500.0) as usize;

    // restore persisted TAI64N high-water mark (anti-replay across restarts)
    if let Some(mark_b64) = root.get("mark").and_then(|x| x.as_str()) {
        if let Some(raw) = util::base64_decode(mark_b64) {
            if raw.len() == 12 {
                let mut m = [0u8; 12];
                m.copy_from_slice(&raw);
                crate::wg::load_mark(Some(m));
            }
        }
    } else if root.get("mark_reset").and_then(|x| x.as_bool()).unwrap_or(false) {
        crate::wg::reset_mark();
    }

    Ok(ScanConfig { targets, identity, probe, lanes })
}

fn split_host_port(text: &str) -> Option<(&str, u16)> {
    if let Some(idx) = text.rfind(']') {
        let rest = &text[idx + 1..];
        if let Some(p) = rest.strip_prefix(':') {
            return Some((&text[..idx + 1], p.parse().ok()?));
        }
        return None;
    }
    if let Some(idx) = text.rfind(':') {
        if text.matches(':').count() == 1 {
            return Some((&text[..idx], text[idx + 1..].parse().ok()?));
        }
    }
    None
}

/// Starts a scan. Returns 0 ok, 1 busy (one scan at a time), -1 bad config.
pub fn start(config: ScanConfig) -> i32 {
    let mut guard = SCANNER.lock().unwrap();
    if let Some(st) = guard.as_ref() {
        if !st.finished.load(Ordering::SeqCst) {
            return 1; // busy
        }
        // reap the previous scan's threads
        let handles = std::mem::take(&mut *st.handles.lock().unwrap());
        for h in handles {
            let _ = h.join();
        }
    }
    *guard = None;

    let ScanConfig { targets, identity, probe, lanes } = config;
    let total = targets.len() as u64;
    let cancel = Arc::new(AtomicBool::new(false));
    let state = Arc::new(ScanState {
        events: Mutex::new(vec![Event::Log(format!(
            "rust core · {} targets · {} lanes · {}ms x {} attempts",
            total, lanes, probe.timeout_ms, probe.attempts
        ))]),
        cancel: cancel.clone(),
        handles: Mutex::new(Vec::new()),
        finished: AtomicBool::new(false),
        workers_alive: AtomicU64::new(0),
        active: AtomicU64::new(0),
        done: AtomicU64::new(0),
        total,
    });

    let queue = Arc::new(Mutex::new(targets));
    let identity = Arc::new(identity);
    let probe_cfg = Arc::new(probe);

    let worker_count = std::cmp::min(lanes.max(1), total as usize);
    let mut handles = Vec::with_capacity(worker_count);
    state.workers_alive.store(worker_count as u64, Ordering::SeqCst);
    for _ in 0..worker_count {
        let queue = queue.clone();
        let identity = identity.clone();
        let probe_cfg = probe_cfg.clone();
        let state_cl = state.clone();
        let cancel = cancel.clone();
        match thread::Builder::new()
            .name("umbra-wg-probe".into())
            .spawn(move || worker_loop(queue, identity, probe_cfg, state_cl, cancel))
        {
            Ok(h) => handles.push(h),
            Err(_) => {
                // a failed spawn decrements the alive count so finish() still fires
                state.workers_alive.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
    *state.handles.lock().unwrap() = handles;
    *guard = Some(state);
    0
}

fn worker_loop(
    queue: Arc<Mutex<Vec<(IpAddr, u16)>>>,
    identity: Arc<Identity>,
    probe_cfg: Arc<ProbeConfig>,
    state: Arc<ScanState>,
    cancel: Arc<AtomicBool>,
) {
    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let job = queue.lock().unwrap().pop();
        let (ip, port) = match job {
            Some(j) => j,
            None => break, // queue drained
        };
        state.active.fetch_add(1, Ordering::SeqCst);
        let stats = probe::probe_endpoint(&ip, port, &identity, &probe_cfg, &cancel);
        state.active.fetch_sub(1, Ordering::SeqCst);
        let done = state.done.fetch_add(1, Ordering::SeqCst) + 1;

        // debug lines first (they narrate the result that follows)
        if probe_cfg.debug {
            for line in &stats.debug_lines {
                state.events.lock().unwrap().push(Event::Dbg(line.clone()));
            }
        }
        state
            .events
            .lock()
            .unwrap()
            .push(Event::Result(ResultEvent { ip, port, stats }));

        // progress heartbeat every 25 probes
        if done % 25 == 0 || done == state.total {
            state.events.lock().unwrap().push(Event::Progress {
                done,
                busy: state.active.load(Ordering::SeqCst),
            });
        }
    }
    // the LAST worker to exit finishes the scan (writes the fin event)
    if state.workers_alive.fetch_sub(1, Ordering::SeqCst) == 1 {
        state
            .events
            .lock()
            .unwrap()
            .push(Event::Progress {
                done: state.done.load(Ordering::SeqCst),
                busy: 0,
            });
        state.finished.store(true, Ordering::SeqCst);
        state.events.lock().unwrap().push(Event::Finished {
            cancelled: state.cancel.load(Ordering::SeqCst),
        });
    }
}

/// Serializes and drains pending events into one JSON array.
/// Returns b"[]" when idle. The caller must copy the bytes out before the
/// next poll (single backing buffer per call).
pub fn poll() -> Vec<u8> {
    let state = {
        let guard = SCANNER.lock().unwrap();
        match guard.clone() {
            Some(s) => s,
            None => return b"[]".to_vec(),
        }
    };
    let mut evts = {
        let mut q = state.events.lock().unwrap();
        std::mem::take(&mut *q)
    };
    if evts.is_empty() {
        return b"[]".to_vec();
    }
    let mut out = String::from("[");
    let mut first = true;
    let mut json_obj = |s: String, out: &mut String, first: &mut bool| {
        if !*first { out.push(','); }
        *first = false;
        out.push_str(&s);
    };
    for e in evts.drain(..) {
        match e {
            Event::Log(x) => json_obj(format!("{{\"t\":\"log\",\"x\":\"{}\"}}", util::json_escape(&x)), &mut out, &mut first),
            Event::Dbg(x) => json_obj(format!("{{\"t\":\"dbg\",\"x\":\"{}\"}}", util::json_escape(&x)), &mut out, &mut first),
            Event::Progress { done, busy } => json_obj(
                format!("{{\"t\":\"prg\",\"done\":{},\"busy\":{}}}", done, busy),
                &mut out,
                &mut first,
            ),
            Event::Finished { cancelled } => {
                let mark = crate::wg::save_mark();
                let mark_str = match mark {
                    Some(m) => format!("\"{}\"", util::base64_encode(&m)),
                    None => "null".to_string(),
                };
                json_obj(
                    format!(
                        "{{\"t\":\"fin\",\"cancel\":{},\"mark\":{}}}",
                        if cancelled { "true" } else { "false" },
                        mark_str
                    ),
                    &mut out,
                    &mut first,
                )
            }
            Event::Result(r) => {
                let st = &r.stats;
                let lats = |v: &Vec<f64>| -> String {
                    if v.is_empty() {
                        "[]".to_string()
                    } else {
                        let items: Vec<String> =
                            v.iter().map(|x| format!("{:.1}", x)).collect();
                        format!("[{}]", items.join(","))
                    }
                };
                let rtt = match st.avg_latency() {
                    Some(v) => format!("{:.1}", v),
                    None => "null".to_string(),
                };
                let jit = match st.jitter() {
                    Some(v) => format!("{:.1}", v),
                    None => "null".to_string(),
                };
                json_obj(
                    format!(
                        "{{\"t\":\"res\",\"ip\":\"{}\",\"p\":{},\"v6\":{},\"att\":{},\"hs\":{},\"png\":{},\"ck\":{},\"hms\":{},\"pms\":{},\"err\":\"{}\",\"rtt\":{},\"jit\":{}}}",
                        r.ip,
                        r.port,
                        util::is_v6(&r.ip),
                        st.attempts,
                        st.handshakes,
                        st.pings,
                        st.cookie_replies,
                        lats(&st.hs_lats),
                        lats(&st.ping_lats),
                        util::json_escape(&st.last_error),
                        rtt,
                        jit
                    ),
                    &mut out,
                    &mut first,
                )
            }
        }
    }
    out.push(']');
    out.into_bytes()
}

/// Cancels the running scan (workers land within ~200 ms).
pub fn cancel() {
    let guard = SCANNER.lock().unwrap();
    if let Some(st) = guard.as_ref() {
        st.cancel.store(true, Ordering::SeqCst);
    }
}

/// Is a scan currently running?
pub fn is_running() -> bool {
    let guard = SCANNER.lock().unwrap();
    guard.as_ref().map(|s| !s.finished.load(Ordering::SeqCst)).unwrap_or(false)
}

/// Deep-debug single endpoint probe (blocks; runs its own socket + retries).
/// Writes a JSON object of the probe result into `out`, returns bytes
/// written or -1 on error.
pub fn probe_once_json(ip_text: &str, port: u16, config_text: &str, out: &mut Vec<u8>) -> i32 {
    let cfg = match parse_probe_config(config_text) {
        Ok(c) => c,
        Err(e) => {
            let s = format!(
                "{{\"ok\":false,\"error\":\"{}\"}}",
                util::json_escape(&e)
            );
            out.extend_from_slice(s.as_bytes());
            return s.len() as i32;
        }
    };
    let ip = match util::parse_ip(ip_text) {
        Some(ip) => ip,
        None => {
            let s = "{\"ok\":false,\"error\":\"bad ip\"}";
            out.extend_from_slice(s.as_bytes());
            return s.len() as i32;
        }
    };
    // override: single target, debug always on
    let probe_cfg = ProbeConfig { debug: true, ..cfg.probe };
    let cancel = Arc::new(AtomicBool::new(false));
    let stats = probe::probe_endpoint(&ip, port, &cfg.identity, &probe_cfg, &cancel);

    let lats = |v: &Vec<f64>| -> String {
        if v.is_empty() {
            "[]".to_string()
        } else {
            let items: Vec<String> = v.iter().map(|x| format!("{:.1}", x)).collect();
            format!("[{}]", items.join(","))
        }
    };
    let rtt = match stats.avg_latency() {
        Some(v) => format!("{:.1}", v),
        None => "null".to_string(),
    };
    let jit = match stats.jitter() {
        Some(v) => format!("{:.1}", v),
        None => "null".to_string(),
    };
    let loss = format!("{:.2}", stats.loss());
    let dbg: Vec<String> = stats
        .debug_lines
        .iter()
        .map(|l| format!("\"{}\"", util::json_escape(l)))
        .collect();
    let s = format!(
        "{{\"ok\":true,\"ip\":\"{}\",\"p\":{},\"v6\":{},\"att\":{},\"hs\":{},\"png\":{},\"ck\":{},\"hms\":{},\"pms\":{},\"err\":\"{}\",\"rtt\":{},\"jit\":{},\"loss\":{},\"dbg\":[{}]}}",
        ip,
        port,
        util::is_v6(&ip),
        stats.attempts,
        stats.handshakes,
        stats.pings,
        stats.cookie_replies,
        lats(&stats.hs_lats),
        lats(&stats.ping_lats),
        util::json_escape(&stats.last_error),
        rtt,
        jit,
        loss,
        dbg.join(",")
    );
    out.extend_from_slice(s.as_bytes());
    s.len() as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_split() {
        assert_eq!(split_host_port("162.159.192.42:2408"), Some(("162.159.192.42", 2408)));
        assert_eq!(split_host_port("[2606:4700:d0::1]:894"), Some(("[2606:4700:d0::1]", 894)));
        assert_eq!(split_host_port("2606:4700:d0::1"), None);
    }

    #[test]
    fn config_parse() {
        let cfg_json = r#"{
            "targets": [["162.159.192.42", 2408], "188.114.96.1:2408"],
            "identity": {
                "priv": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "pub": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
                "v4": "172.16.0.2"
            },
            "ping": "1.1.1.1",
            "attempts": 3, "timeout_ms": 2500, "inter_ms": 200,
            "noise": true, "noise_count": 5, "debug": true, "lanes": 128
        }"#;
        let cfg = parse_config(cfg_json).unwrap();
        assert_eq!(cfg.targets.len(), 2);
        assert_eq!(cfg.probe.attempts, 3);
        assert_eq!(cfg.identity.tunnel_v4, [172, 16, 0, 2]);
        assert_eq!(cfg.identity.ping_target, [1, 1, 1, 1]);
        assert!(parse_json_fails("{}"));
        assert!(parse_json_fails(
            r#"{"identity":{"priv":"AAAA","pub":"AAAA","peer":"AAAA"},"targets":[]}"#
        ));
    }

    fn parse_json_fails(s: &str) -> bool {
        parse_config(s).is_err()
    }

    #[test]
    fn poll_serializes_results() {
        let state = Arc::new(ScanState {
            events: Mutex::new(vec![
                Event::Log("hello".into()),
                Event::Result(ResultEvent {
                    ip: "162.159.192.42".parse().unwrap(),
                    port: 2408,
                    stats: ProbeStats {
                        attempts: 1,
                        handshakes: 1,
                        pings: 1,
                        cookie_replies: 0,
                        hs_lats: vec![23.4],
                        ping_lats: vec![45.6],
                        last_error: String::new(),
                        debug_lines: vec![],
                    },
                }),
                Event::Finished { cancelled: false },
            ]),
            cancel: Arc::new(AtomicBool::new(false)),
            handles: Mutex::new(Vec::new()),
            finished: AtomicBool::new(true),
            workers_alive: AtomicU64::new(0),
            active: AtomicU64::new(0),
            done: AtomicU64::new(1),
            total: 1,
        });
        // parse the events back through the global slot? — instead verify
        // serialization by driving it through a local SCANNER swap.
        let mut guard = SCANNER.lock().unwrap();
        let old = guard.replace(state);
        drop(guard);
        let payload = poll();
        let text = String::from_utf8(payload).unwrap();
        assert!(text.starts_with('[') && text.ends_with(']'), "{}", text);
        assert!(text.contains("\"t\":\"log\""));
        assert!(text.contains("\"t\":\"res\""));
        assert!(text.contains("\"hs\":1"));
        assert!(text.contains("\"t\":\"fin\""));
        // drained — next poll is empty
        let again = poll();
        assert_eq!(again, b"[]".to_vec());
        let mut guard = SCANNER.lock().unwrap();
        *guard = old;
    }
}
