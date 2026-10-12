//! UMBRA native scan core — public FFI surface (called from the C JNI shim).
//!
//! Safety contract:
//!  - every entry point catches panics (a panic must never unwind into JNI)
//!  - all returned pointers point into buffers owned by this library and
//!    stay valid until the next call of the same function
//!  - no JVM calls happen from Rust (the Kotlin side polls events)

pub mod crypto;
pub mod probe;
pub mod scanner;
pub mod util;
pub mod wg;

use std::ffi::c_char;
use std::sync::Mutex;

/// Single backing buffer for poll results (stable pointer between calls;
/// poll has a single caller — the controller's pump coroutine — so the
/// pointer window is race-free).
static POLL_BUFFER: Mutex<Vec<u8>> = Mutex::new(Vec::new());

const VERSION: &str = "UMBRA-RUST-CORE 4.0.0 (x25519 blake2s chacha20poly1305 noise-ik wg-probe)";

#[no_mangle]
pub extern "C" fn umbra_version() -> *const c_char {
    VERSION.as_ptr() as *const c_char
}

/// Starts a batch scan from a config JSON.
/// Returns 0 ok | 1 busy | -1 bad config.
#[no_mangle]
pub extern "C" fn umbra_start_scan(cfg: *const u8, len: usize) -> i32 {
    catch_unwind_i32(|| {
        if cfg.is_null() || len == 0 || len > (16 << 20) {
            return -1;
        }
        let bytes = unsafe { std::slice::from_raw_parts(cfg, len) };
        let text = match std::str::from_utf8(bytes) {
            Ok(t) => t,
            Err(_) => return -1,
        };
        match scanner::parse_config(text) {
            Ok(config) => scanner::start(config),
            Err(_) => -1,
        }
    })
}

/// Drains pending scan events into the poll buffer.
/// Sets *out_ptr/*out_len to the serialized JSON array (b"[]" when idle).
/// Returns 0 ok (buffer valid), 1 no scan has ever started.
#[no_mangle]
pub extern "C" fn umbra_poll_events(out_ptr: *mut *const u8, out_len: *mut usize) -> i32 {
    catch_unwind_i32(|| {
        if out_ptr.is_null() || out_len.is_null() {
            return -1;
        }
        let mut buf = POLL_BUFFER.lock().unwrap();
        *buf = scanner::poll();
        unsafe {
            *out_ptr = buf.as_ptr();
            *out_len = buf.len();
        }
        0
    })
}

/// Cancels the running scan (idempotent).
#[no_mangle]
pub extern "C" fn umbra_cancel_scan() {
    let _ = std::panic::catch_unwind(|| scanner::cancel());
}

/// Is a scan running right now?
#[no_mangle]
pub extern "C" fn umbra_scan_running() -> i32 {
    catch_unwind_i32(|| if scanner::is_running() { 1 } else { 0 })
}

/// Deep-debug single endpoint probe (blocks; full WG handshake + retries +
/// per-round debug lines). Writes the JSON result INTO the caller-provided
/// buffer (thread-safe: no shared state; concurrent callers each use their
/// own buffer). Returns bytes written (truncated to cap) or -1.
#[no_mangle]
pub extern "C" fn umbra_probe_once(
    ip: *const c_char,
    port: u16,
    cfg: *const u8,
    len: usize,
    out: *mut u8,
    cap: usize,
) -> i32 {
    catch_unwind_i32(|| {
        if ip.is_null() || cfg.is_null() || out.is_null() || cap == 0 {
            return -1;
        }
        let ip_c = unsafe { std::ffi::CStr::from_ptr(ip) };
        let ip_s = match ip_c.to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let bytes = unsafe { std::slice::from_raw_parts(cfg, len) };
        let cfg_text = match std::str::from_utf8(bytes) {
            Ok(t) => t,
            Err(_) => return -1,
        };
        // run the probe into a LOCAL buffer, then copy out (truncating)
        let mut local: Vec<u8> = Vec::new();
        let _ = scanner::probe_once_json(ip_s, port, cfg_text, &mut local);
        let n = std::cmp::min(local.len(), cap);
        unsafe {
            std::ptr::copy_nonoverlapping(local.as_ptr(), out, n);
        }
        n as i32
    })
}

/// TAI64N high-water mark persistence (identity anti-replay across
/// process restarts): copies 12 bytes into out (returns 12 or 0).
#[no_mangle]
pub extern "C" fn umbra_get_mark(out: *mut u8) -> i32 {
    catch_unwind_i32(|| {
        if out.is_null() {
            return 0;
        }
        match wg::save_mark() {
            Some(m) => unsafe {
                std::ptr::copy_nonoverlapping(m.as_ptr(), out, 12);
                12
            },
            None => 0,
        }
    })
}

#[no_mangle]
pub extern "C" fn umbra_reset_mark() {
    let _ = std::panic::catch_unwind(wg::reset_mark);
}

/// Restores a persisted TAI64N high-water mark into the Rust core
/// (called once at scan start; 12 bytes).
#[no_mangle]
pub extern "C" fn umbra_load_mark(mark: *const u8, len: usize) {
    let _ = std::panic::catch_unwind(|| {
        if mark.is_null() || len != 12 {
            return;
        }
        let mut m = [0u8; 12];
        unsafe {
            std::ptr::copy_nonoverlapping(mark, m.as_mut_ptr(), 12);
        }
        wg::load_mark(Some(m));
    });
}

fn catch_unwind_i32<F: FnOnce() -> i32 + std::panic::UnwindSafe>(f: F) -> i32 {
    match std::panic::catch_unwind(f) {
        Ok(v) => v,
        Err(_) => -1,
    }
}
