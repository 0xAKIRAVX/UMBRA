//! Minimal initiator-side WireGuard protocol (Noise_IKpsk2, no psk) —
//! ported line-by-line from the battle-tested Kotlin implementation
//! (wireguard-go semantics), byte-for-byte pinned by `tests/vectors.rs`.
//!
//! Layout:
//!   initiation: [type 4][sender 4][ephemeral 32][static 48][timestamp 28][mac1 16][mac2 16]
//!   response:   [type 4][sender 4][receiver 4][ephemeral 32][empty 16][mac1 16][mac2 16]
//!   transport:  [type 4][receiver 4][counter 8][aead(payload)]
//!
//! Reserved bytes (1..3) stay ZERO on every outgoing packet — live testing
//! against production WARP endpoints proved Cloudflare drops non-zero
//! reserved bytes silently (the v3.5 empirical fix, preserved).

use crate::crypto;
use std::sync::Mutex;

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const ZERO_NONCE: [u8; 12] = [0u8; 12];
const PSK: [u8; 32] = [0u8; 32]; // WARP: no preshared key

pub const MSG_INITIATION: u8 = 1;
pub const MSG_RESPONSE: u8 = 2;
pub const MSG_COOKIE_REPLY: u8 = 3;
pub const MSG_TRANSPORT: u8 = 4;

pub const INITIATION_SIZE: usize = 148;
pub const RESPONSE_SIZE: usize = 92;
pub const COOKIE_REPLY_SIZE: usize = 64;
pub const TRANSPORT_HEADER_SIZE: usize = 16;

fn initial_chain_key() -> [u8; 32] {
    crypto::blake2s(CONSTRUCTION)
}

fn initial_hash(chain_key: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(chain_key);
    buf.extend_from_slice(IDENTIFIER);
    crypto::blake2s(&buf)
}

fn mix_hash(h: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + data.len());
    buf.extend_from_slice(h);
    buf.extend_from_slice(data);
    crypto::blake2s(&buf)
}

fn mix_key(ck: &[u8; 32], data: &[u8]) -> [u8; 32] {
    // chainKey = HMAC(HMAC(ck, data), 0x01)
    let inner = crypto::hmac_blake2s(ck, &[data]);
    crypto::hmac_blake2s(&inner, &[&[1u8][..]])
}

fn kdf2(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let prk = crypto::hmac_blake2s(key, &[input]);
    let t0 = crypto::hmac_blake2s(&prk, &[&[1u8][..]]);
    let mut one_two = Vec::with_capacity(33);
    one_two.extend_from_slice(&t0);
    one_two.push(2);
    let t1 = crypto::hmac_blake2s(&prk, &[&one_two]);
    (t0, t1)
}

fn kdf3(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let prk = crypto::hmac_blake2s(key, &[input]);
    let t0 = crypto::hmac_blake2s(&prk, &[&[1u8][..]]);
    let mut t0_2 = Vec::with_capacity(33);
    t0_2.extend_from_slice(&t0);
    t0_2.push(2);
    let t1 = crypto::hmac_blake2s(&prk, &[&t0_2]);
    let mut t1_3 = Vec::with_capacity(33);
    t1_3.extend_from_slice(&t1);
    t1_3.push(3);
    let t2 = crypto::hmac_blake2s(&prk, &[&t1_3]);
    (t0, t1, t2)
}

// ------------------------------------------------------------- TAI64N ----

struct MarkState {
    last: Option<[u8; 12]>,
}

static TIMESTAMP_MARK: Mutex<MarkState> = Mutex::new(MarkState { last: None });

fn compare_ts(a: &[u8; 12], b: &[u8; 12]) -> std::cmp::Ordering {
    for i in 0..12 {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// In-place advance by 1 ns on a TAI64N pair (wireguard-go semantics).
fn bump_timestamp(ts: &mut [u8; 12]) {
    // nanos live at bytes 8..11 (BE u32)
    let nanos = u32::from_be_bytes([ts[8], ts[9], ts[10], ts[11]]);
    if nanos == 0xFFFF_FFFF {
        ts[8] = 0; ts[9] = 0; ts[10] = 0; ts[11] = 0;
        let secs = u32::from_be_bytes([ts[4], ts[5], ts[6], ts[7]]).wrapping_add(1);
        ts[4..8].copy_from_slice(&secs.to_be_bytes());
        if secs == 0 {
            let hi = u32::from_be_bytes([ts[0], ts[1], ts[2], ts[3]]).wrapping_add(1);
            ts[0..4].copy_from_slice(&hi.to_be_bytes());
        }
    } else {
        ts[8..12].copy_from_slice(&nanos.wrapping_add(1).to_be_bytes());
    }
}

/// TAI64N now — 12 bytes BE: (0x400000000000000a + unixSecs) || nanos.
/// Process-wide MONOTONIC with wireguard-go semantics (1 ns bumps) so a
/// restarted process reusing a persisted identity never presents a
/// timestamp the server already saw (silent anti-replay drops).
pub fn tai64n_now() -> [u8; 12] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let unix_secs = now.as_secs();
    let nanos = now.subsec_nanos();

    let mut out = [0u8; 12];
    let base: u64 = 0x4000_0000_0000_000a + unix_secs;
    out[0..8].copy_from_slice(&base.to_be_bytes());
    out[8..12].copy_from_slice(&nanos.to_be_bytes());

    let mut st = TIMESTAMP_MARK.lock().unwrap();
    if let Some(last) = st.last {
        if compare_ts(&out, &last) != std::cmp::Ordering::Greater {
            let mut bumped = last;
            bump_timestamp(&mut bumped);
            st.last = Some(bumped);
            return bumped;
        }
    }
    st.last = Some(out);
    out
}

/// Persists the current high-water mark (None before the first handshake).
pub fn save_mark() -> Option<[u8; 12]> {
    TIMESTAMP_MARK.lock().unwrap().last
}

/// Restores a persisted high-water mark (no-op on malformed input).
pub fn load_mark(mark: Option<[u8; 12]>) {
    if let Some(m) = mark {
        *TIMESTAMP_MARK.lock().unwrap() = MarkState { last: Some(m) };
    }
}

/// Drops the in-process mark (identity invalidated — fresh key, fresh clock).
pub fn reset_mark() {
    *TIMESTAMP_MARK.lock().unwrap() = MarkState { last: None };
}

// --------------------------------------------------------- handshake ----

/// Initiator-side state kept between the initiation and the response.
pub struct PendingHandshake {
    eph_priv: [u8; 32],
    hash: [u8; 32],
    chain_key: [u8; 32],
    pub sender_index: u32,
}

/// Established transport session (initiator side).
pub struct WgSession {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub our_index: u32,
    pub their_index: u32,
    send_counter: u64,
}

/// Builds a handshake initiation packet for `static_priv`/`static_pub` talking
/// to a responder whose long-term public key is `responder_pub`.
/// Returns Err(reason) on invalid key material (never panics — worker
/// threads must not die).
pub fn build_initiation(
    static_priv: &[u8; 32],
    static_pub: &[u8; 32],
    responder_pub: &[u8; 32],
    sender_index: u32,
    ephemeral_priv: &[u8; 32],
    timestamp: &[u8; 12],
) -> (Vec<u8>, Option<PendingHandshake>) {
    let eph_pub = crypto::x25519_base(ephemeral_priv);

    let init_ck = initial_chain_key();
    let init_h = initial_hash(&init_ck);

    let mut h = mix_hash(&init_h, responder_pub);
    let mut ck = mix_key(&init_ck, &eph_pub);
    h = mix_hash(&h, &eph_pub);

    // encrypted static
    let ee = match crypto::x25519_shared(ephemeral_priv, responder_pub) {
        Some(v) => v,
        None => return (Vec::new(), None), // invalid responder public key
    };
    let (ck1, k_static) = kdf2(&ck, &ee);
    ck = ck1;
    let static_ct = crypto::aead_seal(&k_static, &ZERO_NONCE, static_pub, &h);
    h = mix_hash(&h, &static_ct);

    // encrypted timestamp
    let ss = match crypto::x25519_shared(static_priv, responder_pub) {
        Some(v) => v,
        None => return (Vec::new(), None), // invalid keypair
    };
    let (ck2, k_ts) = kdf2(&ck, &ss);
    ck = ck2;
    let ts_ct = crypto::aead_seal(&k_ts, &ZERO_NONCE, timestamp, &h);
    h = mix_hash(&h, &ts_ct);

    let mut packet = vec![0u8; INITIATION_SIZE];
    packet[0..4].copy_from_slice(&(MSG_INITIATION as u32).to_le_bytes());
    packet[4..8].copy_from_slice(&sender_index.to_le_bytes());
    packet[8..40].copy_from_slice(&eph_pub);
    packet[40..88].copy_from_slice(&static_ct);
    packet[88..116].copy_from_slice(&ts_ct);

    // mac1 = keyed BLAKE2s-128 over the first 116 bytes, key = BLAKE2s("mac1----" || responderPub)
    let mut mac_key_input = Vec::with_capacity(39);
    mac_key_input.extend_from_slice(LABEL_MAC1);
    mac_key_input.extend_from_slice(responder_pub);
    let mac1_key = crypto::blake2s(&mac_key_input);
    let mac1 = crypto::blake2s_mac16(&mac1_key, &packet[0..116]);
    packet[116..132].copy_from_slice(&mac1);
    // mac2 stays zero (no cookie)

    (
        packet,
        Some(PendingHandshake { eph_priv: *ephemeral_priv, hash: h, chain_key: ck, sender_index }),
    )
}

/// Consumes a handshake response on the initiator side. Returns
/// (Some(session), "") on success or (None, reason).
pub fn consume_response(
    pending: &PendingHandshake,
    static_priv: &[u8; 32],
    data: &[u8],
) -> (Option<WgSession>, String) {
    if data.len() != RESPONSE_SIZE {
        return (None, format!("bad response length {}", data.len()));
    }
    // byte-wise type check (boringtun semantics) — a WARP response that
    // echoes junk into its reserved bytes is still a valid response
    if data[0] != MSG_RESPONSE {
        return (None, format!("not a response (type {})", le_u32(data, 0)));
    }
    let sender = le_u32(data, 4);
    let receiver = le_u32(data, 8);
    if receiver != pending.sender_index {
        return (None, "receiver index mismatch".to_string());
    }
    let their_eph: [u8; 32] = data[12..44].try_into().unwrap();
    let empty = &data[44..60];

    let mut h = mix_hash(&pending.hash, &their_eph);
    let mut ck = mix_key(&pending.chain_key, &their_eph);
    let ee = match crypto::x25519_shared(&pending.eph_priv, &their_eph) {
        Some(v) => v,
        None => return (None, "bad ephemeral".to_string()),
    };
    ck = mix_key(&ck, &ee);
    let se = match crypto::x25519_shared(static_priv, &their_eph) {
        Some(v) => v,
        None => return (None, "bad static DH".to_string()),
    };
    ck = mix_key(&ck, &se);
    let (ck1, tau, k) = kdf3(&ck, &PSK);
    ck = ck1;
    h = mix_hash(&h, &tau);
    match crypto::aead_open(&k, &ZERO_NONCE, empty, &h) {
        Some(_) => {}
        None => return (None, "response AEAD tag invalid".to_string()),
    }
    h = mix_hash(&h, empty);
    let (send_key, recv_key) = kdf2(&ck, &[]);
    (
        Some(WgSession {
            send_key,
            recv_key,
            our_index: pending.sender_index,
            their_index: sender,
            send_counter: 0,
        }),
        String::new(),
    )
}

impl WgSession {
    /// Seals `inner` (an IP packet) into a transport data packet.
    pub fn build_transport(&mut self, inner: &[u8]) -> Vec<u8> {
        let counter = self.send_counter;
        self.send_counter += 1;
        let padded_len = inner.len() + ((16 - (inner.len() % 16)) % 16);
        let mut padded = vec![0u8; padded_len];
        padded[..inner.len()].copy_from_slice(inner);

        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        let ct = crypto::aead_seal(&self.send_key, &nonce, &padded, &[]);
        let mut packet = Vec::with_capacity(TRANSPORT_HEADER_SIZE + ct.len());
        packet.extend_from_slice(&(MSG_TRANSPORT as u32).to_le_bytes());
        packet.extend_from_slice(&self.their_index.to_le_bytes());
        packet.extend_from_slice(&counter.to_le_bytes());
        packet.extend_from_slice(&ct);
        packet
    }

    /// Opens a transport data packet received from the responder.
    pub fn open_transport(&self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 32 { return None; }
        // byte-wise type check — receivers must ignore the reserved bytes
        if packet[0] != MSG_TRANSPORT { return None; }
        if le_u32(packet, 4) != self.our_index { return None; }
        let counter = le_u64(packet, 8);
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        crypto::aead_open(&self.recv_key, &nonce, &packet[16..], &[])
    }
}

// ------------------------------------------------------------ ICMP v4 ----

/// IPv4 + ICMP echo request (28 bytes) from `src` to `dst`.
pub fn icmp_echo_request(src: &[u8; 4], dst: &[u8; 4], ident: u16, seq: u16) -> Vec<u8> {
    let mut icmp = [0u8; 8];
    icmp[0] = 8;
    icmp[1] = 0;
    icmp[4..6].copy_from_slice(&ident.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq.to_be_bytes());
    let cksum = inet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&cksum.to_be_bytes());

    let total: u16 = 28;
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip[4..6].copy_from_slice(&ident.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    ip[8] = 64;
    ip[9] = 1; // ICMP
    ip[12..16].copy_from_slice(src);
    ip[16..20].copy_from_slice(dst);
    let ip_ck = inet_checksum(&ip);
    ip[10..12].copy_from_slice(&ip_ck.to_be_bytes());

    let mut out = Vec::with_capacity(28);
    out.extend_from_slice(&ip);
    out.extend_from_slice(&icmp);
    out
}

/// Validates that `inner` is an IPv4 ICMP echo reply for our ident/seq.
pub fn parse_echo_reply(inner: &[u8], ident: u16, seq: u16) -> bool {
    if inner.len() < 28 { return false; }
    let ver_ihl = inner[0];
    if ver_ihl >> 4 != 4 { return false; }
    let ihl = ((ver_ihl & 0x0F) as usize) * 4;
    if inner[9] != 1 { return false; } // not ICMP
    if inner.len() < ihl + 8 { return false; }
    let icmp = &inner[ihl..ihl + 8];
    let rid = u16::from_be_bytes([icmp[4], icmp[5]]);
    let rseq = u16::from_be_bytes([icmp[6], icmp[7]]);
    icmp[0] == 0 && icmp[1] == 0 && rid == ident && rseq == seq
}

/// RFC 1071 one's-complement checksum.
pub fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u64) << 8) | (data[i + 1] as u64);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u64) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    (!(sum as u16)) & 0xFFFF
}

fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn le_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}
