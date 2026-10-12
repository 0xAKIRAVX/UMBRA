//! Pure-Rust crypto primitives required by the WireGuard handshake:
//! X25519 / BLAKE2s / HMAC-BLAKE2s / ChaCha20-Poly1305.
//!
//! Zero third-party dependencies (std only) so the crate cross-compiles for
//! every Android ABI with a bare NDK clang. Every primitive is pinned by
//! differential test vectors (`tests/vectors.rs`) generated from the
//! battle-tested Kotlin implementation plus RFC 7748 / RFC 8439 vectors.
//!
//! Constant-time hardening is intentionally traded away (same decision as the
//! Kotlin implementation this port replaces): the scanner only protects
//! ephemeral, per-probe keys.

// ============================================================ X25519 ====
// Field arithmetic mod 2^255-19 over 51-bit limbs (u64 x 5), u128 products.

pub type Fe = [u64; 5];

const M51: u64 = (1u64 << 51) - 1;
/// p = 2^255-19 in 51-bit limbs.
const P_LIMBS: Fe = [
    0x7_FFFF_FFFF_FFED,
    0x7_FFFF_FFFF_FFFF,
    0x7_FFFF_FFFF_FFFF,
    0x7_FFFF_FFFF_FFFF,
    0x7_FFFF_FFFF_FFFF,
];

/// Single carry-reduction pass (dalek-style): limbs < 2^64 in, < 2^52 out.
fn fe_reduce(mut l: Fe) -> Fe {
    let c0 = l[0] >> 51; l[0] &= M51;
    let c1 = l[1] >> 51; l[1] &= M51;
    let c2 = l[2] >> 51; l[2] &= M51;
    let c3 = l[3] >> 51; l[3] &= M51;
    let c4 = l[4] >> 51; l[4] &= M51;
    l[0] += c4 * 19;
    l[1] += c0;
    l[2] += c1;
    l[3] += c2;
    l[4] += c3;
    l
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u64; 5];
    for i in 0..5 { r[i] = a[i] + b[i]; }
    fe_reduce(r)
}

/// a - b mod p (adds 2p first so every limb stays positive).
fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u64; 5];
    for i in 0..5 {
        // 2 * p limbs; guaranteed > any reduced b limb.
        let two_p = P_LIMBS[i].wrapping_mul(2);
        r[i] = a[i] + two_p - b[i];
    }
    fe_reduce(r)
}

fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    #[inline(always)]
    fn m(x: u64, y: u64) -> u128 { (x as u128) * (y as u128) }

    let b1_19 = b[1] * 19;
    let b2_19 = b[2] * 19;
    let b3_19 = b[3] * 19;
    let b4_19 = b[4] * 19;

    // c_k = direct pairs (i+j=k) + 19*(pairs with i+j=k+5), since x^5 ≡ 19
    let c0 = m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19) + m(a[1], b4_19);
    let c1 = m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2_19) + m(a[3], b3_19) + m(a[2], b4_19);
    let c2 = m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3_19) + m(a[3], b4_19);
    let c3 = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4_19);
    let c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);

    let c = [c0, c1, c2, c3, c4];
    let mut r = [0u64; 5];
    let mut carry: u128 = 0;
    for i in 0..5 {
        let v = c[i] + carry;
        r[i] = (v as u64) & M51;
        carry = v >> 51;
    }
    // bits above limb 4 are bits >= 255: fold x 19 into limb 0 (u128 to stay overflow-safe)
    let v0 = (r[0] as u128) + carry * 19;
    r[0] = (v0 as u64) & M51;
    let mut c2r: u128 = v0 >> 51;
    for i in 1..5 {
        let v = (r[i] as u128) + c2r;
        r[i] = v as u64 & M51;
        c2r = v >> 51;
    }
    if c2r != 0 {
        r[0] += (c2r as u64) * 19;
    }
    fe_reduce(r)
}

fn fe_square(a: &Fe) -> Fe { fe_mul(a, a) }

fn fe_from_bytes(bytes: &[u8; 32]) -> Fe {
    let load64 = |i: usize| -> u64 {
        let mut v = 0u64;
        for k in 0..8 { v |= (bytes[i + k] as u64) << (8 * k); }
        v
    };
    let l0 = load64(0) & M51;
    let l1 = (load64(6) >> 3) & M51;
    let l2 = (load64(12) >> 6) & M51;
    let l3 = (load64(19) >> 1) & M51;
    let l4 = (load64(24) >> 12) & M51;
    [l0, l1, l2, l3, l4]
}

/// Fully canonicalizes: repeats the carry pass until every limb < 2^51
/// (the single dalek pass leaves limbs up to ~2^52, which would corrupt the
/// byte packing in [fe_to_bytes]). Converges in <= 6 passes.
fn fe_canonicalize(mut l: Fe) -> Fe {
    for _ in 0..10 {
        if l.iter().all(|&x| x < (1u64 << 51)) {
            return l;
        }
        l = fe_reduce(l);
    }
    l
}

/// Fully-reduced canonical to_bytes (subtracts p once when value >= p).
fn fe_to_bytes(limbs: &Fe) -> [u8; 32] {
    let mut l = fe_canonicalize(*limbs);
    // conditional subtract p
    let mut ge = true;
    for i in (0..5).rev() {
        if l[i] > P_LIMBS[i] { break; }
        if l[i] < P_LIMBS[i] { ge = false; break; }
    }
    if ge {
        let mut borrow = 0i64;
        for i in 0..5 {
            let d = l[i] as i64 - P_LIMBS[i] as i64 - borrow;
            if d < 0 { l[i] = (d + (1i64 << 51)) as u64; borrow = 1; }
            else { l[i] = d as u64; borrow = 0; }
        }
    }
    let mut out = [0u8; 32];
    let w0 = l[0] | (l[1] << 51);
    let w1 = (l[1] >> 13) | (l[2] << 38);
    let w2 = (l[2] >> 26) | (l[3] << 25);
    let w3 = (l[3] >> 39) | (l[4] << 12);
    let words = [w0, w1, w2, w3];
    for (wi, w) in words.iter().enumerate() {
        for k in 0..8 {
            out[wi * 8 + k] = ((w >> (8 * k)) & 0xFF) as u8;
        }
    }
    out
}

/// x^(p-2) mod p via plain square-and-multiply over the bits of p-2.
fn fe_invert(a: &Fe) -> Fe {
    // p-2 = 2^255 - 21, big-endian bits: 0x7fff...ffeb
    let exp_bytes_be: [u8; 32] = {
        let mut b = [0xFFu8; 32];
        b[0] = 0x7F;
        b[31] = 0xEB;
        b
    };
    let mut result: Fe = [1, 0, 0, 0, 0];
    for byte in exp_bytes_be.iter() {
        for bit in (0..8).rev() {
            result = fe_square(&result);
            if (byte >> bit) & 1 == 1 {
                result = fe_mul(&result, a);
            }
        }
    }
    result
}

/// RFC 7748 X25519(scalar, u). Both inputs and the output are 32 LE bytes.
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let mut u_bytes = *u;
    u_bytes[31] &= 127;
    let x1 = fe_from_bytes(&u_bytes);

    let one: Fe = [1, 0, 0, 0, 0];
    let zero: Fe = [0, 0, 0, 0, 0];
    let a24: Fe = [121665, 0, 0, 0, 0];

    let mut x2 = one;
    let mut z2 = zero;
    let mut x3 = x1;
    let mut z3 = one;
    let mut swap: u8 = 0;

    for t in (0..=254).rev() {
        let kt = (k[t / 8] >> (t % 8)) & 1;
        swap ^= kt;
        if swap == 1 {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
        }
        swap = kt;

        let a = fe_add(&x2, &z2);
        let aa = fe_square(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_square(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        let dacb = fe_add(&da, &cb);
        x3 = fe_square(&dacb);
        let damb = fe_sub(&da, &cb);
        let damb2 = fe_square(&damb);
        z3 = fe_mul(&x1, &damb2);
        x2 = fe_mul(&aa, &bb);
        let ae = fe_mul(&a24, &e);
        let aae = fe_add(&aa, &ae);
        z2 = fe_mul(&e, &aae);
    }
    if swap == 1 {
        std::mem::swap(&mut x2, &mut x3);
        std::mem::swap(&mut z2, &mut z3);
    }
    let zinv = fe_invert(&z2);
    let out = fe_mul(&x2, &zinv);
    fe_to_bytes(&out)
}

pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut u = [0u8; 32];
    u[0] = 9;
    x25519(scalar, &u)
}

pub fn clamp_scalar(k: &[u8; 32]) -> [u8; 32] {
    let mut out = *k;
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

/// DH — returns None when the shared secret is all-zero (invalid public key).
pub fn x25519_shared(priv_: &[u8; 32], peer_pub: &[u8; 32]) -> Option<[u8; 32]> {
    let ss = x25519(priv_, peer_pub);
    if ss.iter().all(|&b| b == 0) { None } else { Some(ss) }
}

/// Cryptographically-secure random bytes from the OS (/dev/urandom).
pub fn os_random(buf: &mut [u8]) -> bool {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .is_ok()
}

// ============================================================ BLAKE2s ====
// RFC 7693, unkeyed and keyed (16-byte keyed MAC mode used for mac1).

const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

pub struct Blake2s {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    t: u64,
    done: bool,
}

impl Blake2s {
    /// Streaming BLAKE2s-256, optionally keyed (key <= 32 bytes).
    pub fn new(key: &[u8]) -> Blake2s {
        let mut h = BLAKE2S_IV;
        // parameter block: digest length 32, key length, fanout 1, depth 1
        let mut params: u32 = 32 | (1 << 16) | (1 << 24);
        params |= (key.len() as u32) << 8;
        h[0] ^= params;
        let mut s = Blake2s { h, buf: [0u8; 64], buf_len: 0, t: 0, done: false };
        if !key.is_empty() {
            let mut block = [0u8; 64];
            block[..key.len()].copy_from_slice(key);
            s.update(&block);
        }
        s
    }

    pub fn update(&mut self, data: &[u8]) {
        assert!(!self.done, "blake2s already finalized");
        let mut i = 0;
        while i < data.len() {
            if self.buf_len == 64 {
                self.t += 64;
                let block = self.buf;
                self.compress(&block, false);
                self.buf_len = 0;
            }
            let take = std::cmp::min(64 - self.buf_len, data.len() - i);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[i..i + take]);
            self.buf_len += take;
            i += take;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        assert!(!self.done, "blake2s already finalized");
        self.done = true;
        self.t += self.buf_len as u64;
        for b in self.buf[self.buf_len..].iter_mut() { *b = 0; }
        let block = self.buf;
        self.compress(&block, true);
        let mut out = [0u8; 32];
        for w in 0..8 {
            for byte in 0..4 {
                out[w * 4 + byte] = ((self.h[w] >> (8 * byte)) & 0xFF) as u8;
            }
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64], is_last: bool) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = (block[4 * i] as u32)
                | ((block[4 * i + 1] as u32) << 8)
                | ((block[4 * i + 2] as u32) << 16)
                | ((block[4 * i + 3] as u32) << 24);
        }
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&BLAKE2S_IV);
        v[12] ^= self.t as u32;
        v[13] ^= (self.t >> 32) as u32;
        if is_last { v[14] ^= 0xFFFF_FFFF; }

        macro_rules! g {
            ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {
                v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add($mx);
                v[$d] = (v[$d] ^ v[$a]).rotate_right(16);
                v[$c] = v[$c].wrapping_add(v[$d]);
                v[$b] = (v[$b] ^ v[$c]).rotate_right(12);
                v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add($my);
                v[$d] = (v[$d] ^ v[$a]).rotate_right(8);
                v[$c] = v[$c].wrapping_add(v[$d]);
                v[$b] = (v[$b] ^ v[$c]).rotate_right(7);
            };
        }

        for r in 0..10 {
            let s = &SIGMA[r];
            g!(0, 4, 8, 12, m[s[0]], m[s[1]]);
            g!(1, 5, 9, 13, m[s[2]], m[s[3]]);
            g!(2, 6, 10, 14, m[s[4]], m[s[5]]);
            g!(3, 7, 11, 15, m[s[6]], m[s[7]]);
            g!(0, 5, 10, 15, m[s[8]], m[s[9]]);
            g!(1, 6, 11, 12, m[s[10]], m[s[11]]);
            g!(2, 7, 8, 13, m[s[12]], m[s[13]]);
            g!(3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

/// One-shot BLAKE2s (digestSize 32).
pub fn blake2s(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2s::new(&[]);
    h.update(data);
    h.finalize()
}

/// One-shot keyed BLAKE2s with a 16-byte digest (WireGuard mac1).
pub fn blake2s_mac16(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut st = Blake2s16::new(key);
    st.update(data);
    st.finalize()
}

/// HMAC with BLAKE2s-256 (block size 64) — the WireGuard KDF primitive.
pub fn hmac_blake2s(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    hmac_blake2s_raw(key, &concat(parts))
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts { out.extend_from_slice(p); }
    out
}

fn hmac_blake2s_raw(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&blake2s(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }
    let mut inner = Blake2s::new(&[]);
    inner.update(&ipad);
    inner.update(data);
    let ih = inner.finalize();
    let mut outer = Blake2s::new(&[]);
    outer.update(&opad);
    outer.update(&ih);
    outer.finalize()
}

/// Keyed BLAKE2s producing a 16-byte digest (WireGuard MAC1 form).
struct Blake2s16 {
    inner: Blake2s,
}

impl Blake2s16 {
    fn new(key: &[u8]) -> Self {
        // BLAKE2s with digest length 16: parameter word differs from the
        // 32-byte streaming struct, so we build a dedicated state.
        let mut h = BLAKE2S_IV;
        let mut params: u32 = 16 | (1 << 16) | (1 << 24);
        params |= (key.len() as u32) << 8;
        h[0] ^= params;
        // Re-use the 32-byte struct by inlining the same compress; simplest
        // correct path: run the standard struct but keep our own h copy.
        let mut st = Blake2s { h, buf: [0u8; 64], buf_len: 0, t: 0, done: false };
        if !key.is_empty() {
            let mut block = [0u8; 64];
            block[..key.len()].copy_from_slice(key);
            st.update(&block);
        }
        Blake2s16 { inner: st }
    }

    fn update(&mut self, data: &[u8]) { self.inner.update(data); }

    fn finalize(mut self) -> [u8; 16] {
        // finalize with digest length 16
        let mut st = self.inner;
        st.done = true;
        st.t += st.buf_len as u64;
        for b in st.buf[st.buf_len..].iter_mut() { *b = 0; }
        st.compress(&st.buf.clone(), true);
        let mut out = [0u8; 16];
        for w in 0..4 {
            for byte in 0..4 {
                out[w * 4 + byte] = ((st.h[w] >> (8 * byte)) & 0xFF) as u8;
            }
        }
        out
    }
}

// ================================================= ChaCha20-Poly1305 ====
// RFC 8439 AEAD (WireGuard handshake + transport).

const CHACHA_CONST: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

fn le_u32(b: &[u8], off: usize) -> u32 {
    (b[off] as u32) | ((b[off + 1] as u32) << 8)
        | ((b[off + 2] as u32) << 16) | ((b[off + 3] as u32) << 24)
}

fn chacha_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u32; 16] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&CHACHA_CONST);
    for i in 0..8 { state[4 + i] = le_u32(key, 4 * i); }
    state[12] = counter;
    state[13] = le_u32(nonce, 0);
    state[14] = le_u32(nonce, 4);
    state[15] = le_u32(nonce, 8);

    let mut w = state;
    macro_rules! qr {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            w[$a] = w[$a].wrapping_add(w[$b]);
            w[$d] = (w[$d] ^ w[$a]).rotate_left(16);
            w[$c] = w[$c].wrapping_add(w[$d]);
            w[$b] = (w[$b] ^ w[$c]).rotate_left(12);
            w[$a] = w[$a].wrapping_add(w[$b]);
            w[$d] = (w[$d] ^ w[$a]).rotate_left(8);
            w[$c] = w[$c].wrapping_add(w[$d]);
            w[$b] = (w[$b] ^ w[$c]).rotate_left(7);
        };
    }
    for _ in 0..10 {
        qr!(0, 4, 8, 12); qr!(1, 5, 9, 13); qr!(2, 6, 10, 14); qr!(3, 7, 11, 15);
        qr!(0, 5, 10, 15); qr!(1, 6, 11, 12); qr!(2, 7, 8, 13); qr!(3, 4, 9, 14);
    }
    let mut out = [0u32; 16];
    for i in 0..16 { out[i] = w[i].wrapping_add(state[i]); }
    out
}

fn chacha_xor(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
    let mut block_idx: u32 = 1;
    let mut offset = 0;
    while offset < data.len() {
        let ks = chacha_block(key, nonce, block_idx);
        block_idx = block_idx.wrapping_add(1);
        let n = std::cmp::min(64, data.len() - offset);
        for i in 0..n {
            let kb = (ks[i / 4] >> (8 * (i % 4))) & 0xFF;
            data[offset + i] ^= kb as u8;
        }
        offset += n;
    }
}

fn poly1305_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block = chacha_block(key, nonce, 0);
    let mut pk = [0u8; 32];
    for i in 0..8 {
        let w = block[i];
        pk[4 * i] = (w & 0xFF) as u8;
        pk[4 * i + 1] = ((w >> 8) & 0xFF) as u8;
        pk[4 * i + 2] = ((w >> 16) & 0xFF) as u8;
        pk[4 * i + 3] = ((w >> 24) & 0xFF) as u8;
    }
    pk
}

/// Poly1305 (donna-32 style: 5 x 26-bit limbs) — returns the 16-byte tag.
fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let le32 = |b: &[u8], off: usize| -> u32 { le_u32(b, off) };

    let mut r = [0u32; 5];
    let mut h = [0u32; 5];
    let mut pad = [0u32; 4];

    // r clamp (poly1305-donna-32 exact masks)
    r[0] = (le32(key, 0)) & 0x3FF_FFFF;
    r[1] = (le32(key, 3) >> 2) & 0x3F_FFF03;
    r[2] = (le32(key, 6) >> 4) & 0x3F_FC0FF;
    r[3] = (le32(key, 9) >> 6) & 0x3F_03FFF;
    r[4] = (le32(key, 12) >> 8) & 0x00F_FFFF;

    for i in 0..4 {
        pad[i] = le32(key, 16 + 4 * i);
    }

    // h + s (5th limb for the 2^128 bit), multiply, reduce
    let mut leftover = msg.len() % 16;
    let nblocks = msg.len() / 16;
    for bi in 0..nblocks {
        let blk = &msg[bi * 16..bi * 16 + 16];
        h[0] = h[0].wrapping_add(le32(blk, 0) & 0x3FF_FFFF);
        h[1] = h[1].wrapping_add((le32(blk, 3) >> 2) & 0x3FF_FFFF);
        h[2] = h[2].wrapping_add((le32(blk, 6) >> 4) & 0x3FF_FFFF);
        h[3] = h[3].wrapping_add((le32(blk, 9) >> 6) & 0x3FF_FFFF);
        h[4] = h[4].wrapping_add((le32(blk, 12) >> 8) | (1 << 24));
        poly1305_mul(&mut h, &r);
    }
    if leftover > 0 {
        let mut blk = [0u8; 16];
        blk[..leftover].copy_from_slice(&msg[nblocks * 16..]);
        blk[leftover] = 1;
        h[0] = h[0].wrapping_add(le32(&blk, 0) & 0x3FF_FFFF);
        h[1] = h[1].wrapping_add((le32(&blk, 3) >> 2) & 0x3FF_FFFF);
        h[2] = h[2].wrapping_add((le32(&blk, 6) >> 4) & 0x3FF_FFFF);
        h[3] = h[3].wrapping_add((le32(&blk, 9) >> 6) & 0x3FF_FFFF);
        // NO 2^128 bit on a partial block: the 0x01 marker rides at byte
        // `leftover` (<= 15), which the standard extraction above already
        // captures — (1<<24) would add a phantom 2^128.
        h[4] = h[4].wrapping_add(le32(&blk, 12) >> 8);
        poly1305_mul(&mut h, &r);
    }

    // fully carry h (donna final)
    let mut c = h[1] >> 26; h[1] &= 0x3FF_FFFF;
    h[2] = h[2].wrapping_add(c); c = h[2] >> 26; h[2] &= 0x3FF_FFFF;
    h[3] = h[3].wrapping_add(c); c = h[3] >> 26; h[3] &= 0x3FF_FFFF;
    h[4] = h[4].wrapping_add(c); c = h[4] >> 26; h[4] &= 0x3FF_FFFF;
    h[0] = h[0].wrapping_add(c * 5); c = h[0] >> 26; h[0] &= 0x3FF_FFFF;
    h[1] = h[1].wrapping_add(c);

    // compute h + -p
    let mut g = [0u32; 5];
    g[0] = h[0].wrapping_add(5); c = g[0] >> 26; g[0] &= 0x3FF_FFFF;
    g[1] = h[1].wrapping_add(c); c = g[1] >> 26; g[1] &= 0x3FF_FFFF;
    g[2] = h[2].wrapping_add(c); c = g[2] >> 26; g[2] &= 0x3FF_FFFF;
    g[3] = h[3].wrapping_add(c); c = g[3] >> 26; g[3] &= 0x3FF_FFFF;
    g[4] = h[4].wrapping_add(c).wrapping_sub(1 << 26);

    // select h if h < p, or h + -p if h >= p
    let mask = (g[4] >> 31).wrapping_sub(1);
    for i in 0..5 {
        g[i] &= mask;
    }
    let nmask = !mask;
    for i in 0..5 {
        h[i] = (h[i] & nmask) | g[i];
    }

    // h = h % (2^128)
    h[0] = ((h[0]) | (h[1] << 26)) & 0xFFFF_FFFF;
    h[1] = ((h[1] >> 6) | (h[2] << 20)) & 0xFFFF_FFFF;
    h[2] = ((h[2] >> 12) | (h[3] << 14)) & 0xFFFF_FFFF;
    h[3] = ((h[3] >> 18) | (h[4] << 8)) & 0xFFFF_FFFF;

    // mac = (h + pad) % (2^128)
    let mut f: u64 = (h[0] as u64) + (pad[0] as u64);
    h[0] = f as u32;
    f = (h[1] as u64) + (pad[1] as u64) + (f >> 32);
    h[1] = f as u32;
    f = (h[2] as u64) + (pad[2] as u64) + (f >> 32);
    h[2] = f as u32;
    f = (h[3] as u64) + (pad[3] as u64) + (f >> 32);
    h[3] = f as u32;

    let mut tag = [0u8; 16];
    for i in 0..4 {
        tag[4 * i] = (h[i] & 0xFF) as u8;
        tag[4 * i + 1] = ((h[i] >> 8) & 0xFF) as u8;
        tag[4 * i + 2] = ((h[i] >> 16) & 0xFF) as u8;
        tag[4 * i + 3] = ((h[i] >> 24) & 0xFF) as u8;
    }
    tag
}

fn poly1305_mul(h: &mut [u32; 5], r: &[u32; 5]) {
    let s = [
        r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5,
    ];
    let (r0, r1, r2, r3, r4) = (r[0] as u64, r[1] as u64, r[2] as u64, r[3] as u64, r[4] as u64);
    let (s1, s2, s3, s4) = (s[0] as u64, s[1] as u64, s[2] as u64, s[3] as u64);
    let (h0, h1, h2, h3, h4) = (h[0] as u64, h[1] as u64, h[2] as u64, h[3] as u64, h[4] as u64);

    let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

    let mut c: u64;
    let mut hh = [0u32; 5];

    c = d0 >> 26; hh[0] = (d0 as u32) & 0x3FF_FFFF;
    let d1 = d1 + c; c = d1 >> 26; hh[1] = (d1 as u32) & 0x3FF_FFFF;
    let d2 = d2 + c; c = d2 >> 26; hh[2] = (d2 as u32) & 0x3FF_FFFF;
    let d3 = d3 + c; c = d3 >> 26; hh[3] = (d3 as u32) & 0x3FF_FFFF;
    let d4 = d4 + c; c = d4 >> 26; hh[4] = (d4 as u32) & 0x3FF_FFFF;

    hh[0] = hh[0].wrapping_add((c as u32) * 5);
    let cb = hh[1] >> 26; hh[1] &= 0x3FF_FFFF;
    hh[2] = hh[2].wrapping_add(cb);
    *h = hh;
}

fn mac_data(aad: &[u8], ct: &[u8]) -> Vec<u8> {
    let pad = |n: usize| (16 - (n % 16)) % 16;
    let mut out = Vec::with_capacity(aad.len() + ct.len() + 32 + pad(aad.len()) + pad(ct.len()));
    out.extend_from_slice(aad);
    for _ in 0..pad(aad.len()) { out.push(0); }
    out.extend_from_slice(ct);
    for _ in 0..pad(ct.len()) { out.push(0); }
    out.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    out.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    out
}

/// AEAD seal: returns ct || tag (plaintext len + 16).
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut ct = plaintext.to_vec();
    chacha_xor(key, nonce, &mut ct);
    let tag = poly1305(&poly1305_key(key, nonce), &mac_data(aad, &ct));
    let mut out = ct;
    out.extend_from_slice(&tag);
    out
}

/// AEAD open: verifies the tag; returns None on mismatch.
pub fn aead_open(key: &[u8; 32], nonce: &[u8; 12], ct_and_tag: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if ct_and_tag.len() < 16 { return None; }
    let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);
    let expect = poly1305(&poly1305_key(key, nonce), &mac_data(aad, ct));
    // constant-time-ish compare
    let mut diff = 0u8;
    for i in 0..16 { diff |= tag[i] ^ expect[i]; }
    if diff != 0 { return None; }
    let mut pt = ct.to_vec();
    chacha_xor(key, nonce, &mut pt);
    Some(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn rfc7748_x25519() {
        // RFC 7748 section 5.2 test vector 1
        let scalar: [u8; 32] = hex::decode_vec("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4").try_into().unwrap();
        let u: [u8; 32] = hex::decode_vec("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c").try_into().unwrap();
        let out = x25519(&scalar, &u);
        assert_eq!(hex(&out), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    }

    #[test]
    fn rfc7748_base() {
        // RFC 7748 section 6.1 keypairs + shared-secret agreement
        let priv_a: [u8; 32] = hex::decode_vec("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").try_into().unwrap();
        let pub_a = x25519_base(&priv_a);
        assert_eq!(hex(&pub_a), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let priv_c: [u8; 32] = hex::decode_vec("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb").try_into().unwrap();
        let pub_c = x25519_base(&priv_c);
        assert_eq!(hex(&pub_c), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = x25519(&priv_c, &pub_a);
        let shared2 = x25519(&priv_a, &pub_c);
        assert_eq!(hex(&shared), hex(&shared2));
        assert_eq!(hex(&shared), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    }

    #[test]
    fn blake2s_rfc7693() {
        // RFC 7693 appendix B: blake2s("abc")
        let d = b"abc";
        let h = blake2s(d);
        assert_eq!(hex(&h), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    }

    #[test]
    fn aead_roundtrip() {
        let key: [u8; 32] = [7u8; 32];
        let nonce: [u8; 12] = [1u8; 12];
        for (pt, aad) in [
            (vec![0u8; 0], vec![0u8; 0]),
            (vec![42u8; 26], vec![5u8; 12]),
            (vec![9u8; 128], vec![3u8; 64]),
        ] {
            let ct = aead_seal(&key, &nonce, &pt, &aad);
            let back = aead_open(&key, &nonce, &ct, &aad).expect("tag must verify");
            assert_eq!(back, pt);
            // tampered tag must fail
            let mut bad = ct.clone();
            let n = bad.len();
            bad[n - 1] ^= 1;
            assert!(aead_open(&key, &nonce, &bad, &aad).is_none());
        }
    }
}

/// Tiny internal hex helpers used by tests and debug output.
pub mod hex {
    pub fn decode_vec(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != '\\').collect();
        (0..clean.len() / 2)
            .map(|i| u8::from_str_radix(&clean[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    pub fn encode(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b { s.push_str(&format!("{:02x}", x)); }
        s
    }
}

#[cfg(test)]
mod debug_field_tests {
    use super::*;

    fn fe(v: u64) -> Fe { [v, 0, 0, 0, 0] }

    #[test]
    fn field_mul_small() {
        assert_eq!(fe_mul(&fe(2), &fe(3)), fe(6));
        assert_eq!(fe_mul(&fe(121665), &fe(121666))[0], 121665u64 * 121666u64);
    }

    #[test]
    fn field_sub_small() {
        // compare canonical VALUES — the limb arrays are weakly reduced
        let b = |l: &Fe| fe_to_bytes(l);
        assert_eq!(b(&fe_sub(&fe(5), &fe(3))), b(&fe(2)));
        // 0 - 1 = p - 1
        let p_minus_1 = fe_sub(&fe(0), &fe(1));
        assert_eq!(b(&p_minus_1), b(&[M51 - 19, M51, M51, M51, M51]));
    }

    #[test]
    fn field_add_sub_inverse_roundtrip() {
        // (a + b) - b == a (canonical values)
        let b = |l: &Fe| fe_to_bytes(l);
        let a = fe(123456789012345678u64 % M51);
        let bb = fe(98765432109876543u64 % M51);
        let sum = fe_add(&a, &bb);
        assert_eq!(b(&fe_sub(&sum, &bb)), b(&a));
    }

    #[test]
    fn field_invert_roundtrip() {
        let b = |l: &Fe| fe_to_bytes(l);
        let v = fe(123456789123456789u64 % M51);
        let inv = fe_invert(&v);
        assert_eq!(b(&fe_mul(&v, &inv)), b(&fe(1)));
        assert_eq!(b(&fe_invert(&fe(1))), b(&fe(1)));
    }

    #[test]
    fn field_mul_mod() {
        let b = |l: &Fe| fe_to_bytes(l);
        // (p-1) * (p-1) mod p = 1; p * p mod p = 0
        let pm1 = [M51 - 19, M51, M51, M51, M51];
        assert_eq!(b(&fe_mul(&pm1, &pm1)), b(&fe(1)));
        let p = [M51 - 18, M51, M51, M51, M51];
        assert_eq!(b(&fe_mul(&p, &p)), b(&fe(0)));
    }

    #[test]
    fn fe_bytes_roundtrip() {
        let mut b = [0u8; 32];
        for i in 0..32 { b[i] = (i as u8) * 7 + 1; }
        b[31] &= 127;
        let l = fe_from_bytes(&b);
        let back = fe_to_bytes(&l);
        assert_eq!(back, b);
    }
}

#[cfg(test)]
mod poly_probe {
    use super::*;
    #[test]
    fn rfc8439_poly1305() {
        let key: [u8; 32] = hex::decode_vec(
            "85d6be7857556d337f4452fe42d506a8010380e1e3fb0db2fd4abff6af4149c5",
        ).try_into().unwrap();
        // note: deliberately using the vector below
        let key2: [u8; 32] = hex::decode_vec(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        ).try_into().unwrap();
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305(&key2, msg);
        assert_eq!(crate::crypto::hex::encode(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }
}
