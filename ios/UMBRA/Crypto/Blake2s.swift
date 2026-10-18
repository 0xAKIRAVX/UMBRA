import Foundation

/// Pure-Swift BLAKE2s (RFC 7693) — ported 1:1 from UMBRA's Kotlin WgCrypto,
/// which is itself differential-tested against the live-verified Python
/// reference (warp_vectors.json). Apple's CryptoKit exposes no BLAKE2s, so the
/// scanner carries this self-contained implementation.
///
/// Supports unkeyed + keyed digests of 1..32 bytes (the 16-byte keyed MAC mode
/// is exactly what WireGuard's mac1 field needs) and a streaming variant for
/// HMAC's two-pass inner/outer structure.
enum Blake2s {

    private static let iv: [UInt32] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]

    private static let sigma: [[Int]] = [
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
    ]

    /// BLAKE2s with optional key and variable digest length (1..32).
    static func hash(_ data: [UInt8], key: [UInt8] = [], digestSize: Int = 32) -> [UInt8] {
        precondition(digestSize >= 1 && digestSize <= 32, "digest size out of range")
        precondition(key.count <= 32, "key too long")

        var h = iv
        h[0] ^= UInt32(digestSize) | (UInt32(key.count) << 8) | (1 << 16) | (1 << 24)

        var stream = Stream(state: h, digestSize: digestSize)
        if !key.isEmpty {
            var keyBlock = [UInt8](repeating: 0, count: 64)
            keyBlock.replaceSubrange(0..<key.count, with: key)
            stream.update(keyBlock)
        }
        stream.update(data)
        return stream.final()
    }

    /// HMAC with BLAKE2s-256 as inner/outer hash (block size 64).
    /// Mirrors the Kotlin `hmacBlake2s` — itself differential-tested.
    static func hmac(key: [UInt8], data: [UInt8]) -> [UInt8] {
        var k = [UInt8](repeating: 0, count: 64)
        if key.count > 64 {
            let hashed = Blake2s.hash(key)
            k.replaceSubrange(0..<32, with: hashed)
        } else {
            k.replaceSubrange(0..<key.count, with: key)
        }
        var ipad = [UInt8](repeating: 0x36, count: 64)
        var opad = [UInt8](repeating: 0x5C, count: 64)
        for i in 0..<64 {
            ipad[i] ^= k[i]
            opad[i] ^= k[i]
        }
        let inner = Blake2s.hash(ipad + data)
        return Blake2s.hash(opad + inner)
    }

    /// Streaming BLAKE2s with configurable digest length (1..32).
    final class Stream {
        private var h: [UInt32]
        private let digestSize: Int
        private var buf = [UInt8](repeating: 0, count: 64)
        private var bufLen = 0
        private var t: UInt64 = 0
        private var done = false

        init(state: [UInt32]? = nil, digestSize: Int = 32) {
            self.digestSize = digestSize
            if let state = state {
                h = state
            } else {
                h = Blake2s.iv
                h[0] ^= 32 | (0 << 8) | (1 << 16) | (1 << 24)
            }
        }

        func update(_ x: [UInt8]) {
            precondition(!done, "already digested")
            var i = 0
            while i < x.count {
                if bufLen == 64 {
                    t += 64
                    compress(buf, isLast: false)
                    bufLen = 0
                }
                let take = Swift.min(64 - bufLen, x.count - i)
                buf.replaceSubrange(bufLen..<(bufLen + take), with: x[i..<(i + take)])
                bufLen += take
                i += take
            }
        }

        func final() -> [UInt8] {
            precondition(!done, "already digested")
            done = true
            t += UInt64(bufLen)
            if bufLen < 64 {
                for i in bufLen..<64 { buf[i] = 0 }
            }
            compress(buf, isLast: true)
            let outLen = Swift.min(digestSize, 32)
            var out = [UInt8](repeating: 0, count: outLen)
            var o = 0
            for w in 0..<8 {
                for byteIdx in 0..<4 {
                    if o < outLen {
                        out[o] = UInt8(truncatingIfNeeded: (h[w] >> (8 * UInt32(byteIdx))) & 0xFF)
                        o += 1
                    }
                }
            }
            return out
        }

        private func compress(_ block: [UInt8], isLast: Bool) {
            var m = [UInt32](repeating: 0, count: 16)
            for i in 0..<16 {
                m[i] = UInt32(block[4 * i])
                    | (UInt32(block[4 * i + 1]) << 8)
                    | (UInt32(block[4 * i + 2]) << 16)
                    | (UInt32(block[4 * i + 3]) << 24)
            }
            var v = [UInt32](repeating: 0, count: 16)
            v.replaceSubrange(0..<8, with: h)
            v.replaceSubrange(8..<16, with: Blake2s.iv)
            v[12] ^= UInt32(truncatingIfNeeded: t)
            v[13] ^= UInt32(truncatingIfNeeded: t >> 32)
            if isLast { v[14] ^= 0xFFFFFFFF }

            func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ mx: UInt32, _ my: UInt32) {
                v[a] = v[a] &+ v[b] &+ mx
                v[d] = (v[d] ^ v[a]).rotr(16)
                v[c] = v[c] &+ v[d]
                v[b] = (v[b] ^ v[c]).rotr(12)
                v[a] = v[a] &+ v[b] &+ my
                v[d] = (v[d] ^ v[a]).rotr(8)
                v[c] = v[c] &+ v[d]
                v[b] = (v[b] ^ v[c]).rotr(7)
            }

            for r in 0..<10 {
                let s = sigma[r]
                g(0, 4, 8, 12, m[s[0]], m[s[1]])
                g(1, 5, 9, 13, m[s[2]], m[s[3]])
                g(2, 6, 10, 14, m[s[4]], m[s[5]])
                g(3, 7, 11, 15, m[s[6]], m[s[7]])
                g(0, 5, 10, 15, m[s[8]], m[s[9]])
                g(1, 6, 11, 12, m[s[10]], m[s[11]])
                g(2, 7, 8, 13, m[s[12]], m[s[13]])
                g(3, 4, 9, 14, m[s[14]], m[s[15]])
            }
            for i in 0..<8 {
                h[i] = h[i] ^ v[i] ^ v[i + 8]
            }
        }
    }
}

extension UInt32 {
    fileprivate func rotr(_ n: UInt32) -> UInt32 {
        (self >> n) | (self << (32 - n))
    }
}
