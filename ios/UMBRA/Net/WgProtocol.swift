import Foundation

/// Minimal initiator-side WireGuard protocol (Noise_IKpsk2, no psk) — a
/// line-for-line port of UMBRA's Kotlin WgProtocol, which is itself
/// ported from wireguard-go and byte-for-byte verified against Cloudflare
/// WARP production endpoints AND the shared reference vectors:
///
///   1. build a handshake initiation (148 bytes)
///   2. consume the handshake response (92 bytes)  -> session keys
///   3. send an ICMP echo request *inside* the tunnel and parse the reply
///
/// Layout:
///   initiation: [type 4][sender 4][ephemeral 32][static 48][timestamp 28][mac1 16][mac2 16]
///   response:   [type 4][sender 4][receiver 4][ephemeral 32][empty 16][mac1 16][mac2 16]
///   transport:  [type 4][receiver 4][counter 8][aead(payload)]
///
/// v3.5 empirical rule (live-verified against production WARP): the reserved
/// bytes (1..3) of every outgoing packet stay ZERO — Cloudflare drops any
/// packet whose LE-u32 type word is not exactly 1/2/4. The account's client_id
/// is NEVER written into packets.
enum WgProtocol {

    static let construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    static let identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"
    private static let labelMac1 = "mac1----"

    static let initialChainKey: [UInt8] = WgCrypto.blake2s(Array(construction.utf8))
    static let initialHash: [UInt8] = WgCrypto.blake2s(initialChainKey + Array(identifier.utf8))
    private static let zeroNonce = [UInt8](repeating: 0, count: 12)
    private static let psk = [UInt8](repeating: 0, count: 32) // WARP: no preshared key

    static let msgInitiation: UInt8 = 1
    static let msgResponse: UInt8 = 2
    static let msgCookieReply: UInt8 = 3
    static let msgTransport: UInt8 = 4

    static let initiationSize = 148
    static let responseSize = 92
    static let cookieReplySize = 64
    static let transportHeaderSize = 16

    // ------------------------------------------------------------- KDF ----
    // wireguard-go noise-helpers.go: HKDF-style expansion over HMAC-BLAKE2s.

    private static func hmac(_ key: [UInt8], _ data: [UInt8]) -> [UInt8] {
        WgCrypto.hmacBlake2s(key: key, data: data)
    }

    /// KDF2 -> (t0, t1).
    private static func kdf2(_ key: [UInt8], _ input: [UInt8]) -> ([UInt8], [UInt8]) {
        let prk = hmac(key, input)
        let t0 = hmac(prk, [0x01])
        let t1 = hmac(prk, t0 + [0x02])
        return (t0, t1)
    }

    /// KDF3 -> (t0, t1, t2).
    private static func kdf3(_ key: [UInt8], _ input: [UInt8]) -> ([UInt8], [UInt8], [UInt8]) {
        let prk = hmac(key, input)
        let t0 = hmac(prk, [0x01])
        let t1 = hmac(prk, t0 + [0x02])
        let t2 = hmac(prk, t1 + [0x03])
        return (t0, t1, t2)
    }

    /// mixKey: chainKey = HMAC(HMAC(ck, data), 0x01).
    private static func mixKey(_ ck: [UInt8], _ data: [UInt8]) -> [UInt8] {
        hmac(hmac(ck, data), [0x01])
    }

    /// mixHash: hash = BLAKE2s(h || data).
    private static func mixHash(_ h: [UInt8], _ data: [UInt8]) -> [UInt8] {
        WgCrypto.blake2s(h + data)
    }

    // ----------------------------------------------------------- TAI64N ----

    private static let tsLock = NSLock()
    private static var lastTimestamp: [UInt8]? = nil

    /// TAI64N now — 12 bytes BE: (0x400000000000000a + unixSecs) || nanos.
    /// Process-wide MONOTONIC with wireguard-go semantics (1 ns bumps):
    /// keeps the sequence strictly increasing while staying within ~1 ms of
    /// the wall clock even after 100k initiations — a restarted process
    /// reusing a persisted identity must never present a timestamp the
    /// server already saw (silent anti-replay drops = "warp finds nothing").
    static func tai64nNow() -> [UInt8] {
        let nanoTime = DispatchTime.now().uptimeNanoseconds
        let unixSecs = Int64(Date().timeIntervalSince1970)
        let nanos = Int32(truncatingIfNeeded: nanoTime % 1_000_000_000)
        var out = [UInt8](repeating: 0, count: 12)
        putBeLong(&out, 0, 0x400000000000000A &+ unixSecs)
        putBeInt32(&out, 8, nanos)
        tsLock.lock()
        defer { tsLock.unlock() }
        if let last = lastTimestamp, compareTimestamps(out, last) <= 0 {
            // bump a COPY — callers keep the returned array; mutating the
            // stored one would retroactively change handed-out timestamps.
            var bumped = last
            bumpTimestamp(&bumped)
            lastTimestamp = bumped
            return bumped
        }
        lastTimestamp = out
        return out
    }

    /// Persists the current high-water mark so a NEW process reusing a
    /// persisted WARP identity never presents a timestamp the server already
    /// saw. nil before the first handshake.
    static func saveMark() -> [UInt8]? {
        tsLock.lock(); defer { tsLock.unlock() }
        return lastTimestamp
    }

    /// Restores a persisted high-water mark (no-op on nil/malformed input).
    static func loadMark(_ mark: [UInt8]?) {
        guard let mark = mark, mark.count == 12 else { return }
        tsLock.lock(); defer { tsLock.unlock() }
        lastTimestamp = mark
    }

    /// Drops the in-process mark — used when the identity is invalidated so a
    /// fresh key starts from the wall clock instead of the dead key's future.
    static func resetMark() {
        tsLock.lock(); defer { tsLock.unlock() }
        lastTimestamp = nil
    }

    static func compareTimestamps(_ a: [UInt8], _ b: [UInt8]) -> Int {
        for i in 0..<12 {
            let d = Int(a[i]) - Int(b[i])
            if d != 0 { return d }
        }
        return 0
    }

    /// In-place advance by 1 ns on a TAI64N pair (wireguard-go semantics).
    /// Carries: nanos (bytes 8..11) wrap at 0xFFFFFFFF -> seconds low word
    /// (bytes 4..7) +1 -> 32-bit carry into the high word (bytes 0..3).
    private static func bumpTimestamp(_ ts: inout [UInt8]) {
        let low = beInt32(ts, 8)
        if low == -1 { // 0xFFFFFFFF — nanos carry into the seconds low word
            putBeInt32(&ts, 8, 0)
            var secs = beInt32(ts, 4) // seconds low word lives at bytes 4..7
            secs = secs &+ 1
            putBeInt32(&ts, 4, secs)
            if secs == 0 { // 32-bit carry into the high word (bytes 0..3)
                putBeInt32(&ts, 0, beInt32(ts, 0) &+ 1)
            }
        } else {
            putBeInt32(&ts, 8, low &+ 1)
        }
    }

    // -------------------------------------------------------- handshake ----

    /// Initiator-side state kept between the initiation and the response.
    final class PendingHandshake {
        let ephPriv: [UInt8]
        let hash: [UInt8]
        let chainKey: [UInt8]
        let senderIndex: Int32

        init(ephPriv: [UInt8], hash: [UInt8], chainKey: [UInt8], senderIndex: Int32) {
            self.ephPriv = ephPriv
            self.hash = hash
            self.chainKey = chainKey
            self.senderIndex = senderIndex
        }
    }

    /// Builds a handshake initiation packet for staticPriv/staticPub talking
    /// to a responder whose long-term public key is responderPub.
    /// Fresh ephemeral + index + timestamp are supplied by the caller so the
    /// construction stays deterministic (and unit-testable against vectors).
    static func buildInitiation(
        staticPriv: [UInt8],
        staticPub: [UInt8],
        responderPub: [UInt8],
        senderIndex: Int32,
        ephemeralPriv: [UInt8],
        timestamp: [UInt8] = tai64nNow()
    ) throws -> (packet: [UInt8], pending: PendingHandshake) {
        let ephPub = WgCrypto.x25519Base(ephemeralPriv)

        var h = mixHash(initialHash, responderPub)
        var ck = mixKey(initialChainKey, ephPub)
        h = mixHash(h, ephPub)

        // encrypted static
        guard let ee = WgCrypto.x25519Shared(priv: ephemeralPriv, peerPub: responderPub) else {
            throw WgError("invalid responder public key")
        }
        let (ck1, kStatic) = kdf2(ck, ee)
        ck = ck1
        guard let staticCt = WgCrypto.chacha20Poly1305Seal(key: kStatic, nonce: zeroNonce, plaintext: staticPub, aad: h) else {
            throw WgError("seal failed")
        }
        h = mixHash(h, staticCt)

        // encrypted timestamp
        guard let ss = WgCrypto.x25519Shared(priv: staticPriv, peerPub: responderPub) else {
            throw WgError("invalid keypair")
        }
        let (ck2, kTs) = kdf2(ck, ss)
        ck = ck2
        guard let tsCt = WgCrypto.chacha20Poly1305Seal(key: kTs, nonce: zeroNonce, plaintext: timestamp, aad: h) else {
            throw WgError("seal failed")
        }
        h = mixHash(h, tsCt)

        var packet = [UInt8](repeating: 0, count: initiationSize)
        putLeInt32(&packet, 0, msgInitiation)
        // reserved bytes (1..3) stay ZERO — production WARP drops non-zero
        putLeInt32(&packet, 4, senderIndex)
        packet.replaceSubrange(8..<40, with: ephPub)
        packet.replaceSubrange(40..<88, with: staticCt)      // 48
        packet.replaceSubrange(88..<116, with: tsCt)         // 28

        let mac1Key = WgCrypto.blake2s(Array(labelMac1.utf8) + responderPub)
        let mac1 = WgCrypto.blake2s(Array(packet[0..<116]), key: mac1Key, digestSize: 16)
        packet.replaceSubrange(116..<132, with: mac1)
        // mac2 stays zero (no cookie)

        return (packet, PendingHandshake(ephPriv: ephPriv, hash: h, chainKey: ck, senderIndex: senderIndex))
    }

    /// Consumes a handshake response on the initiator side. Returns the
    /// session when the response is authentic (receiver index matches + AEAD
    /// tag over the empty message verifies), or nil with a reason.
    static func consumeResponse(
        pending: PendingHandshake,
        staticPriv: [UInt8],
        data: [UInt8]
    ) -> (session: WgSession?, error: String) {
        if data.count != responseSize { return (nil, "bad response length \(data.count)") }
        // byte-wise type check (boringtun semantics) — a WARP response that
        // echoes junk into its reserved bytes is still a valid response
        if data[0] != msgResponse { return (nil, "not a response (type \(leInt32(data, 0)))") }
        let sender = leInt32(data, 4)
        let receiver = leInt32(data, 8)
        if receiver != pending.senderIndex { return (nil, "receiver index mismatch") }
        let theirEph = Array(data[12..<44])
        let empty = Array(data[44..<60])

        var h = mixHash(pending.hash, theirEph)
        var ck = mixKey(pending.chainKey, theirEph)
        guard let ee = WgCrypto.x25519Shared(priv: pending.ephPriv, peerPub: theirEph) else {
            return (nil, "bad ephemeral")
        }
        ck = mixKey(ck, ee)
        guard let se = WgCrypto.x25519Shared(priv: staticPriv, peerPub: theirEph) else {
            return (nil, "bad static DH")
        }
        ck = mixKey(ck, se)
        let (ck1, tau, k) = kdf3(ck, psk)
        ck = ck1
        h = mixHash(h, tau)
        if WgCrypto.chacha20Poly1305Open(key: k, nonce: zeroNonce, ctAndTag: empty, aad: h) == nil {
            return (nil, "response AEAD tag invalid")
        }
        h = mixHash(h, empty)
        let (sendKey, recvKey) = kdf2(ck, [])
        return (WgSession(sendKey: sendKey, recvKey: recvKey, ourIndex: pending.senderIndex, theirIndex: sender), "")
    }

    // -------------------------------------------------------- data plane ----

    /// Established transport session (initiator side).
    final class WgSession {
        private let sendKey: [UInt8]
        private let recvKey: [UInt8]
        let ourIndex: Int32
        let theirIndex: Int32
        private var sendCounter: UInt64 = 0
        private let counterLock = NSLock()

        init(sendKey: [UInt8], recvKey: [UInt8], ourIndex: Int32, theirIndex: Int32) {
            self.sendKey = sendKey
            self.recvKey = recvKey
            self.ourIndex = ourIndex
            self.theirIndex = theirIndex
        }

        /// Seals `inner` (an IP packet) into a transport data packet.
        func buildTransport(_ inner: [UInt8]) -> [UInt8]? {
            counterLock.lock()
            let counter = sendCounter
            sendCounter &+= 1
            counterLock.unlock()

            let pad = (16 - (inner.count % 16)) % 16
            let padded = inner + [UInt8](repeating: 0, count: pad)
            var nonce = [UInt8](repeating: 0, count: 12)
            putLeLong(&nonce, 4, counter)
            guard let ct = WgCrypto.chacha20Poly1305Seal(key: sendKey, nonce: nonce, plaintext: padded, aad: []) else {
                return nil
            }
            var packet = [UInt8](repeating: 0, count: transportHeaderSize + ct.count)
            putLeInt32(&packet, 0, WgProtocol.msgTransport)
            putLeInt32(&packet, 4, theirIndex)
            putLeLong(&packet, 8, counter)
            packet.replaceSubrange(16..<(16 + ct.count), with: ct)
            return packet
        }

        /// Opens a transport data packet received from the responder.
        func openTransport(_ packet: [UInt8]) -> [UInt8]? {
            if packet.count < 32 { return nil }
            // byte-wise type check — receivers ignore reserved bytes
            if packet[0] != WgProtocol.msgTransport { return nil }
            if leInt32(packet, 4) != ourIndex { return nil }
            let counter = leLong(packet, 8)
            var nonce = [UInt8](repeating: 0, count: 12)
            putLeLong(&nonce, 4, counter)
            return WgCrypto.chacha20Poly1305Open(key: recvKey, nonce: nonce, ctAndTag: Array(packet[16...]), aad: [])
        }
    }

    // ------------------------------------------------------------ ICMP v4 ----

    /// IPv4 + ICMP echo request (28 bytes) from src to dst.
    static func icmpEchoRequest(src: [UInt8], dst: [UInt8], ident: Int, seq: Int) -> [UInt8] {
        precondition(src.count == 4 && dst.count == 4)
        var icmp = [UInt8](repeating: 0, count: 8)
        icmp[0] = 8; icmp[1] = 0
        putBeShort(&icmp, 4, ident)
        putBeShort(&icmp, 6, seq)
        putBeShort(&icmp, 2, inetChecksum(icmp))

        let total = 20 + 8
        var ip = [UInt8](repeating: 0, count: 20)
        ip[0] = 0x45
        putBeShort(&ip, 2, total)
        putBeShort(&ip, 4, ident & 0xFFFF)
        putBeShort(&ip, 6, 0x4000) // don't fragment
        ip[8] = 64
        ip[9] = 1 // ICMP
        ip.replaceSubrange(12..<16, with: src)
        ip.replaceSubrange(16..<20, with: dst)
        putBeShort(&ip, 10, inetChecksum(ip))

        return ip + icmp
    }

    /// Validates that `inner` is an IPv4 ICMP echo reply for our ident/seq.
    static func parseEchoReply(_ inner: [UInt8], ident: Int, seq: Int) -> Bool {
        if inner.count < 28 { return false }
        let verIhl = Int(inner[0])
        if verIhl >> 4 != 4 { return false }
        let ihl = (verIhl & 0x0F) * 4
        if Int(inner[9]) != 1 { return false } // not ICMP
        if inner.count < ihl + 8 { return false }
        let icmp = Array(inner[ihl..<(ihl + 8)])
        let type = Int(icmp[0])
        let code = Int(icmp[1])
        let rid = beShort(icmp, 4)
        let rseq = beShort(icmp, 6)
        return type == 0 && code == 0 && rid == ident && rseq == seq
    }

    /// RFC 1071 one's-complement checksum.
    static func inetChecksum(_ data: [UInt8]) -> Int {
        var sum: UInt64 = 0
        var i = 0
        while i + 1 < data.count {
            sum += (UInt64(data[i]) << 8) | UInt64(data[i + 1])
            i += 2
        }
        if i < data.count { sum += UInt64(data[i]) << 8 }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return Int(~UInt32(truncatingIfNeeded: sum) & 0xFFFF)
    }

    // --------------------------------------------------------- byte utils ----

    static func leInt32(_ b: [UInt8], _ off: Int) -> Int32 {
        Int32(bitPattern:
            UInt32(b[off])
            | (UInt32(b[off + 1]) << 8)
            | (UInt32(b[off + 2]) << 16)
            | (UInt32(b[off + 3]) << 24))
    }

    static func leLong(_ b: [UInt8], _ off: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in (0..<8).reversed() {
            v = (v << 8) | UInt64(b[off + i])
        }
        return v
    }

    static func putLeInt32(_ b: inout [UInt8], _ off: Int, _ v: Int32) {
        let u = UInt32(bitPattern: v)
        b[off] = UInt8(truncatingIfNeeded: u)
        b[off + 1] = UInt8(truncatingIfNeeded: u >> 8)
        b[off + 2] = UInt8(truncatingIfNeeded: u >> 16)
        b[off + 3] = UInt8(truncatingIfNeeded: u >> 24)
    }

    static func putLeInt32(_ b: inout [UInt8], _ off: Int, _ v: UInt8) {
        b[off] = v
        b[off + 1] = 0
        b[off + 2] = 0
        b[off + 3] = 0
    }

    static func putLeLong(_ b: inout [UInt8], _ off: Int, _ v: UInt64) {
        for i in 0..<8 {
            b[off + i] = UInt8(truncatingIfNeeded: v >> (8 * UInt64(i)))
        }
    }

    static func putBeInt32(_ b: inout [UInt8], _ off: Int, _ v: Int32) {
        let u = UInt32(bitPattern: v)
        b[off] = UInt8(truncatingIfNeeded: u >> 24)
        b[off + 1] = UInt8(truncatingIfNeeded: u >> 16)
        b[off + 2] = UInt8(truncatingIfNeeded: u >> 8)
        b[off + 3] = UInt8(truncatingIfNeeded: u)
    }

    static func beInt32(_ b: [UInt8], _ off: Int) -> Int32 {
        Int32(bitPattern:
            (UInt32(b[off]) << 24)
            | (UInt32(b[off + 1]) << 16)
            | (UInt32(b[off + 2]) << 8)
            | UInt32(b[off + 3]))
    }

    static func putBeShort(_ b: inout [UInt8], _ off: Int, _ v: Int) {
        b[off] = UInt8((v >> 8) & 0xFF)
        b[off + 1] = UInt8(v & 0xFF)
    }

    static func beShort(_ b: [UInt8], _ off: Int) -> Int {
        (Int(b[off]) << 8) | Int(b[off + 1])
    }

    static func putBeLong(_ b: inout [UInt8], _ off: Int, _ v: Int64) {
        let u = UInt64(bitPattern: v)
        for i in 0..<8 {
            b[off + i] = UInt8(truncatingIfNeeded: u >> (8 * UInt64(7 - i)))
        }
    }
}

struct WgError: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { self.description = message }
}
