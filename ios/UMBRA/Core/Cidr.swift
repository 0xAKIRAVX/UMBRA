import Foundation
import Security

/// Random source for the scanner. Deterministic SplitMix64 stream for pool
/// drawing/sampling (reproducible in tests); identity KEYS are generated with
/// SecRandomCopyBytes — cryptographically strong (an upgrade over the Kotlin
/// nanoTime-seeded Random, free on iOS).
///
/// Not thread-safe by design: the engine draws pools from a single task, and
/// every concurrent probe constructs its own instance (same discipline as the
/// Kotlin WarpProbe).
final class Rng {
    private var state: UInt64

    init(seed: UInt64? = nil) {
        state = seed ?? UInt64(Date().timeIntervalSince1970 * 1000) ^ (UInt64(DispatchTime.now().uptimeNanoseconds) << 1)
    }

    private func next() -> UInt64 {
        state &+= 0x9E3779B97F4A7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }

    /// Raw 64-bit draw (uniform).
    func u64() -> UInt64 {
        next()
    }

    /// Uniform Int in 0..<upper (upper > 0).
    func int(_ upper: Int) -> Int {
        precondition(upper > 0)
        return Int(next() % UInt64(upper))
    }

    /// Uniform Int in a ClosedRange.
    func int(in range: ClosedRange<Int>) -> Int {
        range.lowerBound + int(range.count)
    }

    /// Full-range Int32 (for WG sender indices).
    func int32() -> Int32 {
        Int32(bitPattern: UInt32(truncatingIfNeeded: next()))
    }

    /// n random bytes.
    func bytes(_ n: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: n)
        var i = 0
        while i < n {
            let v = next()
            for j in 0..<8 where i + j < n {
                out[i + j] = UInt8(truncatingIfNeeded: v >> (8 * UInt64(j)))
            }
            i += 8
        }
        return out
    }

    /// Cryptographically strong random bytes (identity keys).
    static func secureBytes(_ n: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: n)
        let status = SecRandomCopyBytes(kSecRandomDefault, n, &out)
        if status != errSecSuccess {
            // ultra-rare fallback — never crashes a scan over entropy
            var fb = Rng()
            out = fb.bytes(n)
        }
        return out
    }
}

// ---------------------------------------------------------------------------

/// One parsed CIDR block — byte-array arithmetic replaces the Kotlin
/// BigInteger implementation while preserving exact semantics.
struct CidrBlock: Equatable {
    let family: IpProtocol
    let base: [UInt8]          // network base, masked
    let prefix: Int
    let hostBits: Int
    let text: String

    var bits: Int { family == .IPv4 ? 32 : 128 }
    var size: UInt64 { hostBits >= 64 ? UInt64.max : (UInt64(1) << UInt64(hostBits)) }

    static func parse(_ text: String) -> CidrBlock? {
        let t = text.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return nil }
        guard let slash = t.lastIndex(of: "/") else {
            // bare address = full-length prefix
            guard let bytes = IpText.literalToBytes(t) else { return nil }
            return CidrBlock(family: IpText.familyOf(bytes), base: bytes, prefix: bytes.count * 8, hostBits: 0, text: t)
        }
        let addrPart = String(t[t.startIndex..<slash])
        let prefixPart = String(t[t.index(after: slash)...])
        guard let bytes = IpText.literalToBytes(addrPart) else { return nil }
        let bits = bytes.count * 8
        guard let prefix = Int(prefixPart), prefix >= 0, prefix <= bits else { return nil }
        let hostBits = bits - prefix
        var base = bytes
        // mask host bits to zero
        if hostBits > 0 {
            let fullZeroBytes = hostBits / 8
            if fullZeroBytes > 0 {
                for i in 0..<fullZeroBytes { base[base.count - 1 - i] = 0 }
            }
            let remBits = hostBits % 8
            if remBits > 0 {
                let idx = base.count - 1 - fullZeroBytes
                base[idx] &= UInt8(0xFF << UInt8(remBits))
            }
        }
        return CidrBlock(family: IpText.familyOf(bytes), base: base, prefix: prefix, hostBits: hostBits, text: t)
    }

    static func parseAll(_ list: [String]) -> [CidrBlock] {
        list.compactMap { parse($0) }
    }

    /// Random candidates out of the block (v3.1.1 semantics: small blocks
    /// respect the samples knob; the full-coverage path skips v4 net/bcast).
    func sampleCandidates(_ samples: Int, rng: Rng, into out: inout [[UInt8]]) {
        if samples <= 0 { return }
        if hostBits <= 10 {
            let total = min(size, 2048)
            if samples >= Int(total) {
                // small block, full coverage requested
                for i in 0..<Int(total) {
                    if family == .IPv4 {
                        let last = i & 0xFF
                        if last == 0 || last == 255 { continue }
                    }
                    out.append(CidrBlock.addOffset(base, UInt64(i)))
                }
                return
            }
            // small blocks respect the samples knob
            var seen = Set<[UInt8]>(minimumCapacity: samples * 2)
            var guardCount = 0
            let maxGuard = samples * 20
            while seen.count < samples && guardCount < maxGuard {
                guardCount += 1
                let v = CidrBlock.addOffset(base, CidrBlock.randomUniform(hostBits, rng))
                if v.allSatisfy({ $0 == 0 }) { continue } // never emit unspecified
                if family == .IPv4 {
                    let last = Int(v[3])
                    if last == 0 || last == 255 { continue }
                }
                if seen.insert(v).inserted { out.append(v) }
            }
            return
        }
        var seen = Set<[UInt8]>(minimumCapacity: samples * 2)
        var guardCount = 0
        let maxGuard = samples * 10
        while seen.count < samples && guardCount < maxGuard {
            guardCount += 1
            let v = CidrBlock.addOffset(base, CidrBlock.randomUniform(hostBits, rng))
            if v.allSatisfy({ $0 == 0 }) { continue }
            if seen.insert(v).inserted { out.append(v) }
        }
    }

    /// Uniform random value in [0, 2^hostBits), as an integer offset.
    private static func randomUniform(_ hostBits: Int, _ rng: Rng) -> UInt64 {
        // all our random-drawn blocks have hostBits <= 64 (the v6 /48 draws
        // are handled through the v4-embedded twin path in generateEndpoints;
        // custom v6 CIDRs larger than /64 fall back to a 64-bit draw which is
        // still uniform over the low 64 bits of the host part)
        let bits = min(hostBits, 64)
        let raw = rng.u64()
        return bits >= 64 ? raw : raw >> UInt64(64 - bits)
    }

    /// base + offset (big-endian carry, wraps at the address width).
    static func addOffset(_ base: [UInt8], _ offset: UInt64) -> [UInt8] {
        var out = base
        var carry = offset
        var i = out.count - 1
        while i >= 0 && carry > 0 {
            let sum = UInt64(out[i]) + (carry & 0xFF)
            out[i] = UInt8(truncatingIfNeeded: sum)
            carry = (carry >> 8) + (sum >> 8)
            i -= 1
        }
        return out
    }
}

/// A resolved candidate address.
struct Candidate: Hashable {
    let bytes: [UInt8]
    var ipProtocol: IpProtocol { IpText.familyOf(bytes) }
    var text: String { IpText.format(bytes) }
    var id: String { text }

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    init?(literal: String) {
        guard let bytes = IpText.literalToBytes(literal) else { return nil }
        self.bytes = bytes
    }
}

/// One random ip:port endpoint — the ENDPOINT-mode unit of work.
struct EndpointPair: Hashable {
    let candidate: Candidate
    let port: Int
    var id: String { "\(candidate.text):\(port)" }
}

enum IpGenerator {

    /// Random candidates per CIDR (never full enumeration of big blocks).
    static func generate(
        cidrs: [String],
        family: NetFamily,
        samplesPerPrefix: Int,
        rng: Rng = Rng()
    ) -> [Candidate] {
        let blocks = CidrBlock.parseAll(cidrs).filter { block in
            family == .BOTH
                || (family == .V4 && block.family == .IPv4)
                || (family == .V6 && block.family == .IPv6)
        }
        var seen = Set<[UInt8]>(minimumCapacity: samplesPerPrefix * blocks.count)
        var out: [Candidate] = []
        out.reserveCapacity(samplesPerPrefix * blocks.count)
        for b in blocks {
            var raw: [[UInt8]] = []
            b.sampleCandidates(samplesPerPrefix, rng: rng, into: &raw)
            for bytes in raw where seen.insert(bytes).inserted {
                out.append(Candidate(bytes))
            }
        }
        return out
    }

    /// Builds `2606:4700:d0::a29f:c001`-style bytes for a WARP v6 endpoint.
    static func v6Embedded(prefix: String, v4: [UInt8]) -> [UInt8]? {
        if v4.count != 4 { return nil }
        guard var head = IpText.literalToBytes(prefix), head.count == 16 else { return nil }
        // zero groups 4..6 (bits 48..95), then place v4 in the last 32 bits
        for i in 6..<12 { head[i] = 0 }
        head[12] = v4[0]; head[13] = v4[1]; head[14] = v4[2]; head[15] = v4[3]
        return head
    }

    /// BPB-Warp-Scanner endpoint generation: random ip:port pairs from the
    /// WARP pool. Port 0 -> each endpoint draws its own random port from the
    /// canonical list; port > 0 -> pinned.
    static func generateEndpoints(
        family: NetFamily,
        count: Int,
        port: Int,
        rng: Rng = Rng()
    ) -> [EndpointPair] {
        generateEndpoints(family: family, count: count,
                          portChoices: port > 0 ? [port] : Presets.warpPortsFull,
                          rng: rng)
    }

    /// v3.10 overload: the exact port menu each drawn pair picks from (the
    /// recovery ladder's re-aim passes only the winning ports). Empty or
    /// invalid lists fall back to the canonical list.
    static func generateEndpoints(
        family: NetFamily,
        count: Int,
        portChoices: [Int],
        rng: Rng = Rng()
    ) -> [EndpointPair] {
        if count <= 0 { return [] }
        let v4Blocks = CidrBlock.parseAll(Presets.warpV4)
        if v4Blocks.isEmpty { return [] }
        let choices = portChoices.filter { $0 >= 1 && $0 <= 65535 }
        let menu = choices.isEmpty ? Presets.warpPortsFull : Array(choices)
        let wantV4 = family != .V6
        let wantV6 = family != .V4
        // BPB split: half v4, half v6 when both families are requested
        let v4Quota: Int
        if wantV4 && wantV6 {
            v4Quota = count / 2
        } else if wantV4 {
            v4Quota = count
        } else {
            v4Quota = 0
        }
        let v6Quota = count - v4Quota
        var seen = Set<String>(minimumCapacity: count * 2)
        var out: [EndpointPair] = []
        out.reserveCapacity(count)

        func nextPort() -> Int { menu[rng.int(menu.count)] }

        func nextV4Bytes() -> [UInt8] {
            let block = v4Blocks[rng.int(v4Blocks.count)]
            let host = 1 + rng.int(254)
            return CidrBlock.addOffset(block.base, UInt64(host))
        }

        @discardableResult
        func add(_ c: Candidate, _ p: Int) -> Bool {
            let key = "\(c.text):\(p)"
            if seen.insert(key).inserted {
                out.append(EndpointPair(candidate: c, port: p))
                return true
            }
            return false
        }

        // v4 pass
        var guardCount = 0
        let v4Guard = v4Quota * 20 + 64
        var made4 = 0
        while made4 < v4Quota && guardCount < v4Guard {
            guardCount += 1
            if add(Candidate(nextV4Bytes()), nextPort()) { made4 += 1 }
        }
        // v6 pass (embedded twins of fresh random v4s)
        guardCount = 0
        let v6Guard = v6Quota * 20 + 64
        var made6 = 0
        let prefixes = [Presets.warpV6PrefixD0, Presets.warpV6PrefixD1]
        while made6 < v6Quota && guardCount < v6Guard {
            guardCount += 1
            let v4 = nextV4Bytes()
            let prefix = prefixes[rng.int(prefixes.count)]
            guard let bytes = v6Embedded(prefix: prefix, v4: v4) else { continue }
            if add(Candidate(bytes), nextPort()) { made6 += 1 }
        }
        return out
    }

    static func estimate(cidrs: [String], family: NetFamily, samplesPerPrefix: Int) -> Int {
        let blocks = CidrBlock.parseAll(cidrs).filter { block in
            family == .BOTH
                || (family == .V4 && block.family == .IPv4)
                || (family == .V6 && block.family == .IPv6)
        }
        var total = 0
        for b in blocks {
            let enumerated = b.hostBits <= 10
                ? min(Int(min(b.size, 2048)), samplesPerPrefix)
                : samplesPerPrefix
            total += enumerated
        }
        return total
    }
}
