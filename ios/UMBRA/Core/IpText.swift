import Foundation

/// IP literal parsing/formatting — no DNS, ever.
/// A faithful port of the Kotlin IpText (including the hand-rolled RFC-5952
/// compressor, tested against the same cases).
enum IpText {

    static func isIpv6(_ text: String) -> Bool {
        text.contains(":")
    }

    /// Parses a literal IPv4/IPv6 address to raw bytes. Never performs DNS.
    static func literalToBytes(_ text: String) -> [UInt8]? {
        let t = text.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return nil }
        if t.contains(":") {
            return parseIpv6(t)
        }
        // strict dotted-quad v4 (no leading zeros, matching the Kotlin parser)
        let parts = t.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 4 else { return nil }
        var out = [UInt8](repeating: 0, count: 4)
        for i in 0..<4 {
            let p = parts[i]
            if p.isEmpty || p.count > 3 || (p.count > 1 && p.hasPrefix("0")) { return nil }
            guard let v = Int(p), v >= 0, v <= 255 else { return nil }
            out[i] = UInt8(v)
        }
        return out
    }

    /// Hand-rolled IPv6 literal parser (supports "::" compression and the
    /// embedded-IPv4 tail). Returns 16 bytes or nil.
    static func parseIpv6(_ text: String) -> [UInt8]? {
        var s = text
        if s.hasPrefix("[") || s.hasSuffix("]") {
            guard s.hasPrefix("["), s.hasSuffix("]") else { return nil }
            s = String(s.dropFirst().dropLast())
        }
        if s.contains("%") { return nil } // zone ids rejected
        if s.isEmpty { return nil }

        // embedded IPv4 tail ("::ffff:1.2.3.4" / "a:b:c:d:e:f:1.2.3.4")
        var v4TailGroups: [UInt16] = []
        var head = s
        if let dot = s.range(of: ".", options: .backwards) {
            guard let colon = s.range(of: ":", options: .backwards, range: s.startIndex..<dot.lowerBound) else {
                return nil
            }
            let v4Text = String(s[colon.upperBound...])
            guard let v4 = literalToBytes(v4Text) else { return nil }
            v4TailGroups = [
                UInt16(v4[0]) << 8 | UInt16(v4[1]),
                UInt16(v4[2]) << 8 | UInt16(v4[3]),
            ]
            head = String(s[s.startIndex..<colon.lowerBound])
        }

        // compression "::" (at most one)
        var headGroups: [UInt16] = []
        var tailGroups: [UInt16] = []
        if head.contains("::") {
            let pieces = head.components(separatedBy: "::")
            guard pieces.count == 2 else { return nil }
            for g in pieces[0].split(separator: ":", omittingEmptySubsequences: false) {
                guard let v = parseHexGroup(String(g)) else { return nil }
                headGroups.append(v)
            }
            for g in pieces[1].split(separator: ":", omittingEmptySubsequences: false) {
                guard let v = parseHexGroup(String(g)) else { return nil }
                tailGroups.append(v)
            }
        } else {
            for g in head.split(separator: ":", omittingEmptySubsequences: false) {
                guard let v = parseHexGroup(String(g)) else { return nil }
                headGroups.append(v)
            }
        }

        let embedded = headGroups.count + tailGroups.count + v4TailGroups.count
        guard embedded <= 8 else { return nil }

        var all: [UInt16] = []
        if head.contains("::") {
            let missing = 8 - embedded
            guard missing >= 1 else { return nil } // "::" must expand >= 1 group
            all.append(contentsOf: headGroups)
            all.append(contentsOf: [UInt16](repeating: 0, count: missing))
            all.append(contentsOf: tailGroups)
        } else {
            guard embedded == 8 else { return nil }
            all.append(contentsOf: headGroups)
            all.append(contentsOf: tailGroups)
        }
        all.append(contentsOf: v4TailGroups)
        guard all.count == 8 else { return nil }

        var out = [UInt8](repeating: 0, count: 16)
        for i in 0..<8 {
            out[i * 2] = UInt8(truncatingIfNeeded: all[i] >> 8)
            out[i * 2 + 1] = UInt8(truncatingIfNeeded: all[i])
        }
        return out
    }

    private static func parseHexGroup(_ s: String) -> UInt16? {
        guard !s.isEmpty, s.count <= 4, s.allSatisfy({ $0.isHexDigit }) else { return nil }
        return UInt16(s, radix: 16)
    }

    /// Compact RFC-5952-ish rendering of raw address bytes.
    static func format(_ bytes: [UInt8]) -> String {
        switch bytes.count {
        case 4: return bytes.map { String($0) }.joined(separator: ".")
        case 16: return formatIpv6(bytes)
        default: return "?"
        }
    }

    static func formatIpv6(_ b: [UInt8]) -> String {
        var hextets = [Int](repeating: 0, count: 8)
        for i in 0..<8 {
            hextets[i] = (Int(b[i * 2]) << 8) | Int(b[i * 2 + 1])
        }
        // longest zero run (>= 2 hextets)
        var bestStart = -1
        var bestLen = 0
        var i = 0
        while i < 8 {
            if hextets[i] == 0 {
                var j = i
                while j < 8 && hextets[j] == 0 { j += 1 }
                let len = j - i
                if len > bestLen {
                    bestLen = len
                    bestStart = i
                }
                i = j
            } else {
                i += 1
            }
        }
        var sb = ""
        var k = 0
        while k < 8 {
            if bestStart >= 0 && k == bestStart && bestLen >= 2 {
                sb += "::"
                k += bestLen
                if k >= 8 { break }
                continue
            }
            if k > 0 && !sb.isEmpty && sb.last != ":" {
                sb += ":"
            }
            sb += String(hextets[k], radix: 16)
            k += 1
        }
        if sb.isEmpty { sb = "::" }
        return sb
    }

    /// Renders an IP for URLs / configs — IPv6 gets square brackets.
    static func forUrl(_ ip: String) -> String {
        if isIpv6(ip) && !ip.hasPrefix("[") { return "[\(ip)]" }
        return ip
    }

    static func familyOf(_ bytes: [UInt8]) -> IpProtocol {
        bytes.count == 4 ? .IPv4 : .IPv6
    }
}
