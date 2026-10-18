import Foundation
import Darwin

/// Anti-DPI UDP noise burst — xray `noises` semantics: sent to RANDOM public
/// destinations, never to the probe target (the v3.5 fix: WARP endpoints
/// co-host QUIC/MASQUE on the same port and answer random garbage with
/// version-negotiation packets that pollute the handshake wait).
///
/// Rides a fire-and-forget POSIX unconnected socket (sendto) — no receive
/// ever happens here, so no thread ever blocks.
enum NoiseBurst {

    private static let excludedFirstOctets: Set<Int> = [10, 127, 169, 172, 192]

    static func send(count: Int, cfg: UdpNoiseConfig, rng: Rng) async {
        guard count > 0 else { return }
        for _ in 0..<count {
            if Task.isCancelled { return }
            let span = max(1, cfg.maxPacket - cfg.minPacket)
            let n = cfg.minPacket + rng.int(span)
            let pkt = rng.bytes(n)
            sendOne(pkt: pkt, rng: rng)
            let delaySpan = max(1, cfg.maxDelayMs - cfg.minDelayMs)
            let delayMs = cfg.minDelayMs + rng.int(delaySpan)
            do {
                try await Task.sleep(nanoseconds: UInt64(delayMs) * 1_000_000)
            } catch {
                return // cancelled
            }
        }
    }

    /// One fire-and-forget datagram to a random public unicast destination.
    private static func sendOne(pkt: [UInt8], rng: Rng) {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return }
        defer { close(fd) }

        var first = rng.int(in: 1...223)
        while excludedFirstOctets.contains(first) {
            first = rng.int(in: 1...223)
        }
        let addr32 = (UInt32(first) << 24) | (UInt32(rng.int(256)) << 16)
            | (UInt32(rng.int(256)) << 8) | UInt32(rng.int(256))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(1024 + rng.int(64_512)).bigEndian
        addr.sin_addr = in_addr(s_addr: addr32.bigEndian)

        let sent = pkt.withUnsafeBufferPointer { buf -> Int in
            withUnsafePointer(to: &addr) { saPtr -> Int in
                saPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa -> Int in
                    guard let base = buf.baseAddress else { return 0 }
                    return sendto(fd, base, pkt.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        _ = sent
    }
}
