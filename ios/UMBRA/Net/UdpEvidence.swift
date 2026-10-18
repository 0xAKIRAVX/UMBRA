import Foundation
import Network

/// Independent UDP-egress evidence for negative verdicts.
///
/// A gate that reports "warp unreachable" with zero handshake replies is
/// honest but incomplete: the user cannot tell whether (a) ALL udp is
/// blocked, (b) udp works generally but Cloudflare's network is filtered,
/// or (c) udp reaches Cloudflare fine and only WARP's ranges/ports are
/// selectively dropped. NTP (:123) witnesses answer exactly that.
enum UdpEvidence {

    /// time.cloudflare.com — Cloudflare-network NTP witness.
    static let cfNtp: [UInt8] = [162, 159, 200, 1]

    /// Google NTP — non-Cloudflare control witness.
    static let otherNtp: [UInt8] = [216, 239, 35, 0]

    struct Evidence: Equatable {
        /// UDP round-trip INSIDE Cloudflare's network succeeded.
        let cloudflareNtp: Bool
        /// UDP round-trip to a non-Cloudflare host succeeded.
        let otherNtp: Bool
    }

    /// Probes both witnesses in parallel; never throws.
    static func gather(timeoutMs: Int = 1500) async -> Evidence {
        async let cf = probe(cfNtp, timeoutMs: timeoutMs)
        async let other = probe(otherNtp, timeoutMs: timeoutMs)
        return Evidence(cloudflareNtp: await cf, otherNtp: await other)
    }

    /// One NTP request/reply exchange. False on timeout/any error.
    static func probe(_ ip: [UInt8], timeoutMs: Int) async -> Bool {
        let link = UdpLink(host: IpText.format(ip), port: 123)
        defer { link.close() }
        guard await link.waitReady(timeoutMs: timeoutMs) else { return false }
        // NTPv3 client packet: LI=0, VN=3, Mode=3 (client)
        var req = [UInt8](repeating: 0, count: 48)
        req[0] = 0x1B
        guard await link.send(req) else { return false }
        let resp = await link.receive(timeoutMs: min(5000, max(300, timeoutMs)))
        guard let resp = resp else { return false }
        return resp.count >= 48
    }

    /// Human-readable diagnosis for a scan that saw zero WG replies.
    static func describe(_ e: Evidence) -> String {
        if e.cloudflareNtp {
            return "udp witness: time.cloudflare.com :123 REPLIED — udp to cloudflare's network works, so WARP's ranges/ports are SELECTIVELY filtered here; v6 warp or EDGE (tcp 443) are the usable paths"
        }
        if e.otherNtp {
            return "udp witness: external ntp replied but cloudflare's network stayed silent — this network udp-filters cloudflare as a whole; try EDGE mode (tcp 443, tls-verified) or a different network"
        }
        return "udp witness: even ntp is dead — there is NO udp egress on this network at all (or the active vpn drops it); warp cannot work here, EDGE mode still can"
    }
}

/// Detects an active system VPN (the #1 killer of UDP scans on censored
/// networks). Uses NWPathMonitor — iOS exposes the .vpn interface type.
enum VpnSensor {

    /// Short English hint for the evidence line, or nil.
    static func hint() async -> String? {
        let hasVpn: Bool? = await withCheckedContinuation { (cont: CheckedContinuation<Bool?, Never>) in
            let monitor = NWPathMonitor()
            let box = OnceBox<Bool?>(cont)
            let work = DispatchWorkItem {
                monitor.cancel()
                box.resume(false)
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(1200), execute: work)
            monitor.pathUpdateHandler = { path in
                switch path.status {
                case .satisfied, .unsatisfied:
                    let vpn = path.usesInterfaceType(.vpn)
                    monitor.cancel()
                    work.cancel()
                    box.resume(vpn)
                default:
                    break
                }
            }
            monitor.start(queue: DispatchQueue.global())
        }
        guard let hasVpn = hasVpn, hasVpn else { return nil }
        return "active system vpn detected — it may capture or drop udp egress (disconnect it and rescan)"
    }
}
