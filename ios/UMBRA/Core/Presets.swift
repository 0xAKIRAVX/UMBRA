import Foundation

/// Census-verified presets — identical values to the Android app so both
/// platforms draw from the same proven pools.
enum Presets {

    static let cfEdgeV4: [String] = [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "172.64.0.0/13",
        "131.0.72.0/22",
    ]

    static let cfEdgeV6: [String] = [
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ]

    /// WARP v4 pool — BPB-Warp-Scanner range set (includes the newer 8.x
    /// blocks many ISPs have not rate-limited yet).
    static let warpV4: [String] = [
        "162.159.192.0/24",
        "162.159.193.0/24",
        "162.159.195.0/24",
        "162.159.198.0/24",
        "162.159.199.0/24",
        "188.114.96.0/24",
        "188.114.97.0/24",
        "188.114.98.0/24",
        "188.114.99.0/24",
        "8.34.146.0/24",
        "8.39.214.0/24",
        "8.39.204.0/24",
        "8.6.112.0/24",
        "8.35.211.0/24",
        "8.39.125.0/24",
        "8.47.69.0/24",
    ]

    static let warpV6: [String] = [
        "2606:4700:d0::/48",
        "2606:4700:d1::/48",
    ]

    static let cfEdgePorts: [Int] = [443, 8443, 2053, 2083, 2087, 2096]

    /// Quick-pick port chips for ENDPOINT mode.
    static let warpPorts: [Int] = [2408, 894, 443, 928, 1843, 500, 1701, 4500]

    /// Full canonical WARP endpoint port list (BPB verified set + :443).
    static let warpPortsFull: [Int] = [
        500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939,
        942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070,
        1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854,
        4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
        8742, 8854, 8886, 443,
    ].sorted()

    /// Seed WARP endpoint IPs (live census 2026-10-10): a guaranteed-good head
    /// start, never a verdict about the network.
    static let warpSeedV4: [String] = [
        "188.114.96.1",
        "162.159.192.42",
        "162.159.192.1",
    ]

    /// Known-good seed ENDPOINTS (ip:port) prepended to every ENDPOINT scan.
    static let warpSeedEndpoints: [(ip: String, port: Int)] = [
        ("188.114.96.1", 2408),
        ("162.159.192.42", 2408),
        ("162.159.192.1", 894),
        ("162.159.192.1", 928),
    ]

    /// WARP IPv6 endpoints embed the IPv4 pool:
    /// 2606:4700:d0::a29f:c001 == 162.159.192.1
    static let warpV6PrefixD0 = "2606:4700:d0::"
    static let warpV6PrefixD1 = "2606:4700:d1::"

    static var warpPortsCount: Int { warpPortsFull.count }

    static func cidrs(for mode: ScanMode, family: NetFamily) -> [String] {
        switch mode {
        case .CF_EDGE:
            switch family {
            case .BOTH: return cfEdgeV4 + cfEdgeV6
            case .V4: return cfEdgeV4
            case .V6: return cfEdgeV6
            }
        case .ENDPOINT:
            switch family {
            case .BOTH: return warpV4 + warpV6
            case .V4: return warpV4
            case .V6: return warpV6
            }
        case .CUSTOM:
            return []
        }
    }

    /// 0 is the ENDPOINT-mode sentinel for "draw a random port per endpoint
    /// from the canonical WARP list" (BPB behavior).
    static func defaultPort(for mode: ScanMode) -> Int {
        mode == .ENDPOINT ? 0 : 443
    }

    static func ports(for mode: ScanMode) -> [Int] {
        mode == .ENDPOINT ? warpPorts : cfEdgePorts
    }
}
