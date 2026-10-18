import Foundation

enum IpProtocol: String, Codable, CaseIterable {
    case IPv4, IPv6
}

enum NetFamily: String, Codable, CaseIterable {
    case BOTH, V4, V6

    var label: String {
        switch self {
        case .BOTH: return "ALL"
        case .V4: return "IPv4"
        case .V6: return "IPv6"
        }
    }
}

/// v3.8 semantics: the standalone WARP mode is gone — ENDPOINT absorbed it.
enum ScanMode: String, Codable, CaseIterable {
    case CF_EDGE
    case CUSTOM
    case ENDPOINT

    var label: String {
        switch self {
        case .CF_EDGE: return "EDGE"
        case .CUSTOM: return "CUSTOM"
        case .ENDPOINT: return "ENDPOINT"
        }
    }

    var tagline: String {
        switch self {
        case .CF_EDGE: return "Cloudflare edge · speed.cloudflare.com"
        case .CUSTOM: return "Your own CIDR list"
        case .ENDPOINT: return "WARP ranges · random ip:port · IPv4 + IPv6 · real WireGuard handshake"
        }
    }
}

enum ScanPhase: Int, Codable {
    case idle, generating, register, tcp, wg, probe, ranking, speed, done

    var label: String {
        switch self {
        case .idle: return "IDLE"
        case .generating: return "GENERATE"
        case .register: return "IDENTITY"
        case .tcp: return "TCP STORM"
        case .wg: return "WG PROBE"
        case .probe: return "TLS PROBE"
        case .ranking: return "RANKING"
        case .speed: return "SPEED TEST"
        case .done: return "COMPLETE"
        }
    }

    var order: Int {
        switch self {
        case .idle: return 0
        case .generating: return 1
        case .register, .tcp: return 2
        case .wg, .probe: return 3
        case .ranking: return 4
        case .speed: return 5
        case .done: return 6
        }
    }
}

enum SortKey: String, CaseIterable {
    case SMART, SCORE, LATENCY, JITTER, LOSS, SPEED
}

struct ScanParams: Codable, Equatable {
    var mode: ScanMode = .CF_EDGE
    var cidrs: [String] = []
    var family: NetFamily = .BOTH
    var port: Int = 443
    var samplesPerPrefix: Int = 96
    var tcpAttempts: Int = 3
    var tcpTimeoutMs: Int = 2000
    var concurrency: Int = 150
    var tlsVerify: Bool = true
    /// EDGE/CUSTOM: how many TCP-alive endpoints get full TLS verification —
    /// the REAL alive filter on DPI-filtered networks.
    var verifyTopN: Int = 400
    var speedTest: Bool = true
    var speedTopN: Int = 50
    var speedConcurrency: Int = 4
    var downloadBytes: Int64 = 20 * 1024 * 1024
    /// ENDPOINT only: random ip:port endpoints to test (BPB EndpointCount).
    var endpointsCount: Int = 500
    /// ENDPOINT only: full WireGuard probe rounds per endpoint.
    var warpAttempts: Int = 3
    /// ENDPOINT only: anti-DPI UDP noise burst before each handshake.
    var udpNoise: Bool = true
    /// ENDPOINT only: noise packets per burst.
    var noiseCount: Int = 5

    var speedSni: String { "speed.cloudflare.com" }

    /// WARP endpoints never serve speed.cloudflare.com on their scan port —
    /// the throughput check always rides 443. Port 0 (= RANDOM) is never
    /// connectable.
    var speedPort: Int {
        switch mode {
        case .ENDPOINT: return 443
        default: return port == 0 ? 443 : port
        }
    }

    /// EDGE/CUSTOM scans ALWAYS TLS-verify their TCP-alive candidates; ENDPOINT
    /// needs no TLS phase — its proof is the WireGuard handshake itself.
    var needsTlsPhase: Bool { tlsVerify && mode != .ENDPOINT }
    var downloadMbLabel: Int { Int(downloadBytes / (1024 * 1024)) }

    /// Every (ip, port) pair the TCP storm will probe (one port per scan).
    var effectivePorts: [Int] { [port] }
}

struct ScanResult: Codable, Equatable, Identifiable {
    var ip: String
    var ipProtocol: IpProtocol
    var port: Int
    var latencyMs: Double? = nil
    var jitterMs: Double? = nil
    var packetLoss: Double = 0.0
    var speedMbps: Double? = nil
    var downloadedBytes: Int64 = 0
    var tcpAttempts: Int = 0
    var successfulAttempts: Int = 0
    var tlsSuccess: Bool = false
    var tlsHandshakeMs: Double? = nil
    var httpStatus: Int? = nil
    /// EDGE/CUSTOM only: TLS verification was disabled — tcp-alive stays.
    var tlsSkipped: Bool = false
    /// ENDPOINT mode: completed WireGuard handshakes.
    var wgHandshakes: Int = 0
    var error: String? = nil
    var mode: ScanMode = .CF_EDGE

    /// An endpoint is alive only when it was PROVEN real:
    ///  - ENDPOINT: a real WireGuard handshake ANSWERED (the BPB definition)
    ///  - EDGE/CUSTOM: full TLS with a valid certificate, or HTTP 200
    /// A bare TCP connect is NOT aliveness — DPI middleboxes fake it.
    var alive: Bool {
        switch mode {
        case .ENDPOINT: return wgHandshakes > 0
        case .CF_EDGE, .CUSTOM: return tlsSuccess || httpStatus == 200 || (tlsSkipped && tcpAlive)
        }
    }

    /// TCP-level reachability only (pre-filter, not proof).
    var tcpAlive: Bool { successfulAttempts > 0 }

    var id: String { "\(ip):\(port)" }
    var lossPct: Int { Int(packetLoss * 100) }

    /// Merge a newer probe result into an older one (same ip:port).
    func merge(newer: ScanResult) -> ScanResult {
        var m = newer
        m.ip = ip
        m.ipProtocol = ipProtocol
        m.port = port
        m.latencyMs = newer.latencyMs ?? latencyMs
        m.jitterMs = newer.jitterMs ?? jitterMs
        m.downloadedBytes = max(downloadedBytes, newer.downloadedBytes)
        m.tlsSuccess = tlsSuccess || newer.tlsSuccess
        m.tlsHandshakeMs = newer.tlsHandshakeMs ?? tlsHandshakeMs
        m.httpStatus = newer.httpStatus ?? httpStatus
        m.wgHandshakes = max(wgHandshakes, newer.wgHandshakes)
        // a stale failure must not haunt a now-verified endpoint
        m.error = newer.error ?? (newer.alive ? nil : error)
        m.mode = mode
        return m
    }
}

struct ScanStats: Equatable {
    var phase: ScanPhase = .idle
    var candidates: Int = 0
    var tested: Int = 0
    var alive: Int = 0
    var tlsOk: Int = 0
    var speedTested: Int = 0
    var active: Int = 0
    var elapsedMs: Int64 = 0
    var ratePerSec: Double = 0.0
    var etaSec: Double? = nil

    var progress: Double {
        candidates == 0 ? 0 : min(1.0, max(0.0, Double(tested) / Double(candidates)))
    }
}

struct ScanSummary: Equatable {
    var cancelled: Bool
    var candidates: Int
    var tested: Int
    var alive: Int
    var best: ScanResult?
    var elapsedMs: Int64
    var params: ScanParams
    var finishedAt: Double = Date().timeIntervalSince1970
    /// When a scan produces ZERO alive endpoints, the most likely
    /// engine-level reason — shown in the Done panel so "no results" is
    /// explainable instead of looking like a silent failure.
    var error: String? = nil
}

enum ScanUiState: Equatable {
    case idle
    case running(params: ScanParams, startedAt: Double)
    case done(summary: ScanSummary)
}
