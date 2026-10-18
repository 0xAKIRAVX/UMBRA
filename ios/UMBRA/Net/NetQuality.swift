import Foundation

enum NetGrade: String, Codable {
    case excellent, good, fair, poor
}

/// NETSENSE — the user's own line, measured. Drives the adaptive
/// SmartRanking weights: on a poor, lossy line stability + low ping dominate;
/// on an excellent line raw throughput dominates. Endpoints are then scored
/// RELATIVE to the user's own measured baseline — "بهترین برای نت من".
struct NetworkProfile: Codable, Equatable {
    /// Best TCP-connect RTT to the CF seeds (ms) — nil when unreachable.
    var latencyMs: Double? = nil
    /// Std-dev of the successful RTT samples (ms).
    var jitterMs: Double? = nil
    /// Failed probes / total ping probes (0..1).
    var packetLoss: Double = 0.0
    /// Real TLS handshake RTT (ms) — cannot be faked by DPI middleboxes.
    var tlsRttMs: Double? = nil
    /// TCP answers but TLS never completes -> the ISP's DPI is fake-accepting.
    var dpiSuspected: Bool = false
    var downloadMbps: Double? = nil
    var uploadMbps: Double? = nil
    var v6Ok: Bool = false
    var measuredAt: Double = Date().timeIntervalSince1970

    var grade: NetGrade {
        let g = NetQuality.gradeOf(latencyMs: latencyMs, jitterMs: jitterMs,
                                   packetLoss: packetLoss, downloadMbps: downloadMbps)
        // a line where TCP answers but real TLS never completes is under DPI
        // fake-accept — its flawless TCP numbers must not grade EXCELLENT
        return (dpiSuspected && g == .excellent) ? .good : g
    }

    /// Age of this measurement in minutes (>= 1).
    var ageMinutes: Int {
        max(1, Int((Date().timeIntervalSince1970 - measuredAt) / 60))
    }

    var hasData: Bool {
        latencyMs != nil || downloadMbps != nil || tlsRttMs != nil
    }
}

enum NetQuality {

    static let pingSeeds = ["1.1.1.1", "162.159.192.1", "104.16.1.1", "188.114.96.1"]
    static let tlsSeeds = ["162.159.192.1", "104.16.1.1"]
    static let v6Seeds = ["2606:4700:4700::1111", "2606:4700:d0::a29f:c001"]

    /// Download sample for the line check (1 MB — quick but meaningful).
    static let downloadBytes: Int64 = 1 * 1024 * 1024
    static let uploadBytes: Int64 = 512 * 1024

    /// Full measurement, ~6-10 s wall time. Steps stream to onStep.
    /// Never throws — unreachable seeds simply produce nil fields.
    static func measure(onStep: @Sendable (String) -> Void = { _ in }) async -> NetworkProfile {
        onStep("pinging cloudflare seeds · 4 × 3 rounds")
        let pings = await pingSamples()
        onStep("checking ipv6 route · 2 seeds")
        let v6 = await probeV6()
        onStep("real tls round-trips · dpi-proof")
        let tls = await tlsRtt()
        onStep("measuring download · 1 mb exact-ip")
        let down = await downloadMbps(v6Ok: v6)
        onStep("measuring upload · 512 kb exact-ip")
        let up = await uploadMbps(v6Ok: v6)
        return NetworkProfile(
            latencyMs: pings.0,
            jitterMs: pings.1,
            packetLoss: pings.2,
            tlsRttMs: tls,
            dpiSuspected: pings.0 != nil && tls == nil,
            downloadMbps: down,
            uploadMbps: up,
            v6Ok: v6)
    }

    /// (best latency, jitter, loss) over 12 interleaved TCP handshakes.
    /// v3.2 semantics: jitter and loss are computed PER SEED and aggregated
    /// from the most responsive seed (pooling distinct anycast endpoints
    /// inflates "jitter" with inter-seed RTT spread).
    private static func pingSamples() async -> (Double?, Double?, Double) {
        var perSeed: [String: [Double]] = [:]
        var failures: [String: Int] = [:]
        let sem = AsyncSemaphore(value: 4)
        await withTaskGroup(of: (String, Double?)?.self) { group in
            for round in 0..<3 {
                for seed in pingSeeds {
                    group.addTask {
                        guard let bytes = IpText.literalToBytes(seed) else { return nil }
                        await sem.wait()
                        defer { sem.signal() }
                        let stats = await TcpProbe.probe(ip: bytes, port: 443, attempts: 1, timeoutMs: 2000)
                        return (seed, stats.latenciesMs.first)
                    }
                }
                if round < 2 {
                    try? await Task.sleep(nanoseconds: 140_000_000)
                }
            }
            for await maybe in group {
                guard let (seed, r) = maybe else { continue }
                if let r = r {
                    perSeed[seed, default: []].append(r)
                } else {
                    failures[seed, default: 0] += 1
                }
            }
        }
        let lat = perSeed.values.flatMap { $0 }.min()
        // the most responsive seed (tie -> lowest median) is the line's honest witness
        let bestSeed = perSeed
            .sorted { a, b in
                if a.value.count != b.value.count { return a.value.count > b.value.count }
                return median(a.value) < median(b.value)
            }
            .first
        var jit: Double? = nil
        var loss: Double = 1.0
        if let (_, samples) = bestSeed {
            if samples.count >= 2 {
                let mean = samples.reduce(0, +) / Double(samples.count)
                let variance = samples.reduce(0) { $0 + ($1 - mean) * ($1 - mean) } / Double(samples.count)
                jit = variance.squareRoot()
            }
            let fails = failures[bestSeed!.key] ?? 0
            let total = fails + samples.count
            loss = total == 0 ? 1.0 : Double(fails) / Double(total)
        }
        return (lat, jit, loss)
    }

    private static func median(_ values: [Double]) -> Double {
        let sorted = values.sorted()
        let n = sorted.count
        return n % 2 == 1 ? sorted[n / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }

    private static func probeV6() async -> Bool {
        await withTaskGroup(of: Bool.self) { group in
            for seed in v6Seeds {
                group.addTask {
                    guard let bytes = IpText.literalToBytes(seed) else { return false }
                    let stats = await TcpProbe.probe(ip: bytes, port: 443, attempts: 1, timeoutMs: 2000)
                    return stats.success
                }
            }
            var any = false
            for await ok in group where ok { any = true }
            return any
        }
    }

    /// Best real TLS handshake time over the seeds; nil when none completes.
    private static func tlsRtt() async -> Double? {
        await withTaskGroup(of: Double?.self) { group in
            for seed in tlsSeeds {
                group.addTask {
                    guard let bytes = IpText.literalToBytes(seed) else { return nil }
                    let res = await ExactIpHttps.tlsProbe(
                        ip: bytes, port: 443, sni: "speed.cloudflare.com",
                        connectTimeoutMs: 2500, readTimeoutMs: 4000)
                    return res.ok ? res.handshakeMs : nil
                }
            }
            var best: Double? = nil
            for await rtt in group {
                if let rtt = rtt { best = best.map { min($0, rtt) } ?? rtt }
            }
            return best
        }
    }

    private static func downloadMbps(v6Ok: Bool) async -> Double? {
        let seed = v6Ok ? "2606:4700:d0::a29f:c001" : "162.159.192.1"
        guard let bytes = IpText.literalToBytes(seed) else { return nil }
        let d = await ExactIpHttps.download(
            ip: bytes, port: 443, sni: "speed.cloudflare.com",
            byteCount: downloadBytes,
            connectTimeoutMs: 2500, readTimeoutMs: 6000, maxDurationMs: 7000)
        if d.httpStatus == 200, d.bytes > 0, d.error == nil, d.durationMs > 0 {
            return Double(d.bytes) * 8.0 / 1000.0 / Double(d.durationMs)
        }
        return nil
    }

    private static func uploadMbps(v6Ok: Bool) async -> Double? {
        // 2606:4700:4700::1111 (1.1.1.1 v6) is the resolver anycast — it does
        // not reliably serve the speed SNI; the WARP v6 edge serves both.
        let seed = v6Ok ? "2606:4700:d0::a29f:c001" : "104.16.1.1"
        guard let bytes = IpText.literalToBytes(seed) else { return nil }
        let u = await ExactIpHttps.upload(
            ip: bytes, port: 443, sni: "speed.cloudflare.com",
            byteCount: uploadBytes,
            connectTimeoutMs: 2500, readTimeoutMs: 6000, maxDurationMs: 7000)
        if u.httpStatus == 200, u.bytes > 0, u.durationMs > 0 {
            return Double(u.bytes) * 8.0 / 1000.0 / Double(u.durationMs)
        }
        return nil
    }

    // ------------------------------------------------------ grading logic ----

    /// Pure grading function: 4 dimensions -> 0..4 points -> grade.
    ///  latency   <60 / <120 / <250 ms
    ///  jitter    <10 / <25  / <60  ms
    ///  loss      <=1% / <5%  / <15%
    ///  download  >20 / >8   / >2   Mbps
    static func gradeOf(latencyMs: Double?, jitterMs: Double?, packetLoss: Double, downloadMbps: Double?) -> NetGrade {
        if latencyMs == nil { return .poor }
        var points = 0.0
        switch latencyMs! {
        case ..<60: points += 1.0
        case ..<120: points += 0.75
        case ..<250: points += 0.45
        default: points += 0.0
        }
        if let jit = jitterMs {
            switch jit {
            case ..<10: points += 1.0
            case ..<25: points += 0.75
            case ..<60: points += 0.40
            default: points += 0.0
            }
        } else {
            points += 0.25
        }
        switch packetLoss {
        case ...0.01: points += 1.0
        case ..<0.05: points += 0.70
        case ..<0.15: points += 0.35
        default: points += 0.0
        }
        if let down = downloadMbps {
            switch down {
            case 20...: points += 1.0
            case 8...: points += 0.75
            case 2...: points += 0.40
            default: points += 0.0
            }
        } else {
            points += 0.30
        }
        switch points {
        case 3.5...: return .excellent
        case 2.4...: return .good
        case 1.4...: return .fair
        default: return .poor
        }
    }

    /// Human label helper for logs.
    static func describe(_ p: NetworkProfile) -> String {
        var s = "net \(p.grade.rawValue)"
        if let lat = p.latencyMs { s += " · ping \(Int(lat.rounded()))ms" }
        if let down = p.downloadMbps { s += Fmt.str(" · down %.1fmbps", down) }
        if p.dpiSuspected { s += " · dpi fake-accept suspected" }
        return s
    }
}

/// Minimal async semaphore (counting) for bounded parallelism.
final class AsyncSemaphore {
    private var value: Int
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private let lock = NSLock()

    init(value: Int) {
        precondition(value >= 1)
        self.value = value
    }

    func wait() async {
        lock.lock()
        if value > 0 {
            value -= 1
            lock.unlock()
            return
        }
        await withCheckedContinuation { cont in
            waiters.append(cont)
            lock.unlock()
        }
    }

    func signal() {
        lock.lock()
        if let first = waiters.first {
            waiters.removeFirst()
            lock.unlock()
            first.resume()
            return
        }
        value += 1
        lock.unlock()
    }
}
