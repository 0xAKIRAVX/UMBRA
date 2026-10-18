import Foundation

/// Fixed classic 0..100 quality score (exports + the SCORE sort chip).
/// The adaptive, network-aware score lives in SmartRanking.
enum Ranking {

    static func scoreOf(_ r: ScanResult) -> Double {
        if !r.alive { return 0.0 }
        guard let lat = r.latencyMs else { return 0.0 }
        let latScore = 1.0 / (1.0 + lat / 100.0)
        let lossScore = 1.0 - min(1.0, max(0.0, r.packetLoss))
        let jitScore = 1.0 / (1.0 + (r.jitterMs ?? 0.0) / 50.0)
        let spd = r.speedMbps
        let speedScore: Double
        if let spd = spd, spd > 0.0 {
            speedScore = min(1.0, log(1.0 + spd) / log(1001.0))
        } else {
            speedScore = 0.30
        }
        let base = 100.0 * (0.34 * latScore + 0.26 * lossScore + 0.20 * speedScore + 0.10 * jitScore)
        return base + (r.tlsSuccess ? 10.0 : 0.0)
    }

    static func sort(_ results: [ScanResult], key: SortKey) -> [ScanResult] {
        switch key {
        case .SMART:
            return SmartRanking.sort(results, profile: nil)
        case .SCORE:
            return results.sorted { scoreOf($0) > scoreOf($1) }
        case .LATENCY:
            return results.filter { $0.latencyMs != nil }
                .sorted { ($0.latencyMs ?? .infinity) < ($1.latencyMs ?? .infinity) }
        case .JITTER:
            return results.filter { $0.jitterMs != nil }
                .sorted { ($0.jitterMs ?? .infinity) < ($1.jitterMs ?? .infinity) }
        case .LOSS:
            return results.filter { $0.alive }.sorted { $0.packetLoss < $1.packetLoss }
        case .SPEED:
            return results.filter { $0.speedMbps != nil }
                .sorted { ($0.speedMbps ?? 0) > ($1.speedMbps ?? 0) }
        }
    }
}

/// SMART RANKING — endpoints scored for the user's OWN line.
/// Baseline-relative latency + grade-adaptive weights (excellent line ->
/// throughput dominates; poor line -> stability + low ping dominate).
enum SmartRanking {

    struct Weights {
        let latency: Double
        let stability: Double
        let speed: Double
    }

    static let neutral = Weights(latency: 0.34, stability: 0.36, speed: 0.30)

    static func weightsFor(_ profile: NetworkProfile?) -> Weights {
        switch profile?.grade {
        case .none: return neutral
        case .excellent: return Weights(latency: 0.30, stability: 0.20, speed: 0.50)
        case .good: return Weights(latency: 0.35, stability: 0.25, speed: 0.40)
        case .fair: return Weights(latency: 0.40, stability: 0.35, speed: 0.25)
        case .poor: return Weights(latency: 0.45, stability: 0.45, speed: 0.10)
        }
    }

    /// 0..1 — latency relative to the user's measured baseline when known.
    static func latencyScore(_ r: ScanResult, baselineMs: Double?) -> Double {
        guard let lat = r.latencyMs else { return 0.0 }
        if let baseline = baselineMs, baseline > 0.0 {
            let rel = lat / baseline
            // 1.0 at baseline, e^-0.55 ≈ 0.58 at 1.25×, e^-2.2 ≈ 0.11 at 2×
            return min(1.0, max(0.0, exp(-2.2 * (rel - 1.0))))
        }
        return 1.0 / (1.0 + lat / 100.0)
    }

    /// 0..1 — loss dominates, jitter refines. Unknown jitter ≈ moderate.
    static func stabilityScore(_ r: ScanResult) -> Double {
        let lossS = 1.0 - min(1.0, max(0.0, r.packetLoss))
        let jit = r.jitterMs ?? 20.0
        let jitS = 1.0 / (1.0 + jit / 50.0)
        return 0.6 * lossS + 0.4 * jitS
    }

    /// 0..1 — logarithmic in Mbps (1 -> 0.10 · 10 -> 0.34 · 100 -> 0.67).
    static func speedScore(_ r: ScanResult) -> Double {
        guard let spd = r.speedMbps, spd > 0.0 else { return 0.30 }
        return min(1.0, log(1.0 + spd) / log(1001.0))
    }

    /// 0..110 composite — adaptive weights + relative latency + TLS bonus.
    static func score(_ r: ScanResult, profile: NetworkProfile?) -> Double {
        if !r.alive { return 0.0 }
        let w = weightsFor(profile)
        let base = 100.0 * (
            w.latency * latencyScore(r, baselineMs: profile?.latencyMs)
                + w.stability * stabilityScore(r)
                + w.speed * speedScore(r))
        return base + (r.tlsSuccess ? 10.0 : 0.0)
    }

    static func sort(_ results: [ScanResult], profile: NetworkProfile?) -> [ScanResult] {
        results.sorted { score($0, profile: profile) > score($1, profile: profile) }
    }

    // ------------------------------------------------------------- picks ----

    enum PickKind { case best, ping, stable, fast }

    struct Picks {
        let best: ScanResult?
        let ping: ScanResult?
        let stable: ScanResult?
        let fast: ScanResult?

        func of(_ kind: PickKind) -> ScanResult? {
            switch kind {
            case .best: return best
            case .ping: return ping
            case .stable: return stable
            case .fast: return fast
            }
        }
    }

    /// The three askings of the user — پرسرعت‌ترین · پایدارترین · کمترین پینگ —
    /// plus the adaptive best-overall, from one result set.
    static func picks(_ results: [ScanResult], profile: NetworkProfile?) -> Picks {
        let alive = results.filter { $0.alive }
        let best = alive.max { score($0, profile: profile) < score($1, profile: profile) }
        let ping = alive.filter { $0.latencyMs != nil }.min { ($0.latencyMs ?? .infinity) < ($1.latencyMs ?? .infinity) }
        let stable = alive
            .filter { $0.alive }
            .sorted {
                let j0 = $0.jitterMs ?? .infinity
                let j1 = $1.jitterMs ?? .infinity
                if j0 != j1 { return j0 < j1 }
                if $0.packetLoss != $1.packetLoss { return $0.packetLoss < $1.packetLoss }
                return ($0.latencyMs ?? .infinity) < ($1.latencyMs ?? .infinity)
            }
            .first
        let fast = alive.filter { ($0.speedMbps ?? 0.0) > 0.0 }
            .max { ($0.speedMbps ?? 0.0) < ($1.speedMbps ?? 0.0) }
        return Picks(best: best, ping: ping, stable: stable, fast: fast)
    }
}
