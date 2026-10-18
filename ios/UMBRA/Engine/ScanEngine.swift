import Foundation

/// Events the engine streams to the UI (implemented by ScanController on
/// the MainActor). Every call is an implicit actor hop, so the storm's
/// hundreds of concurrent probes never block a thread to touch the UI.
@MainActor
protocol ScanSink: AnyObject {
    func onPhase(_ phase: ScanPhase)
    func onGenerated(_ count: Int)
    func onResult(_ result: ScanResult)
    func onActive(_ delta: Int)
    func onLog(_ line: String)
    func snapshot() -> [ScanResult]
}

/// v3.6: buckets one probe outcome into a short failure class for the
/// zero-result diagnosis line. nil = success. Pure function.
func classifyWarpProbe(handshakes: Int, pings: Int, cookieReplies: Int, lastError: String?) -> String? {
    if pings > 0 { return nil }
    if handshakes > 0 { return "handshake ok · no data plane" }
    if cookieReplies > 0 { return "cookie reply (alive under load)" }
    guard let e = lastError else { return "no handshake" }
    if e.contains("timeout") { return "handshake timeout" }
    if e.contains("PortUnreachable") { return "icmp port-unreachable" }
    if e.contains("send refused") { return "udp send blocked" }
    return e
}

/// v3.8.1: the ENDPOINT probe pool — census-verified seeds first, then the
/// random draw with any seed pair the draw reproduced REMOVED. Pure function.
func assembleEndpointPool(seeds: [EndpointPair], drawn: [EndpointPair]) -> [EndpointPair] {
    if seeds.isEmpty { return drawn }
    var seedIds = Set<String>()
    seedIds.reserveCapacity(seeds.count * 2)
    for s in seeds { seedIds.insert(s.id) }
    return seeds + drawn.filter { !seedIds.contains($0.id) }
}

/// UMBRA scan engine — a faithful Swift port of the v3.11 Android engine.
///
/// Phase 1  generate   — random candidates per CIDR / BPB-style endpoint pairs
/// Phase 2  register   — ENDPOINT: a silent WARP identity (the handshake KEY)
/// Phase 3  witness    — pre-flight gate + recovery ladder (sweep & re-aim)
/// Phase 4  storm      — ENDPOINT: real WireGuard handshakes; EDGE: TCP
/// Phase 5  verify     — EDGE/CUSTOM: TLS cert verification (DPI-fake filter)
/// Phase 6  speed      — exact-IP HTTPS download
///
/// Fully cooperatively cancellable; every wait is event-driven.
final class ScanEngine {

    struct WitnessHit {
        let pair: EndpointPair
        let rttMs: Double
    }

    /// v3.3 guard: extreme settings could queue a multi-hour storm.
    static let probeCap = 120_000
    /// v3.9: pre-flight witness budget.
    static let witnessTimeoutMs = 2000
    /// v3.9: witness pool size (seeds + this many random pairs).
    static let witnessRandom = 12
    /// v3.10: recovery-sweep budget per probe.
    static let sweepTimeoutMs = 1500
    /// v3.10: drawn pool IPs riding the sweep alongside the seeds.
    static let sweepExtraPoolIps = 2

    /// v3.6: per-scan tally of WHY warp probes failed.
    private let failureLock = NSLock()
    private var warpFailures: [String: Int] = [:]

    private let rng: Rng

    /// Test seams (production defaults wire the real network stack).
    var registrationProvider: (_ licenseKey: String?, _ fresh: Bool) async throws -> WarpAccount =
        { key, fresh in try await WarpRegistration.register(licenseKey: key, fresh: fresh) }
    var witnessProber: (_ account: WarpAccount, _ pairs: [EndpointPair], _ budgetMs: Int) async -> Int =
        { acc, pairs, budget in await ScanEngine.runWitnessRoundDetailed(acc, pairs: pairs, budgetMs: budget).count }
    var sweepProber: (_ account: WarpAccount, _ pairs: [EndpointPair], _ budgetMs: Int) async -> [WitnessHit] =
        { acc, pairs, budget in await ScanEngine.runWitnessRoundDetailed(acc, pairs: pairs, budgetMs: budget) }
    var evidenceGatherer: (_ timeoutMs: Int) async -> UdpEvidence.Evidence? =
        { t in await UdpEvidence.gather(timeoutMs: t) }

    init(rng: Rng = Rng()) {
        self.rng = rng
    }

    // MARK: - run

    func run(_ params: ScanParams, sink: ScanSink) async throws {
        failureLock.lock()
        warpFailures.removeAll()
        failureLock.unlock()

        await sink.onPhase(.generating)

        // ---- v3.8: ENDPOINT generates random ip:port PAIRS (BPB) ----
        var endpointPairs: [EndpointPair]? = nil
        if params.mode == .ENDPOINT {
            let drawn = IpGenerator.generateEndpoints(family: params.family, count: params.endpointsCount,
                                                       port: params.port, rng: rng)
            let seeds = Presets.warpSeedEndpoints.compactMap { seed -> EndpointPair? in
                guard let cand = Candidate(literal: seed.ip) else { return nil }
                return EndpointPair(candidate: cand, port: seed.port)
            }
            endpointPairs = assembleEndpointPool(seeds: seeds, drawn: drawn)
        }
        var candidates: [Candidate] = []
        if endpointPairs == nil {
            candidates = IpGenerator.generate(cidrs: params.cidrs, family: params.family,
                                              samplesPerPrefix: params.samplesPerPrefix, rng: rng)
        }
        let ports = params.effectivePorts
        var pairCount = endpointPairs?.count ?? candidates.count * ports.count
        await sink.onGenerated(pairCount)

        if let pairs = endpointPairs {
            let v4 = pairs.filter { $0.candidate.ipProtocol == .IPv4 }.count
            let v6 = pairs.count - v4
            await sink.onLog(
                "generated \(pairs.count) endpoints · v4 \(v4) · v6 \(v6) · " +
                "\(Presets.warpSeedEndpoints.count) live-verified seeds + " +
                "\(pairs.count - Presets.warpSeedEndpoints.count) random" +
                (params.port > 0 ? " · port \(params.port)" : " · random port each · ×\(Presets.warpPortsCount)"))
            if pairs.isEmpty {
                await sink.onLog("no endpoints — raise the endpoint count")
                await sink.onPhase(.done)
                return
            }
        } else {
            await sink.onLog(
                "generated \(candidates.count) candidates × \(ports.count) port(s) = \(pairCount) probes · port \(params.port)")
            if candidates.isEmpty || ports.isEmpty {
                await sink.onLog("no valid candidates — check CIDR list / port selection")
                await sink.onPhase(.done)
                return
            }
        }

        // ---- v3.8: ENDPOINT identity — one SILENT registration per scan ----
        var account: WarpAccount? = nil
        if params.mode == .ENDPOINT {
            await sink.onPhase(.register)
            await sink.onLog("warp identity · api.cloudflareclient.com (silent · reused 15 min · disk fallback)")
            do {
                account = try await registrationProvider(nil, false)
            } catch let e as CancellationError {
                throw e
            } catch {
                await sink.onLog("identity failed — \(errorDescription(e))")
                account = nil
            }
            if account == nil {
                await sink.onLog(
                    "cannot validate endpoints without a warp identity — registration api " +
                    "unreachable and no stored identity · a tcp-only scan would produce " +
                    "endpoints that never work in wireguard (the v3.7 bug) · scan aborted")
                await sink.onPhase(.done)
                return
            }
            await sink.onLog("warp identity ready · handshake validation live")
        }

        // ---- v3.9/v3.10: pre-flight witness gate + recovery ladder ----
        if params.mode == .ENDPOINT, let acc = account, let pairs = endpointPairs {
            let witnessPairs = ScanEngine.buildWitnessPool(pairs)
            let witnessBudget = ScanEngine.witnessTimeoutMs
            await sink.onLog(
                "pre-flight witness · \(witnessPairs.count) mixed endpoints (v4+v6) · 1 attempt × \(witnessBudget) ms")
            var identity = acc
            var answered = await witnessProber(identity, witnessPairs, witnessBudget)
            if answered > 0 {
                await sink.onLog("pre-flight witness · \(answered)/\(witnessPairs.count) answered · udp path live")
            } else {
                await sink.onLog(
                    "pre-flight witness · 0/\(witnessPairs.count) answered (seeds included) — " +
                    "re-registering a fresh identity to rule out a stale key")
                var fresh: WarpAccount? = nil
                do {
                    fresh = try await registrationProvider(nil, true)
                } catch let e as CancellationError {
                    throw e
                } catch {
                    fresh = nil
                }
                if let f = fresh {
                    identity = f
                    answered = await witnessProber(identity, witnessPairs, witnessBudget)
                }
                if answered > 0 {
                    await sink.onLog("pre-flight witness · fresh identity · \(answered)/\(witnessPairs.count) answered · udp path live")
                    account = identity
                } else {
                    account = identity
                    // recovery ladder: full-port sweep, v4 then v6
                    let sweepV4 = ScanEngine.buildSweepPool(pairs, v6: false)
                    let sweepV6 = ScanEngine.buildSweepPool(pairs, v6: true)
                    var hits = await runSweepRound(identity: identity, pairs: sweepV4, label: "v4 · full port grid", sink: sink)
                    if hits.isEmpty {
                        hits = await runSweepRound(identity: identity, pairs: sweepV6, label: "v6 twins · full port grid", sink: sink)
                    }
                    if !hits.isEmpty {
                        // a PROVEN path exists on this network — re-aim
                        let v4Hit = hits.contains { $0.pair.candidate.ipProtocol == .IPv4 }
                        let v6Hit = hits.contains { $0.pair.candidate.ipProtocol == .IPv6 }
                        let winningPorts = Array(Set(hits.map { $0.pair.port })).sorted()
                        let reAimed = ScanEngine.reAimPool(targetSize: pairCount, hits: hits,
                                                           configuredFamily: params.family, rng: rng)
                        endpointPairs = reAimed
                        pairCount = reAimed.count
                        await sink.onGenerated(pairCount)
                        if fresh == nil {
                            await sink.onLog(
                                "recovery sweep answered with the STORED identity — the key is " +
                                "alive, the scan's configured path was the filtered part")
                        }
                        await sink.onLog(
                            "scan re-aimed · \(hits.count) proven \(v4Hit && v6Hit ? "v4+v6" : (v6Hit ? "ipv6" : "v4")) " +
                            "path(s) → \(reAimed.count) pairs on winning port(s) " +
                            "\(winningPorts.map(String.init).joined(separator: "/")) · storm rolling")
                    } else {
                        let sweepIps = Set(sweepV4.map { $0.candidate.text }).count
                            + Set(sweepV6.map { $0.candidate.text }).count
                        let why = fresh == nil
                            ? "identity may be expired and the registration api is unreachable — a stored identity is the only one available on this network"
                            : "warp udp is silent on this network even with a fresh identity"
                        await sink.onLog("witness verdict · \(why)")
                        let gateDiag = await evidenceDiagnosis(witnessBudget)
                        if !gateDiag.isEmpty { await sink.onLog(gateDiag) }
                        await sink.onLog(
                            "endpoint scan aborted — \(pairCount) dead probes would only repeat " +
                            "this verdict · recovery sweep already covered " +
                            "\(Presets.warpPortsCount) ports × \(sweepIps) ips on v4+v6 · " +
                            "try: another network/isp · disconnect any active vpn")
                        await sink.onPhase(.done)
                        return
                    }
                }
            }
        }

        // ---- v3.3 guard: cap the workload ----
        var trimmedByCap = false
        if pairCount > ScanEngine.probeCap {
            trimmedByCap = true
            if let pairs = endpointPairs {
                endpointPairs = pairs.shuffled(usingRng: rng).prefix(ScanEngine.probeCap).map { $0 }
                pairCount = endpointPairs!.count
            } else {
                // trim in RANDOM order — the generator emits blocks sequentially
                let trimmed = candidates.shuffled(usingRng: rng)
                    .prefix(max(1, ScanEngine.probeCap / max(1, ports.count)))
                candidates = Array(trimmed)
                pairCount = candidates.count * ports.count
            }
        }
        if trimmedByCap {
            await sink.onLog("probe budget capped · \(ScanEngine.probeCap) pairs max — trimmed to \(pairCount)")
        }
        await sink.onGenerated(pairCount)

        // ---- probe storm ----
        let isWg = params.mode == .ENDPOINT && account != nil
        await sink.onPhase(isWg ? .wg : .tcp)
        let counters = StormCounters()
        let lanes = min(500, max(4, params.concurrency))

        // v3.9 heartbeat — proves liveness with real numbers while the storm
        // grinds through an all-dead pool before the first result lands
        let heartbeat: Task<Void, Never>? = isWg ? Task {
            var beat = 0
            while true {
                do {
                    try await Task.sleep(nanoseconds: 10_000_000_000)
                } catch { return }
                beat += 1
                if Task.isCancelled { return }
                if counters.probed == 0 || beat % 3 == 0 {
                    await sink.onLog(
                        "wg storm · \(counters.probed)/\(pairCount) probed · \(counters.active) lanes busy")
                }
            }
        } : nil

        // the worker pool: N lanes each pull the next pair off the queue.
        // Every wait inside a probe is event-driven, so N lanes == N truly
        // concurrent UDP exchanges with ZERO blocked threads (the Android
        // v3.9 "elastic lanes" fix, achieved structurally).
        let stormQueue = StormQueue(endpointPairs ?? cartesianPairs(candidates: candidates, ports: ports))
        try await withTaskGroup(of: Void.self) { group in
            for _ in 0..<lanes {
                group.addTask {
                    while let pair = await stormQueue.next() {
                        if Task.isCancelled { return }
                        await sink.onActive(1)
                        counters.bumpActive()
                        let result: ScanResult
                        do {
                            if isWg, let acc = account {
                                result = try await self.probeWarp(acc, pair.candidate, pair.port, params)
                            } else {
                                result = try await self.probeTcp(pair.candidate, pair.port, params)
                            }
                        } catch let e as CancellationError {
                            counters.dropActive()
                            await sink.onActive(-1)
                            throw e
                        } catch {
                            // a UDP/TCP error on one endpoint must never kill
                            // the remaining thousands of probes in the storm
                            result = ScanEngine.deadProbe(pair.candidate, port: pair.port, params: params,
                                                          reason: "probe \(errorDescription(error))")
                        }
                        await sink.onResult(result)
                        counters.dropActive()
                        await sink.onActive(-1)
                        if isWg { counters.bumpProbed() }
                    }
                }
            }
            try await group.waitForAll()
        }
        heartbeat?.cancel()

        if isWg {
            let snap = await sink.snapshot()
            let alive4 = snap.filter { $0.alive && $0.ipProtocol == .IPv4 }.count
            let alive6 = snap.filter { $0.alive && $0.ipProtocol == .IPv6 }.count
            let handshakes = snap.reduce(0) { $0 + $1.wgHandshakes }
            let pings = snap.reduce(0) { $0 + $1.successfulAttempts }
            var line = "endpoint scan done · \(alive4 + alive6) validated of \(pairCount) " +
                "(v4 \(alive4) · v6 \(alive6) · handshakes \(handshakes) · in-tunnel pings \(pings))"
            if alive4 + alive6 == 0 {
                failureLock.lock()
                let failures = warpFailures
                failureLock.unlock()
                if !failures.isEmpty {
                    let reasons = failures.sorted { $0.value > $1.value }.prefix(3)
                        .map { "\($0.key) ×\($0.value)" }
                        .joined(separator: " · ")
                    line += " — \(reasons)"
                }
                let diag = await evidenceDiagnosis(max(1200, params.tcpTimeoutMs))
                if !diag.isEmpty { line += " · \(diag)" }
            }
            await sink.onLog(line)
        } else {
            let tcpAlive = await sink.snapshot().filter { $0.tcpAlive }.count
            await sink.onLog("tcp storm done · \(tcpAlive) tcp-alive of \(pairCount) → tls verification next")
        }

        // ---- TLS verification (EDGE/CUSTOM): the REAL aliveness filter ----
        if params.needsTlsPhase {
            await sink.onPhase(.probe)
            let pool = (await sink.snapshot()).filter { $0.tcpAlive }
            // natural (arrival) order — NOT latency-sorted: on censored
            // networks fake-DPI endpoints win every latency race
            let targets = pool.prefix(min(2000, max(50, params.verifyTopN)))
            if !targets.isEmpty {
                await sink.onLog(
                    "tls verifying \(targets.count)/\(pool.count) tcp-alive · sni=\(params.speedSni) · " +
                    "dpi-fake endpoints are discarded here")
                await mapInParallel(Array(targets), parallelism: 48, transform: { r in
                    guard let bytes = IpText.literalToBytes(r.ip) else { return nil }
                    let res = await self.tlsProbe(bytes, port: r.port, sni: params.speedSni, params: params)
                    var out = r
                    out.tlsSuccess = res.ok
                    out.tlsHandshakeMs = res.handshakeMs
                    out.error = res.ok ? nil : (res.error ?? "tls failed")
                    return out
                }, sink: sink)
                let verified = (await sink.snapshot()).filter { $0.alive }.count
                let skipped = pool.count - targets.count
                await sink.onLog(
                    "tls verify done · \(verified) real of \(pool.count) tcp-alive" +
                    (skipped > 0 ? " · \(skipped) skipped (cap \(params.verifyTopN))" : ""))
            }
        }

        // ---- exact-IP HTTPS speed test ----
        if params.speedTest {
            await sink.onPhase(.ranking)
            let pool = (await sink.snapshot()).filter { $0.alive }
                .sorted { ($0.latencyMs ?? .infinity) < ($1.latencyMs ?? .infinity) }
                .prefix(min(500, max(5, params.speedTopN)))
            await sink.onPhase(.speed)
            if !pool.isEmpty {
                let speedPort = params.speedPort
                let portLabel = params.mode == .ENDPOINT ? " on :443 (edge bonus)" : " on :\(speedPort)"
                await sink.onLog(
                    "speed testing \(pool.count) endpoints · \(params.downloadMbLabel) MB via \(params.speedSni)\(portLabel)")
                await mapInParallel(Array(pool), parallelism: min(16, max(1, params.speedConcurrency)), transform: { r in
                    guard let bytes = IpText.literalToBytes(r.ip) else { return nil }
                    let d = await ExactIpHttps.download(
                        ip: bytes, port: speedPort, sni: params.speedSni,
                        byteCount: params.downloadBytes,
                        connectTimeoutMs: max(2000, params.tcpTimeoutMs),
                        readTimeoutMs: 8000, maxDurationMs: 15000)
                    var mbps: Double? = nil
                    if d.httpStatus == 200, d.bytes > 0, d.error == nil {
                        mbps = Double(d.bytes) * 8.0 / 1000.0 / Double(d.durationMs)
                    }
                    var out = r
                    out.speedMbps = mbps
                    out.downloadedBytes = d.bytes
                    out.tlsSuccess = d.tlsOk || r.tlsSuccess
                    out.tlsHandshakeMs = d.handshakeMs ?? r.tlsHandshakeMs
                    out.httpStatus = d.httpStatus
                    // a failed bonus measurement must never taint an endpoint
                    // that already passed its own mode's alive proof
                    out.error = (mbps == nil && params.mode != .ENDPOINT) ? (d.error ?? "no measurable throughput") : nil
                    return out
                }, sink: sink)
            }
        }

        // ---- persist the anti-replay timestamp high-water mark ----
        if params.mode == .ENDPOINT, account != nil {
            WarpRegistration.persistTimestampMark()
        }

        await sink.onPhase(.done)
    }

    // MARK: - probes

    private func tlsProbe(_ bytes: [UInt8], port: Int, sni: String,
                          params: ScanParams) async -> ExactIpHttps.TlsProbeResult {
        await ExactIpHttps.tlsProbe(ip: bytes, port: port, sni: sni,
                                    connectTimeoutMs: max(1500, params.tcpTimeoutMs),
                                    readTimeoutMs: 6000)
    }

    private func probeTcp(_ cand: Candidate, _ port: Int, _ params: ScanParams) async throws -> ScanResult {
        let t = await TcpProbe.probe(ip: cand.bytes, port: port, attempts: params.tcpAttempts,
                                     timeoutMs: params.tcpTimeoutMs)
        let lat = t.latenciesMs
        let total = lat.count + t.failures
        let loss = total == 0 ? 1.0 : Double(t.failures) / Double(total)
        return ScanResult(
            ip: cand.text,
            ipProtocol: cand.ipProtocol,
            port: port,
            latencyMs: lat.min(),
            jitterMs: TcpProbe.jitterOf(lat),
            packetLoss: loss,
            tcpAttempts: total,
            successfulAttempts: lat.count,
            error: lat.isEmpty ? (t.lastError ?? "unreachable") : nil,
            tlsSkipped: !params.tlsVerify,
            mode: params.mode)
    }

    /// REAL WARP endpoint validation: anti-DPI noise -> full WireGuard
    /// handshake -> ICMP echo INSIDE the tunnel. A handshake response alone
    /// proves the endpoint speaks WARP on this exact port over UDP (alive);
    /// the in-tunnel ping is the bonus data-plane proof.
    private func probeWarp(_ account: WarpAccount, _ cand: Candidate, _ port: Int,
                           _ params: ScanParams) async throws -> ScanResult {
        let probe = WarpProbe(
            account: account,
            noise: UdpNoiseConfig(enabled: params.udpNoise, count: params.noiseCount))
        let t = await probe.probe(
            ip: cand.bytes,
            port: port,
            attempts: min(7, max(1, params.warpAttempts)),
            timeoutMs: max(2000, params.tcpTimeoutMs),
            interAttemptDelayMs: 200)
        if let key = classifyWarpProbe(handshakes: t.handshakes, pings: t.pings,
                                       cookieReplies: t.cookieReplies, lastError: t.lastError) {
            failureLock.lock()
            warpFailures[key, default: 0] += 1
            failureLock.unlock()
        }
        var error: String? = nil
        if t.pings == 0 {
            if t.handshakes > 0 {
                error = t.lastError ?? "handshake ok · no data plane"
            } else if t.cookieReplies > 0 {
                error = "cookie reply · endpoint alive under load"
            } else {
                error = t.lastError ?? "no handshake"
            }
        }
        return ScanResult(
            ip: cand.text,
            ipProtocol: cand.ipProtocol,
            port: port,
            latencyMs: t.avgPingMs ?? t.avgHandshakeMs,
            jitterMs: t.jitterMs,
            packetLoss: t.loss,
            tcpAttempts: t.attempts,
            successfulAttempts: t.pings,
            wgHandshakes: t.handshakes,
            error: error,
            mode: params.mode)
    }

    /// Fallback result for a probe whose machinery itself threw.
    static func deadProbe(_ cand: Candidate, port: Int, params: ScanParams, reason: String) -> ScanResult {
        ScanResult(ip: cand.text, ipProtocol: cand.ipProtocol, port: port,
                   packetLoss: 1.0, tcpAttempts: 1, successfulAttempts: 0,
                   error: reason, tlsSkipped: !params.tlsVerify, mode: params.mode)
    }

    // MARK: - witness / sweep / re-aim (pure + shared)

    /// The witness pool: census seeds first, then a family-balanced random
    /// tail (v3.10: the v6 pairs sit at the END of the generated pool — a
    /// front-of-pool tail would never probe v6 on dual-stack scans).
    static func buildWitnessPool(_ pool: [EndpointPair]) -> [EndpointPair] {
        let seedCount = Presets.warpSeedEndpoints.count
        let seeds = pool.prefix(seedCount)
        let rest = pool.drop(seedCount)
        let v4 = rest.filter { $0.candidate.ipProtocol == .IPv4 }
        let v6 = rest.filter { $0.candidate.ipProtocol == .IPv6 }
        if v4.isEmpty { return Array(seeds) + v6.prefix(witnessRandom) }
        if v6.isEmpty { return Array(seeds) + v4.prefix(witnessRandom) }
        return Array(seeds) + v4.prefix(witnessRandom / 2) + v6.prefix(witnessRandom - witnessRandom / 2)
    }

    /// v3.10: the recovery sweep grid — seed IPs + a few drawn pool IPs, each
    /// crossed with EVERY canonical WARP port. v6 selects the v4-embedded
    /// twins. Deduplicated on ip:port.
    static func buildSweepPool(_ pool: [EndpointPair], v6: Bool) -> [EndpointPair] {
        let seedIps = Presets.warpSeedV4.compactMap { IpText.literalToBytes($0) }
        let seedTexts = Set(seedIps.map { IpText.format($0) })
        let poolIps = pool.drop(Presets.warpSeedEndpoints.count)
            .filter { $0.candidate.ipProtocol == .IPv4 }
            .map { $0.candidate }
            .filter { !seedTexts.contains($0.text) }
        var dedup: [String: Candidate] = [:]
        for c in poolIps where dedup[c.text] == nil { dedup[c.text] = c }
        let extra = dedup.values.prefix(sweepExtraPoolIps).map { $0.bytes }
        let ips = seedIps + Array(extra)
        let portsList = Presets.warpPortsFull
        var out: [EndpointPair] = []
        out.reserveCapacity(ips.count * portsList.count)
        var seen = Set<String>(minimumCapacity: ips.count * portsList.count * 2)
        for ip in ips {
            let cand: Candidate
            if v6 {
                guard let bytes = IpGenerator.v6Embedded(prefix: Presets.warpV6PrefixD0, v4: ip) else { continue }
                cand = Candidate(bytes)
            } else {
                cand = Candidate(ip)
            }
            for p in portsList {
                let key = "\(cand.text):\(p)"
                if seen.insert(key).inserted {
                    out.append(EndpointPair(candidate: cand, port: p))
                }
            }
        }
        return out
    }

    /// v3.10: rebuilds the scan pool onto a PROVEN path — sweep winners lead,
    /// the rest is re-drawn on the winning ports; family follows what
    /// actually answered. Never fewer pairs than the winners themselves.
    static func reAimPool(targetSize: Int, hits: [WitnessHit], configuredFamily: NetFamily, rng: Rng) -> [EndpointPair] {
        var winnerIds = Set<String>()
        var winners: [EndpointPair] = []
        for h in hits where !winnerIds.contains(h.pair.id) {
            winnerIds.insert(h.pair.id)
            winners.append(h.pair)
        }
        let winningPorts = Array(Set(hits.map { $0.pair.port })).sorted()
        let v4Won = winners.contains { $0.candidate.ipProtocol == .IPv4 }
        let v6Won = winners.contains { $0.candidate.ipProtocol == .IPv6 }
        // a one-sided answer overrides the configured family (that IS the
        // recovery) but never DOWNGRADES a both-family win
        let family: NetFamily
        if v4Won && v6Won {
            family = configuredFamily
        } else if v6Won {
            family = .V6
        } else {
            family = .V4
        }
        let need = max(0, targetSize - winners.count)
        let drawn = IpGenerator.generateEndpoints(family: family, count: need, portChoices: winningPorts, rng: rng)
        return winners + drawn.filter { !winnerIds.contains($0.id) }
    }

    /// One sweep round, logged end-to-end — returns the answering pairs.
    private func runSweepRound(identity: WarpAccount, pairs: [EndpointPair], label: String,
                               sink: ScanSink) async -> [WitnessHit] {
        if pairs.isEmpty { return [] }
        let ipCount = Set(pairs.map { $0.candidate.text }).count
        let portCount = Set(pairs.map { $0.port }).count
        await sink.onLog(
            "recovery sweep · \(label) · \(ipCount) ips × \(portCount) ports · 1 attempt × \(ScanEngine.sweepTimeoutMs) ms")
        let hits = (try? await sweepProber(identity, pairs, ScanEngine.sweepTimeoutMs)) ?? []
        if hits.isEmpty {
            await sink.onLog("recovery sweep · \(label) · 0/\(pairs.count) answered")
        } else {
            let best = hits.prefix(3).map { h in
                "\(h.pair.candidate.text):\(h.pair.port)" +
                (h.rttMs < Double.greatestFiniteMagnitude ? Fmt.str(" %.0fms", h.rttMs) : "")
            }.joined(separator: " · ")
            await sink.onLog("recovery sweep · \(label) · \(hits.count)/\(pairs.count) answered · \(best)")
        }
        return hits
    }

    /// One real witness/sweep round — answering pairs sorted by RTT.
    static func runWitnessRoundDetailed(_ acc: WarpAccount, pairs: [EndpointPair],
                                        budgetMs: Int) async -> [WitnessHit] {
        // v3.10: up to 128 lanes so the sweep grid never queues behind a few
        // 2-second waits (the recovery ladder must not itself freeze)
        let probe = WarpProbe(acc, noise: UdpNoiseConfig(enabled: true, count: 3))
        let sem = AsyncSemaphore(value: min(128, max(4, pairs.count)))
        return await withTaskGroup(of: WitnessHit?.self) { group in
            for pair in pairs {
                group.addTask {
                    await sem.wait()
                    defer { sem.signal() }
                    let st = await probe.probe(ip: pair.candidate.bytes, port: pair.port,
                                               attempts: 1, timeoutMs: budgetMs, interAttemptDelayMs: 0)
                    if st.handshakes > 0 || st.cookieReplies > 0 {
                        let rtt = st.handshakeLatenciesMs.first
                            ?? st.pingLatenciesMs.first
                            ?? Double.greatestFiniteMagnitude
                        return WitnessHit(pair: pair, rttMs: rtt)
                    }
                    return nil
                }
            }
            var hits: [WitnessHit] = []
            for await h in group {
                if let h = h { hits.append(h) }
            }
            return hits.sorted { $0.rttMs < $1.rttMs }
        }
    }

    /// v3.8: zero-result ENDPOINT diagnosis — independent NTP witnesses +
    /// an active system VPN hint. Runs ONLY on negative verdicts.
    private func evidenceDiagnosis(_ timeoutMs: Int) async -> String {
        var parts: [String] = []
        if let evidence = try? await evidenceGatherer(timeoutMs) {
            parts.append(UdpEvidence.describe(evidence))
        }
        if let hint = await VpnSensor.hint() {
            parts.append(hitTrimmed(hint))
        }
        return parts.joined(separator: " · ")
    }

    private func hitTrimmed(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespaces)
    }

    // MARK: - plumbing

    /// Runs `transform` over items with bounded parallelism; each non-nil
    /// partial feeds the sink (which drives UI merges on the MainActor).
    private func mapInParallel(
        _ items: [ScanResult],
        parallelism: Int,
        transform: @escaping (ScanResult) async -> ScanResult?,
        sink: ScanSink
    ) async {
        let sem = AsyncSemaphore(value: max(1, parallelism))
        await withTaskGroup(of: Void.self) { group in
            for item in items {
                group.addTask {
                    await sem.wait()
                    defer { sem.signal() }
                    if let r = await transform(item) {
                        await sink.onResult(r)
                    }
                }
            }
            _ = await group.waitForAll()
        }
    }

    private func cartesianPairs(candidates: [Candidate], ports: [Int]) -> [EndpointPair] {
        var out: [EndpointPair] = []
        out.reserveCapacity(candidates.count * ports.count)
        for c in candidates {
            for p in ports {
                out.append(EndpointPair(candidate: c, port: p))
            }
        }
        return out
    }
}

// MARK: - helpers

/// Lock-protected counters for the storm heartbeat.
final class StormCounters {
    private let lock = NSLock()
    private(set) var probed: Int = 0
    private(set) var active: Int = 0

    func bumpProbed() {
        lock.lock(); probed += 1; lock.unlock()
    }

    func bumpActive() {
        lock.lock(); active += 1; lock.unlock()
    }

    func dropActive() {
        lock.lock(); active -= 1; lock.unlock()
    }
}

/// FIFO work queue shared by the storm's worker lanes.
actor StormQueue {
    private let items: [EndpointPair]
    private var idx = 0

    init(_ items: [EndpointPair]) {
        self.items = items
    }

    func next() -> EndpointPair? {
        guard idx < items.count else { return nil }
        defer { idx += 1 }
        return items[idx]
    }
}

extension Array where Element == EndpointPair {
    func shuffled(usingRng rng: Rng) -> [EndpointPair] {
        var copy = self
        for i in (1..<copy.count).reversed() {
            let j = rng.int(i + 1)
            copy.swapAt(i, j)
        }
        return copy
    }
}

extension Array where Element == Candidate {
    func shuffled(usingRng rng: Rng) -> [Candidate] {
        var copy = self
        for i in (1..<copy.count).reversed() {
            let j = rng.int(i + 1)
            copy.swapAt(i, j)
        }
        return copy
    }
}

func errorDescription(_ e: Error) -> String {
    if let wg = e as? WgError { return wg.description }
    return "\(e)"
}
