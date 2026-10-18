import XCTest
@testable import UMBRA

/// Core model / CIDR / generator / ranking / VLESS tests (ported from the
/// Kotlin suites where the semantics are identical).
final class CoreTests: XCTestCase {

    // ── IpText ───────────────────────────────────────────────────

    func testLiteralToBytesV4Strict() {
        XCTAssertEqual([162, 159, 192, 1], IpText.literalToBytes("162.159.192.1"))
        XCTAssertEqual([1, 1, 1, 1], IpText.literalToBytes(" 1.1.1.1 "))
        XCTAssertNil(IpText.literalToBytes("162.159.192"))        // 3 parts
        XCTAssertNil(IpText.literalToBytes("1.2.3.4.5"))          // 5 parts
        XCTAssertNil(IpText.literalToBytes("01.2.3.4"))           // leading zero
        XCTAssertNil(IpText.literalToBytes("1.2.3.256"))          // out of range
        XCTAssertNil(IpText.literalToBytes(""))
    }

    func testLiteralToBytesV6() {
        let d0 = IpText.literalToBytes("2606:4700:d0::")
        XCTAssertNotNil(d0)
        XCTAssertEqual([0x26, 0x06, 0x47, 0x00, 0x0d, 0x00], Array(d0!.prefix(6)))
        XCTAssertEqual([UInt8](repeating: 0, count: 10), Array(d0!.suffix(10)))

        XCTAssertEqual("2606:4700:d0::a29f:c001",
                       IpText.format(IpText.literalToBytes("2606:4700:d0::a29f:c001")!))

        // embedded v4 tail
        let mapped = IpText.literalToBytes("::ffff:1.2.3.4")
        XCTAssertNotNil(mapped)
        XCTAssertEqual(Array(mapped!.suffix(4)), [1, 2, 3, 4])

        // full form without compression
        XCTAssertEqual("1:2:3:4:5:6:7:8", IpText.format(IpText.literalToBytes("1:2:3:4:5:6:7:8")!))

        // malformed
        XCTAssertNil(IpText.literalToBytes(":::"))
        XCTAssertNil(IpText.literalToBytes("1:2:3:4:5:6:7:8:9"))
        XCTAssertNil(IpText.literalToBytes("1:2:3:4:5:6:7:z"))
        XCTAssertNil(IpText.literalToBytes("fe80::1%en0"))
    }

    func testFormatIpv6Compression() {
        XCTAssertEqual("::", IpText.formatIpv6([UInt8](repeating: 0, count: 16)))
        XCTAssertEqual("::1", IpText.formatIpv6([UInt8](repeating: 0, count: 15) + [1]))
        // longest zero run wins (RFC 5952)
        let b: [UInt8] = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03]
        XCTAssertEqual("1::2:3", IpText.formatIpv6(b))
    }

    func testForUrl() {
        XCTAssertEqual("1.2.3.4", IpText.forUrl("1.2.3.4"))
        XCTAssertEqual("[2606:4700:d0::]", IpText.forUrl("2606:4700:d0::"))
        XCTAssertEqual("[2606:4700:d0::]", IpText.forUrl("[2606:4700:d0::]"))
    }

    // ── CidrBlock / IpGenerator ──────────────────────────────────

    func testCidrParseMasksHostBits() {
        let b = CidrBlock.parse("162.159.192.37/24")
        XCTAssertNotNil(b)
        XCTAssertEqual(24, b!.prefix)
        XCTAssertEqual(.IPv4, b!.family)
        XCTAssertEqual("162.159.192.0", IpText.format(b!.base))
        // v6 /48 masks the last 80 bits
        let v6 = CidrBlock.parse("2606:4700:d1:1234:5678::1/48")
        XCTAssertNotNil(v6)
        XCTAssertEqual(48, v6!.prefix)
        XCTAssertTrue(v6!.base.dropFirst(6).allSatisfy { $0 == 0 })
        XCTAssertNil(CidrBlock.parse("1.2.3.0/33"))
        XCTAssertNil(CidrBlock.parse("not-a-cidr"))
    }

    func testSampleCandidatesSmallBlockSkipsEdges() {
        // a /24 with samples >= 254 enumerates and skips .0/.255
        let block = CidrBlock.parse("10.0.0.0/24")!
        var out: [[UInt8]] = []
        let rng = Rng(seed: 7)
        block.sampleCandidates(300, rng: rng, into: &out)
        XCTAssertEqual(254, out.count)
        XCTAssertFalse(out.contains { $0[3] == 0 || $0[3] == 255 })
        XCTAssertTrue(out.contains { $0[3] == 1 })
        XCTAssertTrue(out.contains { $0[3] == 254 })
    }

    func testSampleCandidatesRespectsSamplesOnSmallBlocks() {
        // v3.1.1: requested samples < block size -> random-sample instead
        let block = CidrBlock.parse("10.0.0.0/24")!
        var out: [[UInt8]] = []
        block.sampleCandidates(20, rng: Rng(seed: 3), into: &out)
        XCTAssertEqual(20, out.count)
        XCTAssertFalse(out.contains { $0[3] == 0 || $0[3] == 255 })
    }

    func testGenerateEndpointsCountsAndFamilies() {
        let rng = Rng(seed: 42)
        let both = IpGenerator.generateEndpoints(family: .BOTH, count: 100, port: 2408, rng: rng)
        XCTAssertEqual(100, both.count)
        XCTAssertEqual(50, both.filter { $0.candidate.ipProtocol == .IPv4 }.count)
        XCTAssertEqual(50, both.filter { $0.candidate.ipProtocol == .IPv6 }.count)
        // pinned port everywhere
        XCTAssertTrue(both.allSatisfy { $0.port == 2408 })
        // dedup on ip:port
        XCTAssertEqual(Set(both.map { $0.id }).count, both.count)
        // v6 twins live in the d0/d1 prefixes
        for p in both where p.candidate.ipProtocol == .IPv6 {
            XCTAssertTrue(p.candidate.text.hasPrefix("2606:4700:d0:") ||
                          p.candidate.text.hasPrefix("2606:4700:d1:"),
                          "unexpected v6 twin \(p.candidate.text)")
        }
        // v4 candidates stay inside the WARP pool
        let pool = Set(CidrBlock.parseAll(Presets.warpV4).map { IpText.format($0.base).split(separator: ".").dropLast().joined(separator: ".") })
        for p in both where p.candidate.ipProtocol == .IPv4 {
            let prefix = p.candidate.text.split(separator: ".").dropLast().joined(separator: ".")
            XCTAssertTrue(pool.contains(prefix), "v4 outside WARP pool: \(p.candidate.text)")
        }
    }

    func testGenerateEndpointsRandomPortMenu() {
        let pairs = IpGenerator.generateEndpoints(family: .V4, count: 60, port: 0, rng: Rng(seed: 9))
        XCTAssertEqual(60, pairs.count)
        let used = Set(pairs.map { $0.port })
        XCTAssertTrue(used.allSatisfy { Presets.warpPortsFull.contains($0) })
        XCTAssertGreaterThan(used.count, 1, "random ports should spread across the canonical list")
    }

    func testV6Embedded() {
        let bytes = IpGenerator.v6Embedded(prefix: Presets.warpV6PrefixD0, v4: [162, 159, 192, 1])
        XCTAssertNotNil(bytes)
        XCTAssertEqual("2606:4700:d0::a29f:c001", IpText.format(bytes!))
        XCTAssertNil(IpGenerator.v6Embedded(prefix: Presets.warpV6PrefixD0, v4: [1, 2, 3]))
    }

    func testEstimateMatchesSmallBlockSemantics() {
        // one /24 with 96 samples -> 96; one /32 full coverage -> 1
        let est = IpGenerator.estimate(cidrs: ["10.0.0.0/24"], family: .V4, samplesPerPrefix: 96)
        XCTAssertEqual(96, est)
        let estFull = IpGenerator.estimate(cidrs: ["10.0.0.5/32"], family: .V4, samplesPerPrefix: 96)
        XCTAssertEqual(1, estFull)
    }

    // ── engine pure functions ────────────────────────────────────

    func testAssembleEndpointPoolDedupsSeedReproductions() {
        let seed = EndpointPair(candidate: Candidate(literal: "188.114.96.1")!, port: 2408)
        let drawn = [
            seed, // the draw reproduced a seed pair
            EndpointPair(candidate: Candidate(literal: "162.159.193.7")!, port: 2408),
        ]
        let pool = assembleEndpointPool(seeds: [seed], drawn: drawn)
        XCTAssertEqual(2, pool.count)
        XCTAssertEqual(seed.id, pool[0].id) // seeds first
    }

    func testBuildWitnessPoolFamilyBalanced() {
        // v3.10: the tail must probe v6 pairs on dual-stack scans
        let v4 = (1...12).map { EndpointPair(candidate: Candidate(literal: "162.159.192.\($0)")!, port: 2408) }
        let v6 = (1...12).map { EndpointPair(candidate: Candidate(IpText.literalToBytes("2606:4700:d0::a29f:c0\(String(format: "%02x", $0))")!), port: 2408) }
        let seeds = Presets.warpSeedEndpoints.map { EndpointPair(candidate: Candidate(literal: $0.ip)!, port: $0.port) }
        let pool = seeds + v4 + v6
        let witness = ScanEngine.buildWitnessPool(pool)
        XCTAssertEqual(Presets.warpSeedEndpoints.count + 12, witness.count)
        let witnessV6 = witness.filter { $0.candidate.ipProtocol == .IPv6 }.count
        XCTAssertEqual(6, witnessV6, "witness tail must be family-balanced")
    }

    func testBuildSweepPoolGridAndV6Twins() {
        let v4pairs = Presets.warpSeedEndpoints.map { EndpointPair(candidate: Candidate(literal: $0.ip)!, port: $0.port) }
        let sweepV4 = ScanEngine.buildSweepPool(v4pairs, v6: false)
        XCTAssertEqual(Presets.warpSeedV4.count * Presets.warpPortsFull.count, sweepV4.count)
        XCTAssertTrue(sweepV4.allSatisfy { $0.candidate.ipProtocol == .IPv4 && Presets.warpPortsFull.contains($0.port) })
        let sweepV6 = ScanEngine.buildSweepPool(v4pairs, v6: true)
        XCTAssertTrue(sweepV6.allSatisfy { $0.candidate.ipProtocol == .IPv6 })
        XCTAssertEqual(sweepV4.count, sweepV6.count)
    }

    func testReAimPoolWinnersLeadAndFollowWinningPorts() {
        let hitPair = EndpointPair(candidate: Candidate(literal: "162.159.192.42")!, port: 894)
        let hits = [ScanEngine.WitnessHit(pair: hitPair, rttMs: 12)]
        let reAimed = ScanEngine.reAimPool(targetSize: 50, hits: hits, configuredFamily: .V4, rng: Rng(seed: 5))
        XCTAssertEqual(hitPair.id, reAimed.first!.id)
        XCTAssertEqual(50, reAimed.count)
        // v4 winner + v4 configured -> drawn pool stays v4 on the winning port
        XCTAssertTrue(reAimed.dropFirst().allSatisfy { $0.candidate.ipProtocol == .IPv4 && $0.port == 894 })

        // a v6-only win flips the family (that IS the recovery)
        let v6Hit = ScanEngine.WitnessHit(
            pair: EndpointPair(candidate: Candidate(IpText.literalToBytes("2606:4700:d0::a29f:c001")!), port: 2408),
            rttMs: 30)
        let reAimedV6 = ScanEngine.reAimPool(targetSize: 30, hits: [v6Hit], configuredFamily: .BOTH, rng: Rng(seed: 6))
        XCTAssertTrue(reAimedV6.allSatisfy { $0.candidate.ipProtocol == .IPv6 }, "v6-only win must flip the family to v6")
    }

    // ── Model ────────────────────────────────────────────────────

    func testScanResultAliveSemantics() {
        var r = ScanResult(ip: "1.1.1.1", ipProtocol: .IPv4, port: 443, mode: .ENDPOINT)
        XCTAssertFalse(r.alive)
        r.wgHandshakes = 2
        XCTAssertTrue(r.alive, "ENDPOINT alive = handshake answered")

        var e = ScanResult(ip: "1.1.1.1", ipProtocol: .IPv4, port: 443, mode: .CF_EDGE)
        e.successfulAttempts = 3
        XCTAssertFalse(e.alive, "a bare TCP connect is NOT aliveness (DPI middleboxes fake it)")
        e.tlsSuccess = true
        XCTAssertTrue(e.alive)

        var s = ScanResult(ip: "1.1.1.1", ipProtocol: .IPv4, port: 443, mode: .CF_EDGE)
        s.tlsSkipped = true
        s.successfulAttempts = 1
        XCTAssertTrue(s.alive, "TLS-verify off keeps tcp-alive results alive (marked)")
    }

    func testScanResultMergeClearsStaleFailure() {
        let old = ScanResult(ip: "1.1.1.1", ipProtocol: .IPv4, port: 443,
                             latencyMs: 10, error: "timeout", mode: .CF_EDGE)
        let newer = ScanResult(ip: "1.1.1.1", ipProtocol: .IPv4, port: 443,
                               latencyMs: 12, tlsSuccess: true, mode: .CF_EDGE)
        let merged = old.merge(newer: newer)
        XCTAssertEqual(12, merged.latencyMs)
        XCTAssertTrue(merged.tlsSuccess)
        XCTAssertNil(merged.error, "a stale failure must not haunt a now-verified endpoint")
        // error survives when the newer state is still dead
        let newerDead = ScanResult(ip: "1.1.1.1", ipProtocol: .IPv4, port: 443,
                                   latencyMs: 15, error: "unreachable", mode: .CF_EDGE)
        let merged2 = old.merge(newer: newerDead)
        XCTAssertEqual("unreachable", merged2.error)
    }

    func testScanParamsSpeedPortSemantics() {
        var p = ScanParams()
        p.mode = .ENDPOINT
        p.port = 0
        XCTAssertEqual(443, p.speedPort, "ENDPOINT speed always rides 443")
        XCTAssertTrue(p.needsTlsPhase == false, "ENDPOINT needs no TLS phase")
        p.mode = .CF_EDGE
        p.port = 2053
        XCTAssertEqual(2053, p.speedPort)
        XCTAssertTrue(p.needsTlsPhase)
    }

    // ── Ranking / SmartRanking ───────────────────────────────────

    func testRankingScoreOfAliveOnly() {
        let dead = ScanResult(ip: "1.1.1.1", ipProtocol: .IPv4, port: 443, latencyMs: 10, mode: .CF_EDGE)
        XCTAssertEqual(0, Ranking.scoreOf(dead))
        var alive = dead
        alive.tlsSuccess = true
        // lat 10ms -> latScore .909, loss 0 -> 1, jitter nil -> 1, speed nil -> .30
        XCTAssertEqual(82.909, Ranking.scoreOf(alive), accuracy: 0.01)
    }

    func testSmartRankingWeightsFollowGrade() {
        let excellent = NetworkProfile(latencyMs: 30, jitterMs: 2, packetLoss: 0, downloadMbps: 50)
        let poor = NetworkProfile(latencyMs: 300, jitterMs: 80, packetLoss: 0.2, downloadMbps: 0.5)
        XCTAssertEqual(.excellent, excellent.grade)
        XCTAssertEqual(.poor, poor.grade)
        let wE = SmartRanking.weightsFor(excellent)
        let wP = SmartRanking.weightsFor(poor)
        XCTAssertGreaterThan(wE.speed, wP.speed, "excellent line -> speed dominates")
        XCTAssertGreaterThan(wP.stability, wE.stability, "poor line -> stability dominates")
        XCTAssertEqual(0.34, SmartRanking.weightsFor(nil).latency, accuracy: 0.0001)
    }

    func testSmartRankingPicks() {
        func mk(_ ip: String, _ lat: Double, _ jit: Double?, _ spd: Double?) -> ScanResult {
            var r = ScanResult(ip: ip, ipProtocol: .IPv4, port: 443, mode: .CF_EDGE)
            r.latencyMs = lat
            r.jitterMs = jit
            r.speedMbps = spd
            r.tlsSuccess = true
            return r
        }
        let results = [
            mk("1.1.1.1", 20, 8, 10),
            mk("2.2.2.2", 60, 1, 5),
            mk("3.3.3.3", 40, 4, 80),
            mk("4.4.4.4", 90, 30, nil),
        ]
        let picks = SmartRanking.picks(results, profile: nil)
        XCTAssertEqual("1.1.1.1", picks.ping?.ip, "lowest ping")
        XCTAssertEqual("2.2.2.2", picks.stable?.ip, "most stable (jitter first)")
        XCTAssertEqual("3.3.3.3", picks.fast?.ip, "fastest")
        XCTAssertNotNil(picks.best)
    }

    func testNetQualityGrading() {
        XCTAssertEqual(.poor, NetQuality.gradeOf(latencyMs: nil, jitterMs: nil, packetLoss: 1, downloadMbps: nil))
        XCTAssertEqual(.excellent,
                       NetQuality.gradeOf(latencyMs: 30, jitterMs: 5, packetLoss: 0, downloadMbps: 50))
        XCTAssertEqual(.fair,
                       NetQuality.gradeOf(latencyMs: 200, jitterMs: 30, packetLoss: 0.08, downloadMbps: 4))
        // DPI fake-accept caps the grade at GOOD
        var p = NetworkProfile(latencyMs: 30, jitterMs: 2, packetLoss: 0, downloadMbps: 50, dpiSuspected: true)
        XCTAssertEqual(.good, p.grade)
        p.dpiSuspected = false
        XCTAssertEqual(.excellent, p.grade)
    }

    // ── VLESS ────────────────────────────────────────────────────

    func testVlessBuildLink() {
        let cfg = VlessGenerator.Config(
            uuid: "123e4567-e89b-12d3-a456-426614174000",
            host: "162.159.192.42",
            port: 443,
            sni: "my-worker.example.workers.dev",
            wsPath: "/ws",
            remark: "test node")
        let link = VlessGenerator.buildLink(cfg)
        XCTAssertEqual(
            "vless://123e4567-e89b-12d3-a456-426614174000@162.159.192.42:443" +
            "?encryption=none&security=tls&sni=my-worker.example.workers.dev" +
            "&type=ws&host=my-worker.example.workers.dev&path=/ws#test%20node",
            link)
    }

    func testVlessIpv6Brackets() {
        let cfg = VlessGenerator.Config(
            uuid: "123e4567-e89b-12d3-a456-426614174000",
            host: "2606:4700:d0::a29f:c001",
            port: 443,
            sni: "x.example.com",
            wsPath: "/",
            remark: "v6")
        let link = VlessGenerator.buildLink(cfg)
        XCTAssertTrue(link.contains("@[2606:4700:d0::a29f:c001]:443"))
    }

    func testVlessTestOnlySni() {
        XCTAssertTrue(VlessGenerator.isTestOnlySni(""))
        XCTAssertTrue(VlessGenerator.isTestOnlySni("speed.cloudflare.com"))
        XCTAssertFalse(VlessGenerator.isTestOnlySni("my-worker.example.workers.dev"))
    }

    func testVlessUuidValidation() {
        XCTAssertTrue(VlessGenerator.isValidUuid("123e4567-e89b-12d3-a456-426614174000"))
        XCTAssertFalse(VlessGenerator.isValidUuid("not-a-uuid"))
    }

    // ── WarpAccount codec ────────────────────────────────────────

    func testWarpAccountJsonRoundTrip() {
        let acc = WarpAccount(
            privateKey: [UInt8](repeating: 3, count: 32),
            publicKey: [UInt8](repeating: 4, count: 32),
            reserved: [1, 2, 3],
            v6: "fd01:db8::2",
            v4: "172.16.0.2",
            responderPublicKey: [UInt8](repeating: 5, count: 32),
            accountId: "aid-1",
            authToken: "tok-1")
        let json = acc.toJson()!
        let back = WarpAccount.fromJson(json)
        XCTAssertNotNil(back)
        XCTAssertEqual(acc, back)
        // malformed rejected
        XCTAssertNil(WarpAccount.fromJson("{not json"))
        // structurally invalid rejected (short key)
        let short = WarpAccount(privateKey: [1], publicKey: [2], reserved: [3],
                                v6: "fd01::", v4: "172.16.0.2", responderPublicKey: [4])
        XCTAssertNil(WarpAccount.fromJson(short.toJson()!))
    }

    func testRegistrationPayloadShape() {
        let payload = WarpRegistration.buildPayload(publicKeyB64: "AAAABBBB", tosIso: "2026-10-19T00:00:00.000Z")
        XCTAssertTrue(payload.contains("\"type\":\"Android\""))
        XCTAssertTrue(payload.contains("\"model\":\"PC\""))
        XCTAssertTrue(payload.contains("\"warp_enabled\":\"true\""))
        XCTAssertTrue(payload.contains("\"key\":\"AAAABBBB\""))
        XCTAssertTrue(payload.contains("\"locale\":\"en_US\""))
    }

    // ── Exporters ────────────────────────────────────────────────

    func testCsvEscaping() {
        let r = ScanResult(ip: "1.1.1.1", ipProtocol: .IPv4, port: 443,
                           error: "bad, \"quoted\" error", mode: .CF_EDGE)
        let csv = Exporters.csv([r])
        XCTAssertTrue(csv.contains("\"bad, \"\"quoted\"\" error\""))
    }
}
