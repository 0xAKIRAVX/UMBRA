import Foundation

/// REAL WARP endpoint validator — the UMBRA port of the BPB-Warp-Scanner
/// approach without xray-core:
///
///   UDP noise burst (anti-DPI, random destinations)
///   -> full WireGuard handshake for the registered account
///   -> ICMP echo request to 1.1.1.1 *inside* the encrypted tunnel
///   -> parse the echo reply
///
/// An endpoint is only reported alive when the WireGuard handshake ANSWERED;
/// the in-tunnel ping is the bonus data-plane proof.
struct WarpProbeStats {
    /// Total probe rounds that actually ran.
    let attempts: Int
    /// Handshakes that completed with a valid AEAD response.
    let handshakes: Int
    /// Pings whose echo reply came back inside the tunnel.
    let pings: Int
    /// RTT (ms) of each full ping round-trip.
    let pingLatenciesMs: [Double]
    /// RTT (ms) of each handshake round-trip.
    let handshakeLatenciesMs: [Double]
    let cookieReplies: Int
    let lastError: String?

    var success: Bool { pings > 0 }

    /// BPB-style average latency of successful pings.
    var avgPingMs: Double? {
        pingLatenciesMs.isEmpty ? nil : pingLatenciesMs.reduce(0, +) / Double(pingLatenciesMs.count)
    }

    /// Average handshake round-trip — the ENDPOINT mode's ranking metric when
    /// the in-tunnel ping never answered. A completed handshake alone already
    /// proves the endpoint speaks WireGuard.
    var avgHandshakeMs: Double? {
        handshakeLatenciesMs.isEmpty ? nil : handshakeLatenciesMs.reduce(0, +) / Double(handshakeLatenciesMs.count)
    }

    var jitterMs: Double? {
        if pingLatenciesMs.count < 2 { return nil }
        let mean = pingLatenciesMs.reduce(0, +) / Double(pingLatenciesMs.count)
        let variance = pingLatenciesMs.reduce(0) { $0 + ($1 - mean) * ($1 - mean) } / Double(pingLatenciesMs.count)
        return variance.squareRoot()
    }

    /// v3.8.1 semantics: loss is the fraction of rounds in which the endpoint
    /// answered NOTHING. A round that completed a handshake is a successful
    /// round — the handshake IS the aliveness proof.
    var loss: Double {
        if attempts == 0 { return 1.0 }
        return Double(attempts - max(pings, handshakes)) / Double(attempts)
    }
}

/// v3.9 budget ladder: attempt 0 gets the FULL budget (a congested-but-alive
/// endpoint deserves it); retries 1+ get half (floor 700 ms). Pure function.
func attemptTimeoutMs(attemptIndex: Int, baseTimeoutMs: Int) -> Int {
    if attemptIndex <= 0 { return baseTimeoutMs }
    let half = baseTimeoutMs / 2
    let floor = min(baseTimeoutMs, 700)
    return max(half, floor)
}

/// v3.9: the noise burst is a connection-opening disguise, not a per-packet
/// tax — the full burst rides before the first handshake only; later attempts
/// send a single refresh packet. Pure function.
func noisePacketsFor(attemptIndex: Int, configured: Int) -> Int {
    if attemptIndex <= 0 { return min(50, max(0, configured)) }
    return min(configured, 1)
}

enum WarpProbeBudget {
    /// Does the retry loop stop after the round that just completed?
    /// Silence NEVER stops early — retries exist exactly for it.
    static func stopAfter(fullSeen: Bool, bonusSpent: Bool) -> Bool {
        fullSeen || bonusSpent
    }
}

/// UDP noise config — mirrors BPB's default (5 random packets of 50-100
/// bytes, 1-5 ms apart).
struct UdpNoiseConfig {
    var enabled: Bool = true
    var count: Int = 5
    var minPacket: Int = 50
    var maxPacket: Int = 100
    var minDelayMs: Int = 1
    var maxDelayMs: Int = 5
}

/// One WARP endpoint prober. A fresh instance per probe call carries its own
/// RNG (the class may be shared by concurrent tasks).
final class WarpProbe {

    private let account: WarpAccount
    private let noise: UdpNoiseConfig
    /// Address pinged through the tunnel — Cloudflare's own anycast DNS.
    private let pingTarget: [UInt8]

    init(account: WarpAccount, noise: UdpNoiseConfig = UdpNoiseConfig(),
         pingTarget: [UInt8] = [1, 1, 1, 1]) {
        self.account = account
        self.noise = noise
        self.pingTarget = pingTarget
    }

    /// Probes one endpoint `attempts` times with `timeoutMs` per datagram
    /// wait. `attempts` is the retry CEILING, not a quota — the loop stops
    /// the moment the endpoint is proven (handshake + ping answered, or alive
    /// with its one bonus round).
    func probe(ip: [UInt8], port: Int, attempts: Int, timeoutMs: Int,
               interAttemptDelayMs: Int = 200) async -> WarpProbeStats {
        let rng = Rng()
        let src = parseV4(account.v4) ?? [172, 16, 0, 2]

        var pingLat: [Double] = []
        var hsLat: [Double] = []
        var handshakes = 0
        var pings = 0
        var cookieReplies = 0
        var lastError: String? = nil

        var roundsRun = 0
        var fullSeen = false
        var aliveSeen = false
        var bonusSpent = false
        let maxAttempts = max(1, attempts)
        while roundsRun < maxAttempts && !WarpProbeBudget.stopAfter(fullSeen: fullSeen, bonusSpent: bonusSpent) {
            if Task.isCancelled { break }
            let aliveBeforeRound = aliveSeen
            let budget = attemptTimeoutMs(attemptIndex: roundsRun, baseTimeoutMs: timeoutMs)
            let noiseNow = noisePacketsFor(attemptIndex: roundsRun, configured: noise.count)
            let outcome = await probeOnce(ip: ip, port: port, tunnelSrc: src, budgetMs: budget,
                                          rng: rng, noiseCount: noiseNow)
            roundsRun += 1
            switch outcome {
            case .full(let hsMs, let pingMs):
                handshakes += 1
                pings += 1
                pingLat.append(pingMs)
                hsLat.append(hsMs)
                fullSeen = true
            case .handshakeOnly(let hsMs, let reason):
                handshakes += 1
                hsLat.append(hsMs)
                lastError = "handshake ok · no data plane (\(reason))"
                aliveSeen = true
            case .cookieReply:
                cookieReplies += 1
                aliveSeen = true
            case .failed(let reason):
                lastError = reason
            }
            if aliveBeforeRound && !fullSeen { bonusSpent = true }
            if roundsRun < maxAttempts, interAttemptDelayMs > 0,
               !WarpProbeBudget.stopAfter(fullSeen: fullSeen, bonusSpent: bonusSpent) {
                do {
                    try await Task.sleep(nanoseconds: UInt64(interAttemptDelayMs) * 1_000_000)
                } catch {
                    break
                }
            }
        }

        return WarpProbeStats(
            attempts: max(1, roundsRun),
            handshakes: handshakes,
            pings: pings,
            pingLatenciesMs: pingLat,
            handshakeLatenciesMs: hsLat,
            cookieReplies: cookieReplies,
            lastError: lastError)
    }

    // MARK: - one round

    private enum ProbeOutcome {
        case full(hsMs: Double, pingMs: Double)
        case handshakeOnly(hsMs: Double, reason: String)
        case cookieReply
        case failed(reason: String)
    }

    private func probeOnce(ip: [UInt8], port: Int, tunnelSrc: [UInt8],
                           budgetMs: Int, rng: Rng, noiseCount: Int) async -> ProbeOutcome {
        // 1. anti-DPI noise burst — random destinations, never the target
        if noise.enabled && noiseCount > 0 {
            await NoiseBurst.send(count: noiseCount, cfg: noise, rng: rng)
        }

        // 2. handshake initiation (fresh ephemeral + index + timestamp);
        //    each round rides a FRESH link (a timed-out round killed its link)
        let link = UdpLink(host: IpText.format(ip), port: port)
        defer { link.close() }
        guard await link.waitReady(timeoutMs: 1500) else {
            return .failed(reason: "udp link refused")
        }

        let senderIndex = rng.int32()
        let ephPriv = WgCrypto.clampScalar(Rng.secureBytes(32))
        let built: (packet: [UInt8], pending: WgProtocol.PendingHandshake)
        do {
            built = try WgProtocol.buildInitiation(
                staticPriv: account.privateKey,
                staticPub: account.publicKey,
                responderPub: account.responderPublicKey,
                senderIndex: senderIndex,
                ephemeralPriv: ephPriv)
        } catch {
            return .failed(reason: "initiation build: \(error)")
        }

        let t0 = DispatchTime.now()
        guard await link.send(built.packet) else {
            return .failed(reason: "udp send refused")
        }

        // 3. wait for the response, SKIPPING stray datagrams (WARP ports
        //    co-host QUIC/MASQUE listeners; junk replies must be discarded
        //    while the wait budget continues)
        var resp: [UInt8]? = nil
        let hsDeadline = DispatchTime.now().uptimeNanoseconds + UInt64(budgetMs) * 1_000_000
        while resp == nil {
            let remainingMs = Int((hsDeadline - DispatchTime.now().uptimeNanoseconds) / 1_000_000)
            if remainingMs <= 0 { return .failed(reason: "handshake timeout") }
            guard let datagram = await link.receive(timeoutMs: remainingMs) else {
                return .failed(reason: "handshake timeout")
            }
            if datagram.count == WgProtocol.responseSize || datagram.count == WgProtocol.cookieReplySize {
                resp = datagram
            }
            // anything else: junk from a co-hosted service — skip, keep waiting
        }
        let hsMs = Double(DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1_000_000.0
        let respBytes = resp!

        // 4. consume the response
        let consumed = WgProtocol.consumeResponse(pending: built.pending,
                                                  staticPriv: account.privateKey,
                                                  data: respBytes)
        guard let session = consumed.session else {
            // type 3 cookie reply still proves a live WARP endpoint (under load)
            if respBytes.count == WgProtocol.cookieReplySize && respBytes[0] == WgProtocol.msgCookieReply {
                return .cookieReply
            }
            return .failed(reason: consumed.error)
        }

        // 5. ICMP echo request inside the tunnel
        let ident = 0x8000 | rng.int(0x8000)
        let inner = WgProtocol.icmpEchoRequest(src: tunnelSrc, dst: pingTarget, ident: ident, seq: 1)
        guard let transport = session.buildTransport(inner) else {
            return .handshakeOnly(hsMs: hsMs, reason: "transport build failed")
        }
        let t1 = DispatchTime.now()
        guard await link.send(transport) else {
            return .handshakeOnly(hsMs: hsMs, reason: "ping send refused")
        }
        // same skip-stray loop for the data plane — only a transport packet
        // (type byte 4) carries our echo reply
        var dataBytes: [UInt8]? = nil
        let pingDeadline = DispatchTime.now().uptimeNanoseconds + UInt64(budgetMs) * 1_000_000
        while dataBytes == nil {
            let remainingMs = Int((pingDeadline - DispatchTime.now().uptimeNanoseconds) / 1_000_000)
            if remainingMs <= 0 { return .handshakeOnly(hsMs: hsMs, reason: "ping timeout") }
            guard let datagram = await link.receive(timeoutMs: remainingMs) else {
                return .handshakeOnly(hsMs: hsMs, reason: "ping timeout")
            }
            if datagram.count >= 32 && datagram[0] == WgProtocol.msgTransport {
                dataBytes = datagram
            }
        }
        let pingMs = Double(DispatchTime.now().uptimeNanoseconds - t1.uptimeNanoseconds) / 1_000_000.0
        guard let innerReply = session.openTransport(dataBytes!) else {
            return .handshakeOnly(hsMs: hsMs, reason: "bad transport reply")
        }

        if WgProtocol.parseEchoReply(innerReply, ident: ident, seq: 1) {
            return .full(hsMs: hsMs, pingMs: pingMs)
        }
        return .handshakeOnly(hsMs: hsMs, reason: "not our echo")
    }

    private func parseV4(_ text: String) -> [UInt8]? {
        let parts = text.trimmingCharacters(in: .whitespaces).split(separator: ".")
        guard parts.count == 4 else { return nil }
        var bytes: [UInt8] = []
        for p in parts {
            guard let v = Int(p), v >= 0, v <= 255 else { return nil }
            bytes.append(UInt8(v))
        }
        return bytes
    }
}
