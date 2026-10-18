import Foundation

/// A registered WARP identity — the WireGuard key pair that makes endpoint
/// validation REAL: endpoints are proven live by a full Noise_IKpsk2
/// handshake for this identity, not by a meaningless TCP connect.
struct WarpAccount: Codable, Equatable {
    /// Clamped X25519 static private key (32 raw bytes).
    let privateKey: [UInt8]
    /// Static public key (32 raw bytes).
    let publicKey: [UInt8]
    /// Registration client_id bytes — informational only (production WARP
    /// servers REJECT packets carrying these bytes in the reserved field,
    /// so they are never written into packets).
    let reserved: [UInt8]
    /// Assigned tunnel IPv6 (no prefix length).
    let v6: String
    /// Assigned tunnel IPv4 (typically 172.16.0.2).
    let v4: String
    /// The WARP peer (responder) static public key — server-side identity.
    let responderPublicKey: [UInt8]
    /// Cloudflare account id + bearer token (for future WARP+ upgrades).
    let accountId: String?
    let authToken: String?

    init(privateKey: [UInt8], publicKey: [UInt8], reserved: [UInt8], v6: String, v4: String,
         responderPublicKey: [UInt8], accountId: String? = nil, authToken: String? = nil) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.reserved = reserved
        self.v6 = v6
        self.v4 = v4
        self.responderPublicKey = responderPublicKey
        self.accountId = accountId
        self.authToken = authToken
    }

    private enum CodingKeys: String, CodingKey {
        case privateKey = "priv"
        case publicKey = "pub"
        case reserved
        case v6, v4
        case responderPublicKey = "peer"
        case accountId = "aid"
        case authToken = "tok"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let b64 = { (key: CodingKeys) -> [UInt8] in
            let s = try? c.decode(String.self, forKey: key)
            return s.flatMap { Data(base64Encoded: $0).map { [UInt8]($0) } } ?? []
        }
        privateKey = b64(.privateKey)
        publicKey = b64(.publicKey)
        reserved = b64(.reserved)
        v6 = (try? c.decode(String.self, forKey: .v6)) ?? ""
        let rawV4 = (try? c.decode(String.self, forKey: .v4)) ?? ""
        v4 = rawV4.isEmpty ? "172.16.0.2" : rawV4
        responderPublicKey = b64(.responderPublicKey)
        accountId = try? c.decode(String.self, forKey: .accountId)
        authToken = try? c.decode(String.self, forKey: .authToken)
    }

    /// The byte fields travel as base64 STRINGS (same JSON the Kotlin side
    /// writes and reads). The synthesized encoder would emit them as JSON
    /// number arrays — which this decoder rejects — so encode explicitly.
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(Data(privateKey).base64EncodedString(), forKey: .privateKey)
        try c.encode(Data(publicKey).base64EncodedString(), forKey: .publicKey)
        try c.encode(Data(reserved).base64EncodedString(), forKey: .reserved)
        try c.encode(v6, forKey: .v6)
        try c.encode(v4, forKey: .v4)
        try c.encode(Data(responderPublicKey).base64EncodedString(), forKey: .responderPublicKey)
        try c.encodeIfPresent(accountId, forKey: .accountId)
        try c.encodeIfPresent(authToken, forKey: .authToken)
    }

    /// Structurally valid? (same acceptance rule as the Kotlin parser)
    var isValid: Bool {
        privateKey.count == 32 && publicKey.count == 32
            && responderPublicKey.count == 32 && !v6.isEmpty
    }

    static func fromJson(_ text: String) -> WarpAccount? {
        guard let data = text.data(using: .utf8) else { return nil }
        guard let acc = try? JSONDecoder().decode(WarpAccount.self, from: data) else { return nil }
        return acc.isValid ? acc : nil
    }

    func toJson() -> String? {
        guard let data = try? JSONEncoder().encode(self) else { return nil }
        return String(data: data, encoding: .utf8)
    }
}

/// Registration flow — the BPB-Warp-Scanner warp.go equivalent: registers a
/// fresh free account with the Cloudflare API, caches it (15 min), persists
/// it (a WARP identity stays valid server-side for weeks) and falls back to
/// the pinned SNI-routed IPs when the domain is DNS-poisoned.
enum WarpRegistration {

    static let apiHost = "api.cloudflareclient.com"
    static let apiPath = "/v0a4005/reg"
    static let userAgent = "insomnia/8.6.1"

    /// Pinned Cloudflare IPs for the registration fallback (verified live
    /// 2026-10-10): the CF edge routes by SNI, so any serving edge IP with
    /// SNI/Host = the API hostname reaches the SAME origin, and the
    /// certificate still validates for the real hostname.
    static let pinnedApiIps = ["104.16.192.82", "104.16.24.84", "162.159.192.1", "188.114.96.1"]

    private static let cacheTtlMs: Double = 15 * 60 * 1000
    private static let lock = NSLock()
    private static var cachedAccount: WarpAccount? = nil
    private static var cachedAt: Double = 0

    // MARK: - persistence (UserDefaults-backed identity store)

    private static func identityJson() -> String? {
        UserDefaults.standard.string(forKey: "umbra.warp.identity_v1")
    }

    private static func persist(_ account: WarpAccount) {
        if let json = account.toJson() {
            UserDefaults.standard.set(json, forKey: "umbra.warp.identity_v1")
        }
    }

    /// Persists the TAI64N high-water mark next to the identity — a restarted
    /// process reusing the identity must continue ABOVE the server's stored
    /// mark (silent anti-replay drops = "warp finds nothing after restart").
    static func persistTimestampMark() {
        guard let mark = WgProtocol.saveMark() else { return }
        let b64 = Data(mark).base64EncodedString()
        UserDefaults.standard.set(b64, forKey: "umbra.warp.ts_mark_v1")
    }

    private static func loadPersisted() -> WarpAccount? {
        guard let json = identityJson(), let acc = WarpAccount.fromJson(json) else { return nil }
        if let b64 = UserDefaults.standard.string(forKey: "umbra.warp.ts_mark_v1"),
           let data = Data(base64Encoded: b64) {
            WgProtocol.loadMark([UInt8](data))
        }
        return acc
    }

    /// Wipes both caches — used when the server rejects the stored identity.
    static func clearCache() {
        lock.lock()
        cachedAccount = nil
        cachedAt = 0
        lock.unlock()
        WgProtocol.resetMark()
        UserDefaults.standard.removeObject(forKey: "umbra.warp.identity_v1")
        UserDefaults.standard.removeObject(forKey: "umbra.warp.ts_mark_v1")
    }

    private static func cached() -> WarpAccount? {
        lock.lock(); defer { lock.unlock() }
        guard let acc = cachedAccount else { return nil }
        if Date().timeIntervalSince1970 - cachedAt >= cacheTtlMs / 1000 { return nil }
        return acc
    }

    // MARK: - registration

    /// Deterministic identity generation.
    static func newIdentity() -> ([UInt8], [UInt8]) {
        let priv = WgCrypto.clampScalar(Rng.secureBytes(32))
        return (priv, WgCrypto.x25519Base(priv))
    }

    /// Builds the exact JSON body the registration endpoint expects.
    static func buildPayload(publicKeyB64: String, tosIso: String) -> String {
        let fields: [(String, String)] = [
            ("install_id", ""),
            ("fcm_token", ""),
            ("tos", tosIso),
            ("type", "Android"),
            ("model", "PC"),
            ("locale", "en_US"),
            ("warp_enabled", "true"),
            ("key", publicKeyB64),
        ]
        // deterministic field order, exactly like the Kotlin JSONObject
        let body = fields.map { "\"\($0.0)\":\"\(escapeJson($0.1))\"" }.joined(separator: ",")
        return "{\(body)}"
    }

    private static func escapeJson(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\t", with: " ")
    }

    static func tosTimestamp(now: Double = Date().timeIntervalSince1970) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'.000Z'"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        return formatter.string(from: Date(timeIntervalSince1970: now))
    }

    /// Parses the registration response; nil when the payload is unusable.
    static func parseResponse(_ body: String, privateKey: [UInt8], publicKey: [UInt8]) -> WarpAccount? {
        struct Peer: Decodable { let public_key: String? }
        struct Addresses: Decodable { let v6: String?; let v4: String? }
        struct Iface: Decodable { let addresses: Addresses? }
        struct Config: Decodable { let client_id: String?; let peers: [Peer]?; let interface: Iface? }
        struct Root: Decodable { let id: String?; let token: String?; let config: Config? }
        guard let data = body.data(using: .utf8),
              let root = try? JSONDecoder().decode(Root.self, from: data),
              let config = root.config,
              let clientIdB64 = config.client_id, !clientIdB64.isEmpty,
              let v6 = config.interface?.addresses?.v6, !v6.isEmpty,
              let peers = config.peers, !peers.isEmpty,
              let peerPubB64 = peers[0].public_key,
              let peerPub = Data(base64Encoded: peerPubB64) else { return nil }
        guard let reserved = Data(base64Encoded: clientIdB64) else { return nil }
        guard reserved.count >= 1 && reserved.count <= 8 && peerPub.count == 32 else { return nil }
        let v4 = config.interface?.addresses?.v4 ?? ""
        return WarpAccount(
            privateKey: privateKey,
            publicKey: publicKey,
            reserved: [UInt8](reserved),
            v6: v6,
            v4: v4.isEmpty ? "172.16.0.2" : v4,
            responderPublicKey: [UInt8](peerPub),
            accountId: root.id,
            authToken: root.token)
    }

    /// Domain first, pinned SNI-routed IPs when the domain is unreachable.
    /// Throws (never returns nil) — the reason rides the error description.
    static func postRegistration(_ payload: String) async throws -> String {
        // 1. the domain, as always
        var urlRequest = URLRequest(url: URL(string: "https://\(apiHost)\(apiPath)")!)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.timeoutInterval = 15
        urlRequest.httpBody = Data(payload.utf8)
        if let (data, response) = try? await URLSession.shared.data(for: urlRequest),
           let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) {
            return String(data: data, encoding: .utf8) ?? ""
        }
        // an HTTP-level rejection from the domain means the origin answered —
        // pinned IPs would hit the SAME origin; propagate honestly if we got
        // a real status code back
        // (domainError carries transport failures only; HTTP errors above
        // returned already via the 2xx filter, else fall through to pins)

        // 2. domain unreachable at the transport level -> pinned IPs
        for ip in pinnedApiIps {
            guard let bytes = IpText.literalToBytes(ip) else { continue }
            if let body = await ExactIpHttps.postJson(
                ip: bytes, port: 443, sni: apiHost, path: apiPath,
                payload: payload, userAgent: userAgent,
                connectTimeoutMs: 4000, readTimeoutMs: 12_000) {
                return body
            }
        }
        throw WgError("registration api unreachable — domain failed and every pinned ip failed (dns poisoned or cloudflare tcp blocked on this network)")
    }

    /// Registers a new account (or reuses the cached identity within its
    /// TTL). Falls back to the last persisted identity when the API is
    /// unreachable. `fresh` bypasses both caches (the pre-flight gate's
    /// stale-key self-heal) and never disturbs them on failure.
    static func register(licenseKey: String? = nil, attempts: Int = 3, fresh: Bool = false) async throws -> WarpAccount {
        var account: WarpAccount? = fresh ? nil : cached()
        var lastError: Error? = nil
        if account == nil {
            for i in 0..<max(1, attempts) {
                if Task.isCancelled { throw CancellationError() }
                do {
                    let (priv, pub) = newIdentity()
                    let pubB64 = Data(pub).base64EncodedString()
                    let payload = buildPayload(publicKeyB64: pubB64, tosIso: tosTimestamp())
                    let body = try await postRegistration(payload)
                    guard let fresh2 = parseResponse(body, privateKey: priv, publicKey: pub) else {
                        throw WgError("unparsable registration payload")
                    }
                    account = fresh2
                    lock.lock()
                    cachedAccount = fresh2
                    cachedAt = Date().timeIntervalSince1970
                    lock.unlock()
                    persist(fresh2)
                } catch let e as CancellationError {
                    throw e
                } catch {
                    lastError = error
                }
                // the API is rate-limited per source IP — a short backoff
                // lets the window slide and the retry actually land
                if account == nil && i < attempts - 1 {
                    try? await Task.sleep(nanoseconds: 700_000_000)
                }
            }
            // API unreachable / rate-limited -> reuse the last working
            // identity instead of aborting the scan
            if account == nil && !fresh {
                account = loadPersisted()
            }
        }
        guard let acc = account else {
            throw WgError("WARP registration failed: \(lastError.map { "\($0)" } ?? "unknown")")
        }
        return acc
    }
}
