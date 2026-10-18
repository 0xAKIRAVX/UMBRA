import Foundation
import Combine

/// UserDefaults-backed settings + persisted scan state (the iOS twin of the
/// Android UmbraSettings). All clamping mirrors the Kotlin ranges so both
/// platforms share the same sane parameter space.
@MainActor
final class SettingsStore: ObservableObject {

    static let shared = SettingsStore()

    private let d = UserDefaults.standard

    // ── language (0 = english · 1 = فارسی · default follows system) ──
    @Published var language: Int {
        didSet { d.set(language, forKey: "umbra.language") }
    }

    // ── appearance ──
    @Published var accent: Int {
        didSet { d.set(accent, forKey: "umbra.accent") }
    }
    @Published var haptics: Bool {
        didSet { d.set(haptics, forKey: "umbra.haptics") }
    }

    // ── netsense: the measured line profile powering smart ranking ──
    @Published private(set) var networkProfile: NetworkProfile?

    // ── last verified results per bucket (ENDPOINT / CF-EDGE) ──
    @Published private(set) var savedEndpointResults: [ScanResult]
    @Published private(set) var savedEdgeResults: [ScanResult]

    init() {
        let stored = d.object(forKey: "umbra.language") as? Int
        if let stored = stored, (0...1).contains(stored) {
            language = stored
        } else {
            language = Locale.current.language.languageCode?.identifier == "fa" ? 1 : 0
        }
        accent = d.object(forKey: "umbra.accent") as? Int ?? 0
        haptics = d.object(forKey: "umbra.haptics") as? Bool ?? true
        networkProfile = Self.loadProfile(d.string(forKey: "umbra.net_profile_v1"))
        savedEndpointResults = Self.loadResults(d.string(forKey: "umbra.saved_endpoint_v1"))
        savedEdgeResults = Self.loadResults(d.string(forKey: "umbra.saved_edge_v1"))
    }

    // MARK: - params

    func loadParams() -> ScanParams {
        var p = ScanParams()
        p.mode = ScanMode(rawValue: d.string(forKey: "umbra.p.mode") ?? "") ?? .ENDPOINT
        p.family = NetFamily(rawValue: d.string(forKey: "umbra.p.family") ?? "") ?? .BOTH
        let port = d.object(forKey: "umbra.p.port") as? Int ?? Presets.defaultPort(for: p.mode)
        if port == 0 {
            p.port = p.mode == .ENDPOINT ? 0 : 443
        } else {
            p.port = min(65535, max(1, port))
        }
        p.cidrs = p.mode == .CUSTOM
            ? (d.string(forKey: "umbra.p.cidrs") ?? "").split(separator: "\n").map(String.init).filter { !$0.isEmpty }
            : Presets.cidrs(for: p.mode, family: p.family)
        p.samplesPerPrefix = clamp(d.object(forKey: "umbra.p.samples") as? Int ?? 96, 10, 5000)
        p.endpointsCount = clamp(d.object(forKey: "umbra.p.endpoints") as? Int ?? 500, 10, 20_000)
        p.tcpAttempts = clamp(d.object(forKey: "umbra.p.attempts") as? Int ?? 3, 1, 10)
        p.tcpTimeoutMs = clamp(d.object(forKey: "umbra.p.timeout") as? Int ?? 2000, 300, 8000)
        p.concurrency = clamp(d.object(forKey: "umbra.p.concurrency") as? Int ?? 150, 10, 400)
        p.tlsVerify = d.object(forKey: "umbra.p.tls") as? Bool ?? true
        p.verifyTopN = clamp(d.object(forKey: "umbra.p.verifyN") as? Int ?? 1200, 50, 2000)
        p.speedTest = d.object(forKey: "umbra.p.speed") as? Bool ?? true
        p.speedTopN = clamp(d.object(forKey: "umbra.p.speedN") as? Int ?? 50, 5, 300)
        p.speedConcurrency = clamp(d.object(forKey: "umbra.p.speedconc") as? Int ?? 4, 1, 8)
        let dlMb = clamp(d.object(forKey: "umbra.p.dlmb") as? Int ?? 20, 1, 100)
        p.downloadBytes = Int64(dlMb) * 1024 * 1024
        p.warpAttempts = clamp(d.object(forKey: "umbra.p.warptries") as? Int ?? 3, 1, 7)
        p.udpNoise = d.object(forKey: "umbra.p.noise") as? Bool ?? true
        p.noiseCount = clamp(d.object(forKey: "umbra.p.noisecnt") as? Int ?? 5, 1, 50)
        return p
    }

    func saveParams(_ p: ScanParams) {
        d.set(p.mode.rawValue, forKey: "umbra.p.mode")
        d.set(p.family.rawValue, forKey: "umbra.p.family")
        d.set(p.port, forKey: "umbra.p.port")
        d.set(p.cidrs.joined(separator: "\n"), forKey: "umbra.p.cidrs")
        d.set(p.samplesPerPrefix, forKey: "umbra.p.samples")
        d.set(p.endpointsCount, forKey: "umbra.p.endpoints")
        d.set(p.tcpAttempts, forKey: "umbra.p.attempts")
        d.set(p.tcpTimeoutMs, forKey: "umbra.p.timeout")
        d.set(p.concurrency, forKey: "umbra.p.concurrency")
        d.set(p.tlsVerify, forKey: "umbra.p.tls")
        d.set(p.verifyTopN, forKey: "umbra.p.verifyN")
        d.set(p.speedTest, forKey: "umbra.p.speed")
        d.set(p.speedTopN, forKey: "umbra.p.speedN")
        d.set(p.speedConcurrency, forKey: "umbra.p.speedconc")
        d.set(Int(p.downloadBytes / (1024 * 1024)), forKey: "umbra.p.dlmb")
        d.set(p.warpAttempts, forKey: "umbra.p.warptries")
        d.set(p.udpNoise, forKey: "umbra.p.noise")
        d.set(p.noiseCount, forKey: "umbra.p.noisecnt")
    }

    // MARK: - custom CIDRs (edited in the config panel)

    var customCidrs: String {
        d.string(forKey: "umbra.custom_cidrs") ?? ""
    }

    func saveCustomCidrs(_ text: String) {
        d.set(text, forKey: "umbra.custom_cidrs")
    }

    // MARK: - buckets

    func saveScanResults(mode: ScanMode, results: [ScanResult]) {
        let capped = Array(results.prefix(60))
        if let data = try? JSONEncoder().encode(capped), let json = String(data: data, encoding: .utf8) {
            switch mode {
            case .ENDPOINT:
                d.set(json, forKey: "umbra.saved_endpoint_v1")
                savedEndpointResults = capped
            case .CF_EDGE, .CUSTOM:
                d.set(json, forKey: "umbra.saved_edge_v1")
                savedEdgeResults = capped
            }
        }
    }

    func clearSavedResults() {
        savedEndpointResults = []
        savedEdgeResults = []
        d.removeObject(forKey: "umbra.saved_endpoint_v1")
        d.removeObject(forKey: "umbra.saved_edge_v1")
    }

    // MARK: - net profile

    func setNetworkProfile(_ profile: NetworkProfile) {
        networkProfile = profile
        if let data = try? JSONEncoder().encode(profile), let json = String(data: data, encoding: .utf8) {
            d.set(json, forKey: "umbra.net_profile_v1")
        }
    }

    // MARK: - codec helpers

    private static func loadResults(_ json: String?) -> [ScanResult] {
        guard let json = json, let data = json.data(using: .utf8),
              let list = try? JSONDecoder().decode([ScanResult].self, from: data) else { return [] }
        return list
    }

    private static func loadProfile(_ json: String?) -> NetworkProfile? {
        guard let json = json, let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(NetworkProfile.self, from: data)
    }

    private func clamp(_ v: Int, _ lo: Int, _ hi: Int) -> Int {
        min(hi, max(lo, v))
    }
}
