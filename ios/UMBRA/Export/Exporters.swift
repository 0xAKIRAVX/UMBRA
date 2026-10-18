import Foundation

/// Report builders — CSV / TXT / JSON string exports (the share sheet feeds
/// from these). Byte-compatible in spirit with the Android Exporters.
enum Exporters {

    private static func stamp() -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f.string(from: Date())
    }

    static func csv(_ results: [ScanResult]) -> String {
        var sb = "ip,protocol,port,latency_ms,jitter_ms,loss_pct,speed_mbps,downloaded_bytes,attempts,ok,tls,tls_handshake_ms,http_status,score,mode,error\n"
        for r in results {
            sb += "\(r.ip),"
            sb += "\(r.ipProtocol.rawValue),"
            sb += "\(r.port),"
            sb += (r.latencyMs.map { Fmt.str("%.1f", $0) } ?? "") + ","
            sb += (r.jitterMs.map { Fmt.str("%.1f", $0) } ?? "") + ","
            sb += "\(r.lossPct),"
            sb += (r.speedMbps.map { Fmt.str("%.2f", $0) } ?? "") + ","
            sb += "\(r.downloadedBytes),"
            sb += "\(r.tcpAttempts),"
            sb += "\(r.successfulAttempts),"
            sb += (r.tlsSuccess ? "yes" : "no") + ","
            sb += (r.tlsHandshakeMs.map { Fmt.str("%.0f", $0) } ?? "") + ","
            sb += (r.httpStatus.map(String.init) ?? "") + ","
            sb += Fmt.str("%.1f", Ranking.scoreOf(r)) + ","
            sb += "\(r.mode.rawValue),"
            sb += csvEscape(r.error ?? "") + "\n"
        }
        return sb
    }

    private static func csvEscape(_ s: String) -> String {
        if s.contains(",") || s.contains("\"") || s.contains("\n") {
            return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return s
    }

    static func txt(_ results: [ScanResult], _ params: ScanParams?) -> String {
        var sb = ""
        sb += "╔════════════════════════════════════════════════════════╗\n"
        sb += "║  U M B R A  ·  Cloudflare deep scan report            ║\n"
        sb += "╚════════════════════════════════════════════════════════╝\n"
        sb += "exported    : \(stamp())\n"
        if let p = params {
            sb += "mode        : \(p.mode.rawValue)\n"
            sb += "port        : \(p.port)\n"
            sb += "family      : \(p.family.label)\n"
            sb += "attempts    : \(p.tcpAttempts) × \(p.tcpTimeoutMs) ms\n"
            sb += "concurrency : \(p.concurrency)\n"
        }
        sb += "results     : \(results.count) alive endpoints\n\n"
        sb += pad("#", 4) + pad("IP", 43) + pad("PORT", 6) + pad("LAT", 7) + pad("LOSS", 5) + pad("SPEED", 9) + pad("SCORE", 6) + "\n"
        sb += String(repeating: "─", count: 90) + "\n"
        for (i, r) in results.enumerated() {
            sb += pad("\(i + 1)", 4)
            sb += pad(r.ip, 43)
            sb += pad("\(r.port)", 6)
            sb += pad(r.latencyMs.map { Fmt.str("%.0fms", $0) } ?? "-", 7)
            sb += pad("\(r.lossPct)%", 5)
            sb += pad(r.speedMbps.map { Fmt.str("%.1fM", $0) } ?? "-", 9)
            sb += pad(Fmt.str("%.0f", Ranking.scoreOf(r)), 6)
            sb += "\n"
            if let err = r.error {
                sb += "     ⚠ \(err)\n"
            }
        }
        return sb
    }

    static func json(_ results: [ScanResult], _ params: ScanParams?) -> String {
        var sb = "{\n  \"app\": \"UMBRA\",\n  \"platform\": \"ios\",\n  \"version\": 2,\n  \"exportedAt\": \"\(stamp())\""
        if let p = params {
            sb += ",\n  \"params\": {\n"
            sb += "    \"mode\": \"\(p.mode.rawValue)\",\n"
            sb += "    \"port\": \(p.port),\n"
            sb += "    \"family\": \"\(p.family.rawValue)\",\n"
            sb += "    \"tcpAttempts\": \(p.tcpAttempts),\n"
            sb += "    \"tcpTimeoutMs\": \(p.tcpTimeoutMs),\n"
            sb += "    \"concurrency\": \(p.concurrency),\n"
            sb += "    \"samplesPerPrefix\": \(p.samplesPerPrefix),\n"
            sb += "    \"downloadBytes\": \(p.downloadBytes)\n  }"
        }
        sb += ",\n  \"results\": ["
        if !results.isEmpty { sb += "\n" }
        for (i, r) in results.enumerated() {
            sb += "    {\n"
            sb += "      \"ip\": \"\(jsonStr(r.ip))\",\n"
            sb += "      \"protocol\": \"\(r.ipProtocol.rawValue)\",\n"
            sb += "      \"port\": \(r.port),\n"
            sb += "      \"latencyMs\": \(r.latencyMs.map { Fmt.str("%.1f", $0) } ?? "null"),\n"
            sb += "      \"jitterMs\": \(r.jitterMs.map { Fmt.str("%.1f", $0) } ?? "null"),\n"
            sb += "      \"packetLoss\": \(r.packetLoss),\n"
            sb += "      \"speedMbps\": \(r.speedMbps.map { Fmt.str("%.3f", $0) } ?? "null"),\n"
            sb += "      \"downloadedBytes\": \(r.downloadedBytes),\n"
            sb += "      \"tcpAttempts\": \(r.tcpAttempts),\n"
            sb += "      \"successfulAttempts\": \(r.successfulAttempts),\n"
            sb += "      \"tlsSuccess\": \(r.tlsSuccess),\n"
            sb += "      \"httpStatus\": \(r.httpStatus.map(String.init) ?? "null"),\n"
            sb += "      \"wgHandshakes\": \(r.wgHandshakes),\n"
            sb += "      \"score\": \(Fmt.str("%.1f", Ranking.scoreOf(r))),\n"
            sb += "      \"error\": \(r.error.map { "\"\(jsonStr($0))\"" } ?? "null")\n"
            sb += "    }" + (i < results.count - 1 ? ",\n" : "\n")
        }
        sb += "  ]\n}"
        return sb
    }

    private static func jsonStr(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\t", with: " ")
    }

    /// printf-style %-Ns left-padding for the TXT report.
    private static func pad(_ s: String, _ width: Int) -> String {
        if s.count >= width { return s + " " }
        return s + String(repeating: " ", count: width - s.count)
    }
}
