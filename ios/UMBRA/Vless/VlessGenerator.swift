import Foundation
import CoreImage
import CoreImage.CIFilterBuiltins
import UIKit

/// VLESS link builder for exact-IP Cloudflare workers — a 1:1 port of the
/// Kotlin VlessGenerator (IPv6 always bracketed per RFC 3986).
///
///   vless://UUID@[ip]:port?encryption=none&security=tls&sni=WORKER
///          &type=ws&host=WORKER&path=P#REMARK
///
/// The SNI must be the user's own Cloudflare-fronted domain (worker / proxy
/// panel) — it drives BOTH the TLS sni and the WebSocket host; with a test
/// SNI like speed.cloudflare.com the link never proxies anything.
enum VlessGenerator {

    struct Config {
        var uuid: String
        var host: String
        var port: Int = 443
        var sni: String = ""
        var wsPath: String = "/"
        var remark: String = "UMBRA-node"
    }

    static func randomUuid() -> String {
        UUID().uuidString.lowercased()
    }

    static func isValidUuid(_ s: String) -> Bool {
        UUID(uuidString: s.trimmingCharacters(in: .whitespaces)) != nil
    }

    /// True when the SNI is a usable (non test-only) host for proxying.
    static func isTestOnlySni(_ sni: String) -> Bool {
        let s = sni.trimmingCharacters(in: .whitespaces).lowercased()
        return s.isEmpty || s == "speed.cloudflare.com"
            || s == "www.speedtest.net" || s.hasSuffix(".speedtest.net")
    }

    static func buildLink(_ cfg: Config) -> String {
        let host = IpText.forUrl(cfg.host.trimmingCharacters(in: .whitespaces))
        let sni = cfg.sni.trimmingCharacters(in: .whitespaces)
        var path = cfg.wsPath.trimmingCharacters(in: .whitespaces)
        if path.isEmpty { path = "/" }
        if !path.hasPrefix("/") { path = "/" + path }
        let remark = cfg.remark.trimmingCharacters(in: .whitespaces)
        let remarkSafe = remark.isEmpty ? "UMBRA-node" : remark
        let port = min(65535, max(1, cfg.port))
        var out = "vless://\(cfg.uuid.trimmingCharacters(in: .whitespaces))@\(host):\(port)"
        out += "?encryption=none&security=tls&sni=\(enc(sni))"
        out += "&type=ws&host=\(enc(sni))"
        out += "&path=\(enc(path).replacingOccurrences(of: "%2F", with: "/"))"
        out += "#\(enc(remarkSafe))"
        return out
    }

    private static func enc(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .urlQueryValueAllowed) ?? s
    }
}

/// QR rendering via CoreImage (built-in — no third-party dependency).
enum QrGen {

    static func qrImage(for string: String, scale: Int = 12) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let transformed = output.transformed(by: CGAffineTransform(scaleX: CGFloat(scale), y: CGFloat(scale)))
        let context = CIContext()
        guard let cg = context.createCGImage(transformed, from: transformed.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}

extension CharacterSet {
    /// rfc3986 query-value-safe set (matches the Kotlin URLEncoder output
    /// closely enough for uuid/host/path/remark values).
    static let urlQueryValueAllowed: CharacterSet = {
        var set = CharacterSet.alphanumerics
        set.insert(charactersIn: "-._~")
        return set
    }()
}
