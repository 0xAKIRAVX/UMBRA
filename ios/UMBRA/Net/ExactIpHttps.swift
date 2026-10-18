import Foundation
import Network
import Security

/// Exact-IP HTTPS: TCP connect goes to the candidate IP itself, while the
/// TLS SNI and HTTP Host header point at speed.cloudflare.com /
/// engage.cloudflareclient.com. The certificate is fully validated (default
/// trust store + hostname verification for the SNI), so a wrong-endpoint IP
/// can never pass. DNS is never used for the candidate.
///
/// iOS port note: URLSession cannot connect to an IP with a foreign SNI, so
/// this speaks HTTP/1.1 directly over a Network.framework TLS connection —
/// the same wire behavior as the Kotlin ExactIpHttps (which used an
/// SSLSocket for exactly the same reason).
enum ExactIpHttps {

    struct TlsProbeResult {
        let ok: Bool
        let handshakeMs: Double?
        let error: String?
    }

    struct DownloadResult {
        let bytes: Int64
        let durationMs: Int64
        let httpStatus: Int?
        let tlsOk: Bool
        let handshakeMs: Double?
        let error: String?
    }

    struct UploadResult {
        let bytes: Int64
        let durationMs: Int64
        let httpStatus: Int?
        let error: String?
    }

    static let userAgent = "UMBRA-Scanner/3.0 (iOS)"

    // ------------------------------------------------------------ probes ----

    static func tlsProbe(ip: [UInt8], port: Int, sni: String,
                         connectTimeoutMs: Int, readTimeoutMs: Int) async -> TlsProbeResult {
        let link = TlsLink(host: IpText.format(ip), port: port, sni: sni)
        let ok = await link.connect(timeoutMs: connectTimeoutMs)
        defer { link.close() }
        if ok {
            return TlsProbeResult(ok: true, handshakeMs: link.handshakeMs, error: nil)
        }
        return TlsProbeResult(ok: false, handshakeMs: nil, error: "TLS: cannot establish session with \(sni)")
    }

    /// v3.6.1: generic JSON POST over the exact-IP TLS session — the WARP
    /// registration fallback for DNS-poisoned networks (the CF edge routes by
    /// SNI, so any serving edge IP reaches the same origin and the
    /// certificate still validates for the real hostname).
    static func postJson(ip: [UInt8], port: Int, sni: String, path: String,
                         payload: String, userAgent: String,
                         connectTimeoutMs: Int, readTimeoutMs: Int) async -> String? {
        let link = TlsLink(host: IpText.format(ip), port: port, sni: sni)
        let ok = await link.connect(timeoutMs: connectTimeoutMs)
        if !ok {
            link.close()
            return nil
        }
        let body = Array(payload.utf8)
        let req = "POST \(path) HTTP/1.1\r\nHost: \(sni)\r\nUser-Agent: \(userAgent)\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        guard await link.send(Array(req.utf8) + body) else {
            link.close()
            return nil
        }
        var buffer: [UInt8] = []
        var deadlineMs = readTimeoutMs
        while true {
            let chunk = await link.receiveChunk(maxLen: 64 * 1024, timeoutMs: deadlineMs)
            if let data = chunk.data { buffer += data }
            if chunk.isComplete || chunk.data == nil { break }
            if buffer.count > 4 * 1024 * 1024 { break }
            deadlineMs = readTimeoutMs
        }
        link.close()
        guard let status = parseStatusLine(buffer) else { return nil }
        if !(200...299).contains(status) { return nil }
        guard let headerEnd = findHeaderEnd(buffer) else { return nil }
        return String(bytes: buffer[min(headerEnd + 4, buffer.count)...], encoding: .utf8)
    }

    /// Download measurement: GET /__down?bytes=N over the exact-IP session.
    static func download(ip: [UInt8], port: Int, sni: String, byteCount: Int64,
                         connectTimeoutMs: Int, readTimeoutMs: Int,
                         maxDurationMs: Int64) async -> DownloadResult {
        let link = TlsLink(host: IpText.format(ip), port: port, sni: sni)
        let ok = await link.connect(timeoutMs: connectTimeoutMs)
        if !ok {
            link.close()
            return DownloadResult(bytes: 0, durationMs: 0, httpStatus: nil, tlsOk: false,
                                   handshakeMs: nil, error: "connect failed")
        }
        let handshakeMs = link.handshakeMs
        let req = "GET /__down?bytes=\(byteCount) HTTP/1.1\r\nHost: \(sni)\r\nUser-Agent: \(userAgent)\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        guard await link.send(Array(req.utf8)) else {
            link.close()
            return DownloadResult(bytes: 0, durationMs: 0, httpStatus: nil, tlsOk: true,
                                   handshakeMs: handshakeMs, error: "send failed")
        }
        // header phase
        var buffer: [UInt8] = []
        var headerDone = false
        var body: Int64 = 0
        var t0 = DispatchTime.now()
        var status: Int? = nil
        let wallStart = DispatchTime.now()
        while true {
            guard link.isAlive else { break }
            let chunk = await link.receiveChunk(maxLen: 64 * 1024, timeoutMs: readTimeoutMs)
            guard let data = chunk.data else {
                if !headerDone && buffer.isEmpty {
                    link.close()
                    return DownloadResult(bytes: 0, durationMs: 0, httpStatus: nil, tlsOk: true,
                                           handshakeMs: handshakeMs, error: "no HTTP response")
                }
                break
            }
            if !headerDone {
                buffer += data
                if let end = findHeaderEnd(buffer) {
                    status = parseStatusLine(buffer)
                    headerDone = true
                    buffer = Array(buffer[min(end + 4, buffer.count)...])
                    body += Int64(buffer.count)
                    t0 = DispatchTime.now()
                    if buffer.isEmpty { /* body starts with the next chunk */ }
                }
            } else {
                body += Int64(data.count)
            }
            if headerDone {
                let elapsedWall = Int64((DispatchTime.now().uptimeNanoseconds - wallStart.uptimeNanoseconds) / 1_000_000)
                if body >= byteCount || elapsedWall >= maxDurationMs { break }
            } else if buffer.count > 128 * 1024 {
                break // header phase runaway — not a valid HTTP answer
            }
        }
        link.close()
        if !headerDone {
            return DownloadResult(bytes: 0, durationMs: 0, httpStatus: status, tlsOk: true,
                                   handshakeMs: handshakeMs, error: "no HTTP response")
        }
        if status != 200 {
            return DownloadResult(bytes: 0, durationMs: 0, httpStatus: status, tlsOk: true,
                                   handshakeMs: handshakeMs, error: "HTTP status: \(status.map(String.init) ?? "?")")
        }
        if body <= 0 {
            return DownloadResult(bytes: 0, durationMs: 0, httpStatus: 200, tlsOk: true,
                                  handshakeMs: handshakeMs, error: "empty body")
        }
        let durMs = Int64((DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1_000_000)
        return DownloadResult(bytes: body, durationMs: max(1, durMs), httpStatus: 200, tlsOk: true,
                              handshakeMs: handshakeMs, error: nil)
    }

    /// Upload measurement: POSTs bytes to speed.cloudflare.com's /__up sink.
    static func upload(ip: [UInt8], port: Int, sni: String, byteCount: Int64,
                       connectTimeoutMs: Int, readTimeoutMs: Int,
                       maxDurationMs: Int64) async -> UploadResult {
        let link = TlsLink(host: IpText.format(ip), port: port, sni: sni)
        let ok = await link.connect(timeoutMs: connectTimeoutMs)
        if !ok {
            link.close()
            return UploadResult(bytes: 0, durationMs: 0, httpStatus: nil, error: "connect failed")
        }
        let req = "POST /__up?bytes=\(byteCount) HTTP/1.1\r\nHost: \(sni)\r\nUser-Agent: \(userAgent)\r\nAccept: */*\r\nContent-Type: application/octet-stream\r\nContent-Length: \(byteCount)\r\nConnection: close\r\n\r\n"
        guard await link.send(Array(req.utf8)) else {
            link.close()
            return UploadResult(bytes: 0, durationMs: 0, httpStatus: nil, error: "send failed")
        }
        let t0 = DispatchTime.now()
        var sent: Int64 = 0
        let chunk = [UInt8](repeating: 0, count: 16 * 1024)
        while sent < byteCount {
            let elapsed = Int64((DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1_000_000)
            if elapsed >= maxDurationMs { break }
            let n = Int(min(Int64(chunk.count), byteCount - sent))
            guard await link.send(Array(chunk[0..<n])) else { break }
            sent += Int64(n)
        }
        let durMs = Int64((DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1_000_000)
        if sent <= 0 {
            link.close()
            return UploadResult(bytes: 0, durationMs: 0, httpStatus: nil, error: "upload aborted")
        }
        if sent < byteCount {
            link.close()
            return UploadResult(bytes: sent, durationMs: max(1, durMs), httpStatus: nil, error: "upload truncated")
        }
        // server must acknowledge the consumed body
        var buffer: [UInt8] = []
        while buffer.count < 16384 {
            let c = await link.receiveChunk(maxLen: 16 * 1024, timeoutMs: readTimeoutMs)
            if let data = c.data { buffer += data }
            if c.isComplete || c.data == nil { break }
        }
        link.close()
        let status = parseStatusLine(buffer)
        if status == nil {
            return UploadResult(bytes: sent, durationMs: max(1, durMs), httpStatus: nil, error: "no HTTP response")
        }
        if status != 200 {
            return UploadResult(bytes: sent, durationMs: max(1, durMs), httpStatus: status,
                                error: "HTTP status: \(status!)")
        }
        return UploadResult(bytes: sent, durationMs: max(1, durMs), httpStatus: 200, error: nil)
    }

    // ------------------------------------------------------------ parsing ----

    /// "HTTP/1.1 200 OK" -> 200
    static func parseStatusLine(_ buffer: [UInt8]) -> Int? {
        let line = String(bytes: buffer.prefix(1024), encoding: .isoLatin1) ?? ""
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        let parts = trimmed.split(separator: " ")
        guard parts.count >= 2 else { return nil }
        if let code = Int(parts[1]) { return code }
        if parts.count >= 3, let code = Int(parts[2]) { return code }
        return nil
    }

    static func findHeaderEnd(_ buffer: [UInt8]) -> Int? {
        guard buffer.count >= 4 else { return nil }
        for i in 0...(buffer.count - 4) {
            if buffer[i] == 0x0D, buffer[i + 1] == 0x0A,
               buffer[i + 2] == 0x0D, buffer[i + 3] == 0x0A {
                return i
            }
        }
        return nil
    }
}

/// TLS connection to a literal IP with a foreign SNI + full validation.
final class TlsLink {
    private let conn: NWConnection
    private let queue: DispatchQueue
    private let sni: String
    private let lock = NSLock()
    private var dead = false
    private(set) var handshakeMs: Double = 0

    init(host: String, port: Int, sni: String) {
        self.sni = sni
        queue = DispatchQueue(label: "umbra.tls.\(UUID().uuidString)")
        let tls = NWProtocolTLS.Options()
        // SNI for the ClientHello (Network.framework sets it from this name)
        if let cSni = sni.cString(using: .utf8) {
            sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, cSni)
        }
        // full default verification against the SNI hostname (default trust
        // store + hostname policy) — a wrong-endpoint IP can never pass
        let verifyName = sni
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, secTrust, complete in
            let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
            let policy = SecPolicyCreateSSL(true, verifyName as CFString)
            SecTrustSetPolicies(trust, policy)
            var error: CFError?
            let ok = SecTrustEvaluateWithError(trust, &error)
            complete(ok)
        }, queue)
        let params = NWParameters(tls: tls)
        conn = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? NWEndpoint.Port(443),
            using: params)
    }

    var isAlive: Bool {
        lock.lock(); defer { lock.unlock() }
        return !dead
    }

    /// TCP+TLS connect; true on ready. Measures the handshake time.
    func connect(timeoutMs: Int) async -> Bool {
        lock.lock()
        if dead { lock.unlock(); return false }
        lock.unlock()
        let timer = DispatchWorkItem { [weak self] in self?.forceFail() }
        queue.asyncAfter(deadline: .now() + .milliseconds(max(1, timeoutMs)), execute: timer)
        defer { timer.cancel() }
        let t0 = DispatchTime.now()
        let ok = await withTaskCancellationHandler(operation: {
            await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
                let box = OnceBox(cont)
                conn.stateUpdateHandler = { state in
                    switch state {
                    case .ready: box.resume(true)
                    case .failed, .cancelled: box.resume(false)
                    default: break
                    }
                }
                conn.start(queue: queue)
                queue.asyncAfter(deadline: .now() + .milliseconds(max(1, timeoutMs) + 50)) {
                    box.resume(false)
                }
            }
        }, onCancel: {
            timer.cancel()
            self.forceFail()
        })
        handshakeMs = Double(DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1_000_000.0
        if !ok { forceFail() }
        return ok
    }

    func send(_ data: [UInt8]) async -> Bool {
        lock.lock()
        if dead { lock.unlock(); return false }
        lock.unlock()
        return await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            conn.send(content: Data(data), completion: .contentProcessed { [weak self] error in
                if error != nil { self?.forceFail() }
                cont.resume(returning: error == nil)
            })
        }
    }

    /// Receives one chunk. data == nil && !isComplete -> error/timeout.
    func receiveChunk(maxLen: Int, timeoutMs: Int) async -> (data: [UInt8]?, isComplete: Bool) {
        lock.lock()
        if dead { lock.unlock(); return (nil, false) }
        lock.unlock()
        let timer = DispatchWorkItem { [weak self] in self?.forceFail() }
        queue.asyncAfter(deadline: .now() + .milliseconds(max(1, timeoutMs)), execute: timer)
        defer { timer.cancel() }
        return await withTaskCancellationHandler(operation: {
            await withCheckedContinuation { (cont: CheckedContinuation<(data: [UInt8]?, isComplete: Bool), Never>) in
                conn.receive(minimumIncompleteLength: 1, maximumLength: maxLen) { data, _, isComplete, error in
                    if let data = data, error == nil {
                        cont.resume(returning: ([UInt8](data), isComplete))
                    } else if let data = data {
                        cont.resume(returning: ([UInt8](data), true))
                    } else {
                        cont.resume(returning: (nil, isComplete))
                    }
                }
            }
        }, onCancel: {
            timer.cancel()
            self.forceFail()
        })
    }

    func close() {
        forceFail()
    }

    private func forceFail() {
        lock.lock()
        let wasDead = dead
        dead = true
        lock.unlock()
        if !wasDead {
            conn.cancel()
        }
    }
}
