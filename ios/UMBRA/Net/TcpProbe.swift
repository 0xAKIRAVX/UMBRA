import Foundation
import Network

struct TcpStats {
    let latenciesMs: [Double]
    let failures: Int
    let lastError: String?

    var success: Bool { !latenciesMs.isEmpty }
}

/// Pure TCP handshake latency probing against a literal IP address.
/// The OS never resolves DNS for the candidate (the NWEndpoint.Host is a
/// literal). Fully cooperative-cancellable.
enum TcpProbe {

    static func probe(ip: [UInt8], port: Int, attempts: Int, timeoutMs: Int,
                      interAttemptDelayMs: Int = 25) async -> TcpStats {
        let host = IpText.format(ip)
        var lat: [Double] = []
        var failures = 0
        var lastError: String? = nil
        for attempt in 0..<max(1, attempts) {
            if attempt > 0 && interAttemptDelayMs > 0 {
                do {
                    try await Task.sleep(nanoseconds: UInt64(interAttemptDelayMs) * 1_000_000)
                } catch {
                    return TcpStats(latenciesMs: lat, failures: failures, lastError: lastError)
                }
            }
            let link = TcpLink(host: host, port: port)
            let t0 = DispatchTime.now()
            let ok = await link.waitReady(timeoutMs: timeoutMs)
            let dt = Double(DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1_000_000.0
            if ok {
                lat.append(dt)
            } else {
                failures += 1
                lastError = "TCP timeout"
            }
            link.close()
        }
        return TcpStats(latenciesMs: lat, failures: failures, lastError: lastError)
    }

    static func jitterOf(_ latencies: [Double]) -> Double? {
        if latencies.count < 2 { return nil }
        let mean = latencies.reduce(0, +) / Double(latencies.count)
        let variance = latencies.reduce(0) { $0 + ($1 - mean) * ($1 - mean) } / Double(latencies.count)
        return variance.squareRoot()
    }
}

/// One plain-TCP connection used for connect-time measurement.
final class TcpLink {
    private let conn: NWConnection
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var dead = false

    init(host: String, port: Int) {
        queue = DispatchQueue(label: "umbra.tcp.\(UUID().uuidString)")
        let params = NWParameters.tcp
        conn = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? NWEndpoint.Port(443),
            using: params)
    }

    func waitReady(timeoutMs: Int) async -> Bool {
        lock.lock()
        if dead { lock.unlock(); return false }
        lock.unlock()
        let timer = DispatchWorkItem { [weak self] in self?.forceFail() }
        queue.asyncAfter(deadline: .now() + .milliseconds(max(1, timeoutMs)), execute: timer)
        defer { timer.cancel() }
        return await withTaskCancellationHandler(operation: {
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
