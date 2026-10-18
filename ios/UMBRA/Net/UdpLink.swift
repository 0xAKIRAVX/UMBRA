import Foundation
import Network

/// Async UDP socket — a thin await-able wrapper over NWConnection.
///
/// Semantics mirror the Kotlin DatagramSocket usage it replaces:
///  - connected to exactly one endpoint (host must be a literal IP)
///  - `receive(timeoutMs:)` returns ONE datagram, or nil on timeout/error
///    (cooperative: cancels with the surrounding Task)
///  - a timeout (or Task cancellation) permanently kills the link — a new
///    probe round builds a fresh link, exactly like a fresh handshake round
///
/// THE v3.9 LESSON, SOLVED STRUCTURALLY: the Android app had to fight its
/// runtime's 64-thread blocking-IO pool ("elastic lanes") because every UDP
/// receive BLOCKED a thread. Here every wait is event-driven — a storm of
/// hundreds of concurrent probes blocks ZERO threads, so the frozen-scan
/// failure mode cannot exist on iOS by construction.
final class UdpLink {

    private let conn: NWConnection
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var dead = false

    init(host: String, port: Int) {
        queue = DispatchQueue(label: "umbra.udp.\(UUID().uuidString)")
        conn = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? NWEndpoint.Port(443),
            using: NWParameters.udp)
    }

    var isDead: Bool {
        lock.lock(); defer { lock.unlock() }
        return dead
    }

    /// Waits for the connection to become ready. False on failure/timeout.
    func waitReady(timeoutMs: Int) async -> Bool {
        if isDead { return false }
        let timer = DispatchWorkItem { [weak self] in
            self?.kill()
        }
        queue.asyncAfter(deadline: .now() + .milliseconds(max(1, timeoutMs)), execute: timer)
        defer { timer.cancel() }
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
                // belt: deadline path (kill() flips state to .cancelled)
                queue.asyncAfter(deadline: .now() + .milliseconds(max(1, timeoutMs) + 50)) {
                    box.resume(false)
                }
            }
        }, onCancel: {
            timer.cancel()
            self.kill()
        })
        return ok
    }

    /// Fire-and-forget datagram send. False when the link refused it.
    func send(_ data: [UInt8]) async -> Bool {
        if isDead { return false }
        return await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            conn.send(content: Data(data), completion: .contentProcessed { error in
                cont.resume(returning: error == nil)
            })
        }
    }

    /// Receives ONE datagram within the budget. nil = timeout / error / dead.
    func receive(timeoutMs: Int) async -> [UInt8]? {
        if isDead { return nil }
        let timer = DispatchWorkItem { [weak self] in
            self?.kill()
        }
        queue.asyncAfter(deadline: .now() + .milliseconds(max(1, timeoutMs)), execute: timer)
        defer { timer.cancel() }
        return await withTaskCancellationHandler(operation: {
            await withCheckedContinuation { (cont: CheckedContinuation<[UInt8]?, Never>) in
                lock.lock()
                if dead {
                    lock.unlock()
                    cont.resume(returning: nil)
                    return
                }
                lock.unlock()
                conn.receiveMessage { data, _, _, error in
                    if let data = data {
                        cont.resume(returning: [UInt8](data))
                    } else {
                        _ = error
                        cont.resume(returning: nil)
                    }
                }
            }
        }, onCancel: {
            timer.cancel()
            self.kill()
        })
    }

    func close() {
        kill()
    }

    private func kill() {
        lock.lock()
        let wasDead = dead
        dead = true
        lock.unlock()
        if !wasDead {
            conn.cancel()
        }
    }
}

/// One-shot resume box — lets callbacks, timers and cancellation all race a
/// single continuation safely.
final class OnceBox<T> {
    private let lock = NSLock()
    private var cont: CheckedContinuation<T, Never>?

    init(_ cont: CheckedContinuation<T, Never>) {
        self.cont = cont
    }

    func resume(_ value: T) {
        lock.lock()
        let c = cont
        cont = nil
        lock.unlock()
        c?.resume(returning: value)
    }
}
