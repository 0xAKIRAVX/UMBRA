import Foundation
import SwiftUI
import UIKit

/// The scan session owner: state machine, live stats, log console, result
/// merging and persistence. Implements ScanSink on the MainActor.
@MainActor
final class ScanController: ObservableObject, ScanSink {

    @Published private(set) var uiState: ScanUiState = .idle
    @Published private(set) var stats = ScanStats()
    @Published private(set) var logLines: [String] = []
    @Published private(set) var results: [ScanResult] = []
    @Published private(set) var lastSummary: ScanSummary?

    private var resultsById: [String: (index: Int, result: ScanResult)] = [:]
    private var scanTask: Task<Void, Never>? = nil
    private var tickTask: Task<Void, Never>? = nil
    private var engine = ScanEngine()
    private var startedAt: Double = 0
    private var testedTimes: [Double] = []
    private var errorForDonePanel: String? = nil
    private let logLimit = 600
    private let store: SettingsStore

    init(store: SettingsStore = SettingsStore.shared) {
        self.store = store
    }

    var isRunning: Bool { scanTask != nil }

    // MARK: - lifecycle

    func start(params: ScanParams) {
        guard scanTask == nil else { return }
        resultsById.removeAll()
        results = []
        logLines = []
        testedTimes = []
        stats = ScanStats()
        errorForDonePanel = nil
        startedAt = Date().timeIntervalSince1970
        uiState = .running(params: params, startedAt: startedAt)
        store.saveParams(params)
        UIApplication.shared.isIdleTimerDisabled = true

        scanTask = Task { [weak self] in
            guard let self else { return }
            do {
                try await self.engine.run(params, sink: self)
                self.finish(cancelled: false, params: params)
            } catch is CancellationError {
                self.finish(cancelled: true, params: params)
            } catch {
                self.appendLog("engine failure · \(errorDescription(error))")
                self.finish(cancelled: false, params: params)
            }
        }
        tickTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                guard let self, self.scanTask != nil else { return }
                self.stats.elapsedMs = Int64((Date().timeIntervalSince1970 - self.startedAt) * 1000)
                self.updateRate()
            }
        }
    }

    func stop() {
        scanTask?.cancel()
    }

    private func finish(cancelled: Bool, params: ScanParams) {
        scanTask = nil
        tickTask?.cancel()
        tickTask = nil
        UIApplication.shared.isIdleTimerDisabled = false
        stats.active = 0
        let elapsed = Int64((Date().timeIntervalSince1970 - startedAt) * 1000)
        let aliveResults = results.filter { $0.alive }
        let best = aliveResults
            .max { Ranking.scoreOf($0) < Ranking.scoreOf($1) }
        // v3.11 (Android): the zero-result Done-panel reason must be captured
        // BEFORE the net-profile line is appended (it would mask the verdict)
        let reason: String?
        if aliveResults.isEmpty {
            reason = errorForDonePanel ?? lastEngineVerdictLine()
        } else {
            reason = nil
        }
        let summary = ScanSummary(
            cancelled: cancelled,
            candidates: stats.candidates,
            tested: stats.tested,
            alive: aliveResults.count,
            best: best,
            elapsedMs: elapsed,
            params: params,
            finishedAt: Date().timeIntervalSince1970,
            error: reason)
        lastSummary = summary
        uiState = .done(summary: summary)
        stats.phase = .done

        // persist results (smart-pick board) + journal a zero-result verdict
        store.saveScanResults(mode: params.mode, results: Array(aliveResults.prefix(60)))
        if aliveResults.isEmpty, let reason = reason {
            CrashGuard.journal(reason: reason)
        } else {
            CrashGuard.clear()
        }
        appendLog(
            "scan \(cancelled ? "stopped" : "complete") · \(summary.tested)/\(summary.candidates) tested · \(summary.alive) alive · \(formatElapsed(elapsed))")
    }

    // MARK: - ScanSink

    func onPhase(_ phase: ScanPhase) {
        stats.phase = phase
    }

    func onGenerated(_ count: Int) {
        stats.candidates = count
    }

    func onResult(_ result: ScanResult) {
        if let existing = resultsById[result.id] {
            let merged = existing.result.merge(newer: result)
            resultsById[result.id] = (existing.index, merged)
            results[existing.index] = merged
        } else {
            let index = results.count
            results.append(result)
            resultsById[result.id] = (index, result)
            testedTimes.append(Date().timeIntervalSince1970)
            stats.tested += 1
        }
        stats.alive = results.filter { $0.alive }.count
        stats.tlsOk = results.filter { $0.tlsSuccess }.count
        stats.speedTested = results.filter { $0.speedMbps != nil }.count
        updateRate()
    }

    func onActive(_ delta: Int) {
        stats.active = max(0, stats.active + delta)
    }

    func onLog(_ line: String) {
        appendLog(line)
        // the first line carrying a verdict/failure becomes the zero-result
        // Done-panel reason (captured before the profile line lands)
        if errorForDonePanel == nil, looksLikeVerdict(line) {
            errorForDonePanel = line
        }
    }

    func snapshot() -> [ScanResult] {
        results
    }

    // MARK: - helpers

    private func appendLog(_ line: String) {
        logLines.append(line)
        if logLines.count > logLimit {
            logLines.removeFirst(logLines.count - logLimit)
        }
    }

    private func updateRate() {
        let now = Date().timeIntervalSince1970
        testedTimes.removeAll { now - $0 > 15 }
        stats.ratePerSec = Double(testedTimes.count) / 15.0
        if stats.ratePerSec > 0.01, stats.candidates > stats.tested {
            stats.etaSec = Double(stats.candidates - stats.tested) / stats.ratePerSec
        } else {
            stats.etaSec = nil
        }
    }

    private func looksLikeVerdict(_ line: String) -> Bool {
        line.contains("aborted") || line.contains("identity failed")
            || line.contains("cannot validate") || line.contains("scan done")
            || line.contains("no valid candidates") || line.contains("no endpoints")
            || line.contains("engine failure")
    }

    private func lastEngineVerdictLine() -> String? {
        logLines.last(where: { !$0.contains("net profile") })
    }

    private func formatElapsed(_ ms: Int64) -> String {
        let total = Int(ms / 1000)
        let m = total / 60
        let s = total % 60
        return m > 0 ? "\(m)m \(s)s" : "\(s)s"
    }

    func clearResults() {
        guard !isRunning else { return }
        results = []
        resultsById.removeAll()
        lastSummary = nil
        uiState = .idle
        stats = ScanStats()
        store.clearSavedResults()
    }
}

/// Minimal crash journal — a zero-result verdict or engine failure is
/// persisted and surfaced on the next launch instead of vanishing.
enum CrashGuard {
    static func journal(reason: String) {
        UserDefaults.standard.set(reason, forKey: "umbra.crash.reason")
        let n = UserDefaults.standard.integer(forKey: "umbra.crash.count")
        UserDefaults.standard.set(n + 1, forKey: "umbra.crash.count")
    }

    static func clear() {
        UserDefaults.standard.removeObject(forKey: "umbra.crash.reason")
    }

    static var pendingReason: String? {
        UserDefaults.standard.string(forKey: "umbra.crash.reason")
    }

    static var count: Int {
        UserDefaults.standard.integer(forKey: "umbra.crash.count")
    }
}
