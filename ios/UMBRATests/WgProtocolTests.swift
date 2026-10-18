import XCTest
@testable import UMBRA

/// TAI64N + engine pure-function tests (ported from the Kotlin suite).
final class WgProtocolTests: XCTestCase {

    // ── TAI64N ───────────────────────────────────────────────────

    private func compareTs(_ a: [UInt8], _ b: [UInt8]) -> Int {
        WgProtocol.compareTimestamps(a, b)
    }

    func testTai64nMatchesWireguardGoShapeAndStaysNearWallClock() {
        WgProtocol.resetMark()
        let ts = WgProtocol.tai64nNow()
        XCTAssertEqual(12, ts.count)
        let secsBase = Int64(UInt64(bitPattern: Int64(WgProtocol.beInt32(ts, 0))) << 32
            | UInt64(bitPattern: Int64(WgProtocol.beInt32(ts, 4)) & 0xFFFFFFFF))
        let nowSecs = Int64(Date().timeIntervalSince1970)
        let delta = abs(secsBase - 0x400000000000000A - nowSecs)
        XCTAssertLessThanOrEqual(delta, 2, "timestamp \(secsBase) too far from now")
        let nanos = WgProtocol.beInt32(ts, 8)
        XCTAssertTrue((0...999_999_999).contains(nanos), "nanos must be a plausible sub-second value")
    }

    func testRapidFireTimestampsNeverRaceFarAheadOfWallClock() {
        // v3.6 regression guard for the replay-window bug: 1 ns bumps keep
        // the lead sub-millisecond even after bursts of initiations.
        WgProtocol.resetMark()
        for _ in 0..<500 { _ = WgProtocol.tai64nNow() }
        let ts = WgProtocol.tai64nNow()
        let secsBase = Int64(UInt64(bitPattern: Int64(WgProtocol.beInt32(ts, 0))) << 32
            | UInt64(bitPattern: Int64(WgProtocol.beInt32(ts, 4)) & 0xFFFFFFFF))
        let nowSecs = Int64(Date().timeIntervalSince1970)
        let leadMs = (secsBase - 0x400000000000000A - nowSecs) * 1000
        XCTAssertLessThanOrEqual(leadMs, 2_000, "sequence ran \(leadMs)ms ahead of wall clock")
    }

    func testMarkRoundTripsAndForcesStrictlyHigherTimestamps() {
        WgProtocol.resetMark()
        for _ in 0..<3 { _ = WgProtocol.tai64nNow() }
        let mark = WgProtocol.saveMark()
        XCTAssertNotNil(mark)
        XCTAssertEqual(12, mark!.count)

        // simulate a restart: fresh state, mark restored
        WgProtocol.resetMark()
        WgProtocol.loadMark(mark)
        let next = WgProtocol.tai64nNow()
        XCTAssertGreaterThan(compareTs(next, mark!), 0,
                             "restored mark must not let the next timestamp go backwards")

        // malformed marks are ignored instead of corrupting the sequence
        WgProtocol.loadMark([UInt8](repeating: 0, count: 11))
        WgProtocol.loadMark(nil)
        WgProtocol.resetMark()
    }

    func testTai64nIsStrictlyMonotonicAcrossRapidConsecutiveCalls() {
        var prev = WgProtocol.tai64nNow()
        for _ in 0..<500 {
            let next = WgProtocol.tai64nNow()
            XCTAssertGreaterThan(compareTs(next, prev), 0, "timestamp must strictly increase")
            prev = next
        }
    }

    func testBumpTimestampCarriesNanosIntoSeconds() {
        // a mark sitting at the CURRENT second with nanos = 0xFFFFFFFF must
        // force the next timestamp to carry into the seconds word
        let nowSecs = Int64(Date().timeIntervalSince1970)
        let full = 0x400000000000000A + nowSecs
        var ts = [UInt8](repeating: 0, count: 12)
        WgProtocol.putBeLong(&ts, 0, full)
        WgProtocol.putBeInt32(&ts, 8, -1) // 0xFFFFFFFF nanos
        WgProtocol.loadMark(ts)
        let next = WgProtocol.tai64nNow()
        XCTAssertEqual(0, WgProtocol.beInt32(next, 8), "nanos must wrap to 0")
        let nextFull = Int64(UInt64(bitPattern: Int64(WgProtocol.beInt32(next, 0))) << 32
            | UInt64(bitPattern: Int64(WgProtocol.beInt32(next, 4)) & 0xFFFFFFFF))
        XCTAssertEqual(full + 1, nextFull, "the 1ns bump must carry into the seconds word")
        WgProtocol.resetMark()
    }

    // ── budget ladder (v3.9) ─────────────────────────────────────

    func testAttemptTimeoutLadder() {
        XCTAssertEqual(2000, attemptTimeoutMs(attemptIndex: 0, baseTimeoutMs: 2000))
        XCTAssertEqual(1000, attemptTimeoutMs(attemptIndex: 1, baseTimeoutMs: 2000))
        XCTAssertEqual(700, attemptTimeoutMs(attemptIndex: 5, baseTimeoutMs: 1000))
        XCTAssertEqual(500, attemptTimeoutMs(attemptIndex: 2, baseTimeoutMs: 500))
        XCTAssertEqual(100, attemptTimeoutMs(attemptIndex: 1, baseTimeoutMs: 100)) // floor never above base
    }

    func testNoisePacketsForLadder() {
        XCTAssertEqual(5, noisePacketsFor(attemptIndex: 0, configured: 5))
        XCTAssertEqual(50, noisePacketsFor(attemptIndex: 0, configured: 100))
        XCTAssertEqual(1, noisePacketsFor(attemptIndex: 3, configured: 5))
        XCTAssertEqual(0, noisePacketsFor(attemptIndex: 3, configured: 0))
    }

    func testWarpProbeBudgetStopAfter() {
        XCTAssertFalse(WarpProbeBudget.stopAfter(fullSeen: false, bonusSpent: false))
        XCTAssertTrue(WarpProbeBudget.stopAfter(fullSeen: true, bonusSpent: false))
        XCTAssertTrue(WarpProbeBudget.stopAfter(fullSeen: false, bonusSpent: true))
    }

    // ── probe classification (v3.6) ──────────────────────────────

    func testClassifyWarpProbe() {
        XCTAssertNil(classifyWarpProbe(handshakes: 1, pings: 1, cookieReplies: 0, lastError: nil))
        XCTAssertEqual("handshake ok · no data plane",
                       classifyWarpProbe(handshakes: 3, pings: 0, cookieReplies: 0, lastError: nil))
        XCTAssertEqual("cookie reply (alive under load)",
                       classifyWarpProbe(handshakes: 0, pings: 0, cookieReplies: 2, lastError: nil))
        XCTAssertEqual("no handshake",
                       classifyWarpProbe(handshakes: 0, pings: 0, cookieReplies: 0, lastError: nil))
        XCTAssertEqual("handshake timeout",
                       classifyWarpProbe(handshakes: 0, pings: 0, cookieReplies: 0, lastError: "handshake timeout"))
        XCTAssertEqual("udp send blocked",
                       classifyWarpProbe(handshakes: 0, pings: 0, cookieReplies: 0, lastError: "udp send refused"))
        XCTAssertEqual("some other error",
                       classifyWarpProbe(handshakes: 0, pings: 0, cookieReplies: 0, lastError: "some other error"))
    }
}
