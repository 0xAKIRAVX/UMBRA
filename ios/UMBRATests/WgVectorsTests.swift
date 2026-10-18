import XCTest
@testable import UMBRA

/// Differential tests: every Swift crypto/protocol path is compared
/// byte-for-byte against the shared reference vectors — the exact same
/// vectors the Android Kotlin implementation passes, which were generated
/// from a Python reference verified LIVE against production Cloudflare WARP
/// endpoints. If these pass, the iOS probe speaks identical bytes to the
/// Android app and the validated reference.
final class WgVectorsTests: XCTestCase {

    private func hex(_ s: String) -> [UInt8] {
        stride(from: 0, to: s.count, by: 2).map {
            UInt8(s[s.index(s.startIndex, offsetBy: $0)..<s.index(s.startIndex, offsetBy: $0 + 2)], radix: 16)!
        }
    }

    private func vectors(_ key: String) throws -> [[String: Any]] {
        try WgVectors.root()[key] as! [[String: Any]]
    }

    // ── BLAKE2s ──────────────────────────────────────────────────

    func testBlake2sMatchesReference() throws {
        let arr = try vectors("blake2s")
        for c in arr {
            XCTAssertEqual(WgCrypto.blake2s(hex(c["data"] as! String)),
                           hex(c["out"] as! String))
        }
    }

    func testBlake2sEmptyDigestIsWellKnown() {
        let empty = WgCrypto.blake2s([])
        XCTAssertEqual("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
                       empty.map { String(format: "%02x", $0) }.joined())
    }

    func testKeyedBlake2s128MacMatchesReference() throws {
        let arr = try vectors("blake2s_keyed128")
        for c in arr {
            XCTAssertEqual(
                WgCrypto.blake2s(hex(c["data"] as! String), key: hex(c["key"] as! String), digestSize: 16),
                hex(c["out"] as! String))
        }
    }

    func testHmacBlake2sMatchesReference() throws {
        let arr = try vectors("hmac_blake2s")
        for c in arr {
            XCTAssertEqual(
                WgCrypto.hmacBlake2s(key: hex(c["key"] as! String), data: hex(c["data"] as! String)),
                hex(c["out"] as! String))
        }
    }

    // ── X25519 ───────────────────────────────────────────────────

    func testX25519PublicKeysAndSharedSecretsMatchReference() throws {
        let arr = try vectors("x25519")
        for c in arr {
            let priv = hex(c["priv"] as! String)
            XCTAssertEqual(hex(c["pub"] as! String), WgCrypto.x25519Base(priv))
            XCTAssertEqual(hex(c["shared"] as! String),
                           WgCrypto.x25519Shared(priv: priv, peerPub: hex(c["peer_pub"] as! String)))
        }
    }

    func testX25519Rfc7748Vector() throws {
        let v = try WgVectors.root()["x25519_rfc7748"] as! [String: Any]
        let out = WgCrypto.x25519(hex(v["scalar"] as! String), u: hex(v["u"] as! String))
        XCTAssertEqual(hex(v["out"] as! String), out)
    }

    func testX25519SharedRejectsAllZeroSecret() {
        // low-order point -> all-zero shared secret -> nil (Kotlin parity)
        let zeroPub = [UInt8](repeating: 0, count: 32)
        let priv = WgCrypto.clampScalar([UInt8](repeating: 1, count: 32))
        XCTAssertNil(WgCrypto.x25519Shared(priv: priv, peerPub: zeroPub))
    }

    // ── ChaCha20-Poly1305 ────────────────────────────────────────

    func testAeadSealMatchesReferenceAndOpensBack() throws {
        let arr = try vectors("aead")
        for c in arr {
            let key = hex(c["key"] as! String)
            let nonce = hex(c["nonce"] as! String)
            let pt = hex(c["pt"] as! String)
            let ad = hex(c["ad"] as! String)
            let ct = WgCrypto.chacha20Poly1305Seal(key: key, nonce: nonce, plaintext: pt, aad: ad)
            XCTAssertEqual(hex(c["ct"] as! String), ct)
            XCTAssertEqual(pt, WgCrypto.chacha20Poly1305Open(key: key, nonce: nonce, ctAndTag: ct!, aad: ad))
        }
    }

    func testAeadRejectsTamperedCiphertext() {
        let key = [UInt8](0..<32).map { $0 + 1 }
        let nonce = [UInt8](repeating: 0, count: 12)
        let ct = WgCrypto.chacha20Poly1305Seal(
            key: key, nonce: nonce, plaintext: Array("hello warp".utf8), aad: [])!
        var tampered = ct
        tampered[0] ^= 0x40
        XCTAssertNil(WgCrypto.chacha20Poly1305Open(key: key, nonce: nonce, ctAndTag: tampered, aad: []))
    }

    func testAeadRejectsShortInput() {
        XCTAssertNil(WgCrypto.chacha20Poly1305Open(
            key: [UInt8](repeating: 0, count: 32),
            nonce: [UInt8](repeating: 0, count: 12),
            ctAndTag: [UInt8](repeating: 0, count: 15),
            aad: []))
    }

    // ── full handshake ───────────────────────────────────────────

    func testHandshakeInitiationPacketMatchesReferenceByteForByte() throws {
        let hs = try WgVectors.root()["handshake"] as! [String: Any]
        let built = try WgProtocol.buildInitiation(
            staticPriv: hex(hs["init_static_priv"] as! String),
            staticPub: hex(hs["init_static_pub"] as! String),
            responderPub: hex(hs["resp_static_pub"] as! String),
            senderIndex: Int32(hs["sender_index"] as! Int),
            ephemeralPriv: hex(hs["eph_priv"] as! String),
            timestamp: hex(hs["timestamp"] as! String))
        XCTAssertEqual(148, built.packet.count)
        XCTAssertEqual(hex(hs["init_packet"] as! String), built.packet)

        // and the response consumption yields the reference session
        let consumed = WgProtocol.consumeResponse(
            pending: built.pending,
            staticPriv: hex(hs["init_static_priv"] as! String),
            data: hex(hs["response_packet"] as! String))
        XCTAssertNotNil(consumed.session, "consumeResponse failed: \(consumed.error)")
        XCTAssertEqual(Int32(hs["their_index"] as! Int), consumed.session!.theirIndex)
    }

    func testSessionKeysDeriveIdenticallyAndTransportRoundtrips() throws {
        let root = try WgVectors.root()
        let hs = root["handshake"] as! [String: Any]
        let initPriv = hex(hs["init_static_priv"] as! String)
        let built = try WgProtocol.buildInitiation(
            staticPriv: initPriv,
            staticPub: hex(hs["init_static_pub"] as! String),
            responderPub: hex(hs["resp_static_pub"] as! String),
            senderIndex: Int32(hs["sender_index"] as! Int),
            ephemeralPriv: hex(hs["eph_priv"] as! String),
            timestamp: hex(hs["timestamp"] as! String))
        let consumed = WgProtocol.consumeResponse(
            pending: built.pending, staticPriv: initPriv,
            data: hex(hs["response_packet"] as! String))
        let session = try XCTUnwrap(consumed.session)

        // transport request (echo request inside the tunnel)
        let tr = root["transport_req"] as! [String: Any]
        let inner = WgProtocol.icmpEchoRequest(
            src: [172, 16, 0, 2], dst: [1, 1, 1, 1],
            ident: tr["ident"] as! Int, seq: tr["seq"] as! Int)
        let packetOut = session.buildTransport(inner)
        XCTAssertEqual(hex(tr["packet"] as! String), packetOut)

        // transport reply decrypts to the reference inner packet + parses
        let reply = root["transport_reply"] as! [String: Any]
        let innerReply = session.openTransport(hex(reply["packet"] as! String))
        XCTAssertNotNil(innerReply)
        XCTAssertEqual(hex(reply["inner"] as! String), innerReply!)
        XCTAssertTrue(WgProtocol.parseEchoReply(innerReply!, ident: tr["ident"] as! Int, seq: tr["seq"] as! Int))
    }

    func testResponseWithWrongReceiverIndexIsRejected() throws {
        let hs = try WgVectors.root()["handshake"] as! [String: Any]
        let initPriv = hex(hs["init_static_priv"] as! String)
        let built = try WgProtocol.buildInitiation(
            staticPriv: initPriv,
            staticPub: hex(hs["init_static_pub"] as! String),
            responderPub: hex(hs["resp_static_pub"] as! String),
            senderIndex: Int32(hs["sender_index"] as! Int),
            ephemeralPriv: hex(hs["eph_priv"] as! String),
            timestamp: hex(hs["timestamp"] as! String))
        var resp = hex(hs["response_packet"] as! String)
        resp[8] ^= 0x01 // corrupt receiver index
        let consumed = WgProtocol.consumeResponse(pending: built.pending, staticPriv: initPriv, data: resp)
        XCTAssertNil(consumed.session)
        XCTAssertFalse(consumed.error.isEmpty)
    }

    /// v3.5 regression guard (live-verified against production WARP):
    /// outgoing reserved bytes stay ZERO — non-zero type words get the
    /// packet silently dropped by Cloudflare.
    func testOutgoingReservedBytesStayZero() throws {
        let hs = try WgVectors.root()["handshake"] as! [String: Any]
        let built = try WgProtocol.buildInitiation(
            staticPriv: hex(hs["init_static_priv"] as! String),
            staticPub: hex(hs["init_static_pub"] as! String),
            responderPub: hex(hs["resp_static_pub"] as! String),
            senderIndex: Int32(hs["sender_index"] as! Int),
            ephemeralPriv: hex(hs["eph_priv"] as! String),
            timestamp: hex(hs["timestamp"] as! String))
        XCTAssertEqual(1, Int(built.packet[0]))
        for i in 1...3 {
            XCTAssertEqual(0, Int(built.packet[i]), "reserved byte \(i) must be zero")
        }

        // transport packets carry zeros too
        let initPriv = hex(hs["init_static_priv"] as! String)
        let consumed = WgProtocol.consumeResponse(
            pending: built.pending, staticPriv: initPriv,
            data: hex(hs["response_packet"] as! String))
        let session = try XCTUnwrap(consumed.session)
        let tr = try WgVectors.root()["transport_req"] as! [String: Any]
        let inner = WgProtocol.icmpEchoRequest(
            src: [172, 16, 0, 2], dst: [1, 1, 1, 1],
            ident: tr["ident"] as! Int, seq: tr["seq"] as! Int)
        let tp = session.buildTransport(inner)!
        XCTAssertEqual(4, Int(tp[0]))
        for i in 1...3 {
            XCTAssertEqual(0, Int(tp[i]), "reserved byte \(i) must be zero")
        }
    }

    // ── ICMP ─────────────────────────────────────────────────────

    func testIcmpChecksumsAreValidAndReplyParsingWorks() throws {
        let req = WgProtocol.icmpEchoRequest(src: [172, 16, 0, 2], dst: [1, 1, 1, 1], ident: 0xA1B2, seq: 7)
        XCTAssertEqual(28, req.count)
        // one's-complement sum incl. checksum = 0xFFFF (i.e. checksum verifies)
        XCTAssertEqual(0xFFFF, oneComplementSum(Array(req[0..<20])))
        XCTAssertEqual(0xFFFF, oneComplementSum(Array(req[20..<28])))
        XCTAssertEqual(8, Int(req[20])) // echo request type
        // builds the exact reference bytes
        let tr = try WgVectors.root()["transport_req"] as! [String: Any]
        let ref = hex(tr["inner"] as! String)
        XCTAssertEqual(Array(ref[0..<28]), req)
    }

    private func oneComplementSum(_ data: [UInt8]) -> Int {
        var sum: UInt64 = 0
        var i = 0
        while i + 1 < data.count {
            sum += (UInt64(data[i]) << 8) | UInt64(data[i + 1])
            i += 2
        }
        if i < data.count { sum += UInt64(data[i]) << 8 }
        while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        return Int(sum & 0xFFFF)
    }
}
