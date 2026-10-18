import Foundation
import CryptoKit

/// Crypto primitives required by the WireGuard handshake.
///
/// X25519 / ChaCha20-Poly1305 ride on Apple's audited CryptoKit
/// (constant-time, hardware-accelerated); BLAKE2s and HMAC-BLAKE2s use the
/// self-contained RFC 7693 port in Blake2s.swift. Every primitive is
/// differential-tested byte-for-byte against the live-verified reference
/// vectors (see UMBRATests/WgVectorsTests.swift) — the exact same vectors the
/// Android Kotlin implementation passes, so both platforms emit identical
/// bytes on the wire.
enum WgCrypto {

    // ------------------------------------------------------------- X25519 ----

    /// WireGuard scalar clamping (RFC 7748 §5).
    static func clampScalar(_ k: [UInt8]) -> [UInt8] {
        precondition(k.count == 32)
        var out = k
        out[0] &= 248
        out[31] = (out[31] & 127) | 64
        return out
    }

    /// X25519(scalar, u) — the scalar is clamped first (matching the Kotlin
    /// ladder implementation; CryptoKit clamps internally as well).
    static func x25519(_ scalar: [UInt8], u: [UInt8]) -> [UInt8]? {
        precondition(scalar.count == 32 && u.count == 32, "x25519: 32-byte inputs")
        guard let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(clampScalar(scalar))),
              let peer = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(u)) else { return nil }
        guard let ss = try? key.sharedSecretFromKeyAgreement(with: peer) else { return nil }
        return ss.withUnsafeBytes { [UInt8]($0) }
    }

    /// X25519(scalar, 9) — public key of a clamped private scalar.
    static func x25519Base(_ scalar: [UInt8]) -> [UInt8] {
        precondition(scalar.count == 32)
        let key = (try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(clampScalar(scalar))))!
        return [UInt8](key.publicKey.rawRepresentation)
    }

    /// DH — nil when the shared secret is all-zero (invalid public key),
    /// mirroring the Kotlin null-check.
    static func x25519Shared(priv: [UInt8], peerPub: [UInt8]) -> [UInt8]? {
        guard let ss = x25519(priv, u: peerPub) else { return nil }
        if ss.allSatisfy({ $0 == 0 }) { return nil }
        return ss
    }

    // ------------------------------------------------- ChaCha20-Poly1305 ----
    // RFC 8439 AEAD (CryptoKit) — output is ciphertext || tag, matching the
    // Kotlin WgCrypto.chacha20Poly1305Seal contract.

    static func chacha20Poly1305Seal(
        key: [UInt8], nonce: [UInt8], plaintext: [UInt8], aad: [UInt8]
    ) -> [UInt8]? {
        guard key.count == 32, nonce.count == 12,
              let n = try? ChaChaPoly.Nonce(data: Data(nonce)) else { return nil }
        guard let sealed = try? ChaChaPoly.seal(
            Data(plaintext),
            using: SymmetricKey(data: Data(key)),
            nonce: n,
            authenticating: Data(aad)) else { return nil }
        return [UInt8](sealed.combined)
    }

    static func chacha20Poly1305Open(
        key: [UInt8], nonce: [UInt8], ctAndTag: [UInt8], aad: [UInt8]
    ) -> [UInt8]? {
        guard key.count == 32, nonce.count == 12,
              let n = try? ChaChaPoly.Nonce(data: Data(nonce)) else { return nil }
        guard let box = try? ChaChaPoly.SealedBox(combined: Data(ctAndTag)) else { return nil }
        guard let pt = try? ChaChaPoly.open(
            box,
            using: SymmetricKey(data: Data(key)),
            authenticating: Data(aad)) else { return nil }
        return [UInt8](pt)
    }

    // ----------------------------------------------------------- BLAKE2s ----

    static func blake2s(_ data: [UInt8], key: [UInt8] = [], digestSize: Int = 32) -> [UInt8] {
        Blake2s.hash(data, key: key, digestSize: digestSize)
    }

    static func hmacBlake2s(key: [UInt8], data: [UInt8]) -> [UInt8] {
        Blake2s.hmac(key: key, data: data)
    }
}
