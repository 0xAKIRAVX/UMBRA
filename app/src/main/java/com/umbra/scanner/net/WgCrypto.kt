package com.umbra.scanner.net

import java.math.BigInteger

/**
 * Pure-Kotlin crypto primitives required by the WireGuard handshake
 * (X25519 / BLAKE2s / HMAC-BLAKE2s / ChaCha20-Poly1305).
 *
 * Zero third-party dependencies: works on every API level (minSdk 26),
 * fully unit-testable against RFC and differential vectors, and keeps the
 * APK tiny. Constant-time hardening is intentionally traded away — the
 * scanner only protects ephemeral, per-probe keys.
 */
object WgCrypto {

    private fun Int.rotr(n: Int): Int = Integer.rotateRight(this, n)
    private fun Int.rotl(n: Int): Int = Integer.rotateLeft(this, n)

    // ------------------------------------------------------------ X25519 ----
    // RFC 7748 Montgomery ladder, BigInteger arithmetic mod 2^255-19.

    private val P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))
    private val A24 = BigInteger.valueOf(121665) // (486662 - 2) / 4, RFC 7748
    private val U9 = BigInteger.valueOf(9)

    fun clampScalar(k: ByteArray): ByteArray {
        val out = k.copyOf(32)
        out[0] = (out[0].toInt() and 248).toByte()
        out[31] = ((out[31].toInt() and 127) or 64).toByte()
        return out
    }

    /** X25519(k, u) — both arguments and the result are 32-byte little-endian. */
    fun x25519(scalar: ByteArray, u: ByteArray): ByteArray {
        require(scalar.size == 32 && u.size == 32) { "x25519: 32-byte inputs" }
        val k = clampScalar(scalar)
        val kInt = leToBigInt(k)
        val x1 = leToBigInt(u.copyOf().also { it[31] = (it[31].toInt() and 127).toByte() })

        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE
        var swap = 0

        for (t in 254 downTo 0) {
            val kt = if (kInt.testBit(t)) 1 else 0
            swap = swap xor kt
            if (swap == 1) {
                var tmp = x2; x2 = x3; x3 = tmp
                tmp = z2; z2 = z3; z3 = tmp
            }
            swap = kt

            val a = (x2 + z2).mod(P)
            val aa = (a * a).mod(P)
            val b = (x2 - z2).mod(P)
            val bb = (b * b).mod(P)
            val e = (aa - bb).mod(P)
            val c = (x3 + z3).mod(P)
            val d = (x3 - z3).mod(P)
            val da = (d * a).mod(P)
            val cb = (c * b).mod(P)
            x3 = ((da + cb).mod(P) * (da + cb)).mod(P)
            z3 = (x1 * ((da - cb).mod(P) * (da - cb))).mod(P)
            x2 = (aa * bb).mod(P)
            z2 = (e * (aa + (A24 * e).mod(P))).mod(P)
        }
        if (swap == 1) {
            var tmp = x2; x2 = x3; x3 = tmp
            tmp = z2; z2 = z3; z3 = tmp
        }
        val result = (x2 * z2.modPow(P - BigInteger.TWO, P)).mod(P)
        return bigIntToLe(result, 32)
    }

    fun x25519Base(scalar: ByteArray): ByteArray =
        x25519(scalar, bigIntToLe(U9, 32))

    /** DH — returns null when the shared secret is all-zero (invalid public key). */
    fun x25519Shared(priv: ByteArray, peerPub: ByteArray): ByteArray? {
        val ss = x25519(priv, peerPub)
        return if (ss.all { it == 0.toByte() }) null else ss
    }

    private fun leToBigInt(b: ByteArray): BigInteger = BigInteger(1, b.reversedArray())

    private fun bigIntToLe(v: BigInteger, len: Int): ByteArray {
        val be = v.toByteArray() // may carry a leading zero or be short
        val out = ByteArray(len)
        var i = be.size - 1
        var o = 0
        while (i >= 0 && o < len) {
            out[o] = be[i]
            i--; o++
        }
        return out
    }

    // ----------------------------------------------------------- BLAKE2s ----
    // RFC 7693, unkeyed and keyed (incl. 16-byte keyed MAC mode used for mac1).

    private val BLAKE2S_IV = intArrayOf(
        0x6A09E667.toInt(), 0xBB67AE85.toInt(), 0x3C6EF372.toInt(), 0xA54FF53A.toInt(),
        0x510E527F.toInt(), 0x9B05688C.toInt(), 0x1F83D9AB.toInt(), 0x5BE0CD19.toInt(),
    )

    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    )

    /** BLAKE2s with optional key and variable digest length (1..32). */
    fun blake2s(data: ByteArray, key: ByteArray = ByteArray(0), digestSize: Int = 32): ByteArray {
        require(digestSize in 1..32) { "digest size out of range" }
        require(key.size <= 32) { "key too long" }

        val h = BLAKE2S_IV.copyOf()
        h[0] = h[0] xor (digestSize or (key.size shl 8) or (1 shl 16) or (1 shl 24))

        val buf = ByteArray(64)
        var bufLen = 0
        var t = 0L

        fun compress(block: ByteArray, isLast: Boolean, realLen: Int) {
            val m = IntArray(16)
            for (i in 0 until 16) {
                m[i] = (block[4 * i].toInt() and 0xFF) or
                    ((block[4 * i + 1].toInt() and 0xFF) shl 8) or
                    ((block[4 * i + 2].toInt() and 0xFF) shl 16) or
                    ((block[4 * i + 3].toInt() and 0xFF) shl 24)
            }
            val v = IntArray(16)
            System.arraycopy(h, 0, v, 0, 8)
            System.arraycopy(BLAKE2S_IV, 0, v, 8, 8)
            v[12] = v[12] xor (t.toInt())
            v[13] = v[13] xor ((t ushr 32).toInt())
            if (isLast) v[14] = v[14] xor (-1).toInt()

            fun g(a: Int, b: Int, c: Int, d: Int, mx: Int, my: Int) {
                v[a] = v[a] + v[b] + mx
                v[d] = (v[d] xor v[a]).rotr(16)
                v[c] = v[c] + v[d]
                v[b] = (v[b] xor v[c]).rotr(12)
                v[a] = v[a] + v[b] + my
                v[d] = (v[d] xor v[a]).rotr(8)
                v[c] = v[c] + v[d]
                v[b] = (v[b] xor v[c]).rotr(7)
            }

            for (r in 0 until 10) {
                val s = SIGMA[r]
                g(0, 4, 8, 12, m[s[0]], m[s[1]])
                g(1, 5, 9, 13, m[s[2]], m[s[3]])
                g(2, 6, 10, 14, m[s[4]], m[s[5]])
                g(3, 7, 11, 15, m[s[6]], m[s[7]])
                g(0, 5, 10, 15, m[s[8]], m[s[9]])
                g(1, 6, 11, 12, m[s[10]], m[s[11]])
                g(2, 7, 8, 13, m[s[12]], m[s[13]])
                g(3, 4, 9, 14, m[s[14]], m[s[15]])
            }
            for (i in 0 until 8) h[i] = h[i] xor v[i] xor v[i + 8]
        }

        fun update(x: ByteArray) {
            var i = 0
            while (i < x.size) {
                if (bufLen == 64) {
                    t += 64
                    compress(buf, false, 64)
                    bufLen = 0
                }
                val take = minOf(64 - bufLen, x.size - i)
                System.arraycopy(x, i, buf, bufLen, take)
                bufLen += take
                i += take
            }
        }

        if (key.isNotEmpty()) update(ByteArray(64).also { System.arraycopy(key, 0, it, 0, key.size) })
        update(data)

        // final block
        t += bufLen
        if (bufLen < 64) java.util.Arrays.fill(buf, bufLen, 64, 0.toByte())
        compress(buf, true, bufLen)

        val out = ByteArray(digestSize)
        var o = 0
        for (w in 0 until 8) {
            repeat(4) { byteIdx ->
                if (o < digestSize) {
                    out[o] = ((h[w] ushr (8 * byteIdx)) and 0xFF).toByte()
                    o++
                }
            }
        }
        return out
    }

    /** HMAC with BLAKE2s-256 as the inner/outer hash (block size 64). */
    fun hmacBlake2s(key: ByteArray, vararg data: ByteArray): ByteArray {
        val k = ByteArray(64)
        if (key.size > 64) {
            System.arraycopy(blake2s(key), 0, k, 0, 32)
        } else {
            System.arraycopy(key, 0, k, 0, key.size)
        }
        val ipad = ByteArray(64) { (k[it].toInt() xor 0x36).toByte() }
        val opad = ByteArray(64) { (k[it].toInt() xor 0x5C).toByte() }

        val inner = Blake2sStream()
        inner.update(ipad)
        for (d in data) inner.update(d)
        val innerHash = inner.digest()

        val outer = Blake2sStream()
        outer.update(opad)
        outer.update(innerHash)
        return outer.digest()
    }

    /** Reusable streaming BLAKE2s-256 (unkeyed). */
    class Blake2sStream {
        private val h = BLAKE2S_IV.copyOf().also { it[0] = it[0] xor (32 or (0 shl 8) or (1 shl 16) or (1 shl 24)) }
        private val buf = ByteArray(64)
        private var bufLen = 0
        private var t = 0L
        private var done = false

        fun update(x: ByteArray) {
            check(!done) { "already digested" }
            var i = 0
            while (i < x.size) {
                if (bufLen == 64) {
                    t += 64
                    compress(buf, false)
                    bufLen = 0
                }
                val take = minOf(64 - bufLen, x.size - i)
                System.arraycopy(x, i, buf, bufLen, take)
                bufLen += take
                i += take
            }
        }

        fun digest(): ByteArray {
            if (done) throw IllegalStateException("already digested")
            done = true
            t += bufLen
            if (bufLen < 64) java.util.Arrays.fill(buf, bufLen, 64, 0.toByte())
            compress(buf, true)
            val out = ByteArray(32)
            var o = 0
            for (w in 0 until 8) {
                repeat(4) { byteIdx ->
                    out[o] = ((h[w] ushr (8 * byteIdx)) and 0xFF).toByte(); o++
                }
            }
            return out
        }

        private fun compress(block: ByteArray, isLast: Boolean) {
            val m = IntArray(16)
            for (i in 0 until 16) {
                m[i] = (block[4 * i].toInt() and 0xFF) or
                    ((block[4 * i + 1].toInt() and 0xFF) shl 8) or
                    ((block[4 * i + 2].toInt() and 0xFF) shl 16) or
                    ((block[4 * i + 3].toInt() and 0xFF) shl 24)
            }
            val v = IntArray(16)
            System.arraycopy(h, 0, v, 0, 8)
            System.arraycopy(BLAKE2S_IV, 0, v, 8, 8)
            v[12] = v[12] xor (t.toInt())
            v[13] = v[13] xor ((t ushr 32).toInt())
            if (isLast) v[14] = v[14] xor (-1).toInt()

            fun g(a: Int, b: Int, c: Int, d: Int, mx: Int, my: Int) {
                v[a] = v[a] + v[b] + mx
                v[d] = (v[d] xor v[a]).rotr(16)
                v[c] = v[c] + v[d]
                v[b] = (v[b] xor v[c]).rotr(12)
                v[a] = v[a] + v[b] + my
                v[d] = (v[d] xor v[a]).rotr(8)
                v[c] = v[c] + v[d]
                v[b] = (v[b] xor v[c]).rotr(7)
            }

            for (r in 0 until 10) {
                val s = SIGMA[r]
                g(0, 4, 8, 12, m[s[0]], m[s[1]])
                g(1, 5, 9, 13, m[s[2]], m[s[3]])
                g(2, 6, 10, 14, m[s[4]], m[s[5]])
                g(3, 7, 11, 15, m[s[6]], m[s[7]])
                g(0, 5, 10, 15, m[s[8]], m[s[9]])
                g(1, 6, 11, 12, m[s[10]], m[s[11]])
                g(2, 7, 8, 13, m[s[12]], m[s[13]])
                g(3, 4, 9, 14, m[s[14]], m[s[15]])
            }
            for (i in 0 until 8) h[i] = h[i] xor v[i] xor v[i + 8]
        }
    }

    // ------------------------------------------------- ChaCha20-Poly1305 ----
    // RFC 8439 AEAD (used by WireGuard for both handshake and transport).

    private val CHACHA_CONST = intArrayOf(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)

    fun chacha20Poly1305Seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 12) { "bad key/nonce size" }
        val ct = chachaXor(key, nonce, plaintext)
        val tag = poly1305(derivePolyKey(key, nonce), macData(aad, ct))
        return ct + tag
    }

    fun chacha20Poly1305Open(key: ByteArray, nonce: ByteArray, ctAndTag: ByteArray, aad: ByteArray): ByteArray? {
        if (ctAndTag.size < 16) return null
        val ct = ctAndTag.copyOfRange(0, ctAndTag.size - 16)
        val tag = ctAndTag.copyOfRange(ctAndTag.size - 16, ctAndTag.size)
        val expect = poly1305(derivePolyKey(key, nonce), macData(aad, ct))
        if (!java.security.MessageDigest.isEqual(tag, expect)) return null
        return chachaXor(key, nonce, ct)
    }

    private fun chachaBlock(key: ByteArray, nonce: ByteArray, counter: Int): IntArray {
        val state = IntArray(16)
        System.arraycopy(CHACHA_CONST, 0, state, 0, 4)
        state[4] = leInt(key, 0); state[5] = leInt(key, 4)
        state[6] = leInt(key, 8); state[7] = leInt(key, 12)
        state[8] = leInt(key, 16); state[9] = leInt(key, 20)
        state[10] = leInt(key, 24); state[11] = leInt(key, 28)
        state[12] = counter
        state[13] = leInt(nonce, 0); state[14] = leInt(nonce, 4); state[15] = leInt(nonce, 8)

        val w = state.copyOf()
        fun qr(a: Int, b: Int, c: Int, d: Int) {
            w[a] += w[b]; w[d] = (w[d] xor w[a]).rotl(16)
            w[c] += w[d]; w[b] = (w[b] xor w[c]).rotl(12)
            w[a] += w[b]; w[d] = (w[d] xor w[a]).rotl(8)
            w[c] += w[d]; w[b] = (w[b] xor w[c]).rotl(7)
        }
        repeat(10) {
            qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
            qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
        }
        val out = IntArray(16)
        for (i in 0 until 16) out[i] = w[i] + state[i]
        return out
    }

    /** Poly1305 one-time key = first 32 bytes of the counter-0 keystream. */
    private fun derivePolyKey(key: ByteArray, nonce: ByteArray): ByteArray {
        val block = chachaBlock(key, nonce, 0)
        val polyKey = ByteArray(32)
        repeat(8) { i -> putLeInt(polyKey, 4 * i, block[i]) }
        return polyKey
    }

    /** ChaCha20 keystream XOR starting at block counter 1 (RFC 8439 §2.8). */
    private fun chachaXor(key: ByteArray, nonce: ByteArray, data: ByteArray): ByteArray {
        val out = ByteArray(data.size)
        var blockIdx = 1
        var offset = 0
        while (offset < data.size) {
            val ks = chachaBlock(key, nonce, blockIdx++)
            val n = minOf(64, data.size - offset)
            repeat(n) { i ->
                out[offset + i] = (data[offset + i].toInt() xor ((ks[i / 4] ushr (8 * (i % 4))) and 0xFF)).toByte()
            }
            offset += n
        }
        return out
    }

    private fun macData(aad: ByteArray, ct: ByteArray): ByteArray {
        val out = ByteArray(aad.size + pad16(aad.size) + ct.size + pad16(ct.size) + 16)
        var p = 0
        System.arraycopy(aad, 0, out, p, aad.size); p += aad.size + pad16(aad.size)
        System.arraycopy(ct, 0, out, p, ct.size); p += ct.size + pad16(ct.size)
        putLeLong(out, p, aad.size.toLong()); p += 8
        putLeLong(out, p, ct.size.toLong())
        return out
    }

    private fun pad16(n: Int): Int = (16 - (n and 15)) and 15

    private fun leInt(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8) or
            ((b[off + 2].toInt() and 0xFF) shl 16) or ((b[off + 3].toInt() and 0xFF) shl 24)

    private fun putLeInt(b: ByteArray, off: Int, v: Int) {
        b[off] = (v and 0xFF).toByte()
        b[off + 1] = ((v ushr 8) and 0xFF).toByte()
        b[off + 2] = ((v ushr 16) and 0xFF).toByte()
        b[off + 3] = ((v ushr 24) and 0xFF).toByte()
    }

    private fun putLeLong(b: ByteArray, off: Int, v: Long) {
        repeat(8) { i -> b[off + i] = ((v ushr (8 * i)) and 0xFF).toByte() }
    }

    // ------------------------------------------------------------ Poly1305 --
    // BigInteger-based (non constant-time, adequate for a scanner).

    private fun poly1305(key: ByteArray, msg: ByteArray): ByteArray {
        val rBytes = ByteArray(16)
        System.arraycopy(key, 0, rBytes, 0, 16)
        rBytes[3] = (rBytes[3].toInt() and 15).toByte()
        rBytes[7] = (rBytes[7].toInt() and 15).toByte()
        rBytes[11] = (rBytes[11].toInt() and 15).toByte()
        rBytes[15] = (rBytes[15].toInt() and 15).toByte()
        rBytes[4] = (rBytes[4].toInt() and 252).toByte()
        rBytes[8] = (rBytes[8].toInt() and 252).toByte()
        rBytes[12] = (rBytes[12].toInt() and 252).toByte()

        val r = BigInteger(1, rBytes.reversedArray())
        val s = BigInteger(1, key.copyOfRange(16, 32).reversedArray())
        val p = BigInteger.TWO.pow(130).subtract(BigInteger.valueOf(5))

        var acc = BigInteger.ZERO
        var i = 0
        while (i < msg.size) {
            val len = minOf(16, msg.size - i)
            val chunk = msg.copyOfRange(i, i + len).reversedArray()
            val n = BigInteger(1, chunk).add(BigInteger.ONE.shiftLeft(8 * len))
            acc = acc.add(n).multiply(r).mod(p)
            i += 16
        }
        val tagInt = acc.add(s).and(BigInteger.TWO.pow(128).subtract(BigInteger.ONE))
        val be = tagInt.toByteArray()
        val out = ByteArray(16)
        var bi = be.size - 1
        var o = 0
        while (bi >= 0 && o < 16) {
            out[o] = be[bi]; bi--; o++
        }
        return out
    }
}
