package com.umbra.scanner.core

import java.math.BigInteger
import kotlin.random.Random

class CidrBlock private constructor(
    val family: IpProtocol,
    val base: BigInteger,
    val prefix: Int,
    val size: BigInteger,
    val text: String,
) {
    private val bits: Int = if (family == IpProtocol.IPv4) 32 else 128
    private val hostBits: Int = bits - prefix

    companion object {
        fun parse(text: String): CidrBlock? {
            val t = text.trim()
            if (t.isEmpty()) return null
            val slash = t.lastIndexOf('/')
            val addrPart = if (slash >= 0) t.substring(0, slash) else t
            val prefixPart = if (slash >= 0) t.substring(slash + 1) else null
            val bytes = IpText.literalToBytes(addrPart) ?: return null
            val bits = bytes.size * 8
            val prefix = when {
                prefixPart == null -> bits
                else -> prefixPart.toIntOrNull() ?: return null
            }
            if (prefix < 0 || prefix > bits) return null
            val hostBits = bits - prefix
            var base = BigInteger(1, bytes)
            if (hostBits > 0) base = base.shiftRight(hostBits).shiftLeft(hostBits)
            val size = BigInteger.ONE.shiftLeft(hostBits)
            return CidrBlock(
                family = if (bytes.size == 4) IpProtocol.IPv4 else IpProtocol.IPv6,
                base = base,
                prefix = prefix,
                size = size,
                text = t,
            )
        }

        fun parseAll(list: List<String>): List<CidrBlock> =
            list.mapNotNull { parse(it) }
    }

    fun sampleCandidates(samples: Int, random: Random, out: MutableList<ByteArray>) {
        if (samples <= 0) return
        if (hostBits <= 10) {
            // small block: enumerate everything (skip v4 net/broadcast style edges)
            val total = size.min(BigInteger.valueOf(2048))
            var i = BigInteger.ZERO
            while (i < total) {
                if (family == IpProtocol.IPv4) {
                    val last = i.and(BigInteger.valueOf(255))
                    if (last == BigInteger.ZERO || last == BigInteger.valueOf(255)) {
                        i = i.add(BigInteger.ONE)
                        continue
                    }
                }
                out.add(base.add(i).toAddressBytes(bits))
                i = i.add(BigInteger.ONE)
            }
            return
        }
        val seen = HashSet<BigInteger>(samples * 2)
        var guard = 0
        val maxGuard = samples * 10
        val jrnd = java.util.Random(random.nextLong())
        while (seen.size < samples && guard < maxGuard) {
            guard++
            val r = BigInteger(hostBits, jrnd)
            val v = base.add(r)
            if (v.signum() == 0) continue // never emit the unspecified address
            if (seen.add(v)) out.add(v.toAddressBytes(bits))
        }
    }
}

private fun BigInteger.toAddressBytes(bits: Int): ByteArray {
    val len = bits / 8
    val out = ByteArray(len)
    val raw = toByteArray()
    val src = if (raw.size > len && raw[0].toInt() == 0) raw.copyOfRange(1, raw.size) else raw
    if (src.size > len) {
        System.arraycopy(src, src.size - len, out, 0, len)
    } else {
        System.arraycopy(src, 0, out, len - src.size, src.size)
    }
    return out
}

class Candidate(val bytes: ByteArray) {
    val protocol: IpProtocol = IpText.familyOf(bytes)
    val text: String = IpText.format(bytes)
    val id: String get() = text
}

object IpGenerator {
    fun generate(
        cidrs: List<String>,
        family: NetFamily,
        samplesPerPrefix: Int,
        random: Random = Random(System.nanoTime()),
    ): List<Candidate> {
        val blocks = CidrBlock.parseAll(cidrs).filter {
            family == NetFamily.BOTH || (family == NetFamily.V4 && it.family == IpProtocol.IPv4) ||
                (family == NetFamily.V6 && it.family == IpProtocol.IPv6)
        }
        val seen = HashSet<BigInteger>(samplesPerPrefix * blocks.size)
        val out = ArrayList<Candidate>(samplesPerPrefix * blocks.size)
        val raw = ArrayList<ByteArray>(samplesPerPrefix * 2)
        for (b in blocks) {
            raw.clear()
            b.sampleCandidates(samplesPerPrefix, random, raw)
            for (bytes in raw) {
                if (seen.add(BigInteger(1, bytes))) out.add(Candidate(bytes))
            }
        }
        return out
    }

    /**
     * WARP endpoint generation.
     *
     * IPv4: random sampling inside the WARP CIDR pool (as before).
     * IPv6: real WARP v6 endpoints embed the IPv4 pool in the last 32 bits
     * (2606:4700:d0::a29f:c001 == 162.159.192.1), so uniform sampling of the /48
     * essentially never hits a live address. Instead each sampled IPv4 is mapped
     * into both the d0 and d1 /96 prefixes — guaranteeing realistic candidates.
     */
    fun generateWarp(
        family: NetFamily,
        samplesPerPrefix: Int,
        random: Random = Random(System.nanoTime()),
    ): List<Candidate> {
        val wantV4 = family != NetFamily.V6
        val wantV6 = family != NetFamily.V4
        val out = ArrayList<Candidate>(samplesPerPrefix * 6)
        val seen = HashSet<BigInteger>(samplesPerPrefix * 8)

        if (wantV4) {
            for (c in generate(Presets.WARP_V4, NetFamily.V4, samplesPerPrefix, random)) {
                if (seen.add(BigInteger(1, c.bytes))) out.add(c)
            }
        }
        if (wantV6) {
            val v4pool = generate(Presets.WARP_V4, NetFamily.V4, samplesPerPrefix, random)
            for (v4 in v4pool) {
                // 2606:4700:d0::  and  2606:4700:d1::  + embedded v4 (d0 first — DNS-verified)
                for (prefix in listOf(Presets.WARP_V6_PREFIX_D0, Presets.WARP_V6_PREFIX_D1)) {
                    val bytes = v6Embedded(prefix, v4.bytes) ?: continue
                    if (seen.add(BigInteger(1, bytes))) out.add(Candidate(bytes))
                }
            }
        }
        return out
    }

    /** Builds `2606:4700:d0::a29f:c001`-style bytes for a WARP v6 endpoint. */
    internal fun v6Embedded(prefix: String, v4: ByteArray): ByteArray? {
        if (v4.size != 4) return null
        val head = IpText.literalToBytes(prefix) ?: return null
        require(head.size == 16) { "prefix must be a full /128 literal" }
        // zero groups 4..6 (bits 48..95), then place v4 in groups 7..8 (last 32 bits)
        for (i in 6 until 12) head[i] = 0
        head[12] = v4[0]; head[13] = v4[1]; head[14] = v4[2]; head[15] = v4[3]
        return head
    }

    fun estimate(cidrs: List<String>, family: NetFamily, samplesPerPrefix: Int): Int {
        val blocks = CidrBlock.parseAll(cidrs).filter {
            family == NetFamily.BOTH || (family == NetFamily.V4 && it.family == IpProtocol.IPv4) ||
                (family == NetFamily.V6 && it.family == IpProtocol.IPv6)
        }
        var total = 0
        for (b in blocks) {
            val enumerated = if (b.hostBitsValue() <= 10) b.size.min(BigInteger.valueOf(2048)).toInt() else samplesPerPrefix
            total += enumerated
        }
        return total
    }

    private fun CidrBlock.hostBitsValue(): Int = if (family == IpProtocol.IPv4) 32 - prefix else 128 - prefix
}
