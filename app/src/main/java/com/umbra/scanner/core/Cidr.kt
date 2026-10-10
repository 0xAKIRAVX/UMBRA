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
            val total = size.min(BigInteger.valueOf(2048)).toLong()
            if (samples >= total) {
                // small block, full coverage requested (skip v4 net/broadcast style edges)
                var i = BigInteger.ZERO
                while (i < BigInteger.valueOf(total)) {
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
            // v3.1.1 fix: small blocks now RESPECT the samples knob. The old
            // behavior enumerated the whole block (254/256 per /24) no matter
            // what the user configured, so a WARP scan generated ~2.6x more
            // candidates than the UI estimate promised and ran correspondingly
            // longer. Requested samples < block size → random-sample instead.
            val seen = HashSet<BigInteger>(samples * 2)
            val jrnd = java.util.Random(random.nextLong())
            var guard = 0
            val maxGuard = samples * 20
            while (seen.size < samples && guard < maxGuard) {
                guard++
                val r = BigInteger(hostBits, jrnd)
                val v = base.add(r)
                if (v.signum() == 0) continue // never emit the unspecified address
                if (family == IpProtocol.IPv4) {
                    val last = v.and(BigInteger.valueOf(255))
                    if (last == BigInteger.ZERO || last == BigInteger.valueOf(255)) continue
                }
                if (seen.add(v)) out.add(v.toAddressBytes(bits))
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

/** v3.7: one random ip:port endpoint to test — the ENDPOINT-mode unit of work
 *  (the BPB-Warp-Scanner "Endpoint"). */
data class EndpointPair(val candidate: Candidate, val port: Int)

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

    /**
     * v3.7 ENDPOINT mode: BPB-Warp-Scanner endpoint generation.
     *
     * Each endpoint is a RANDOM `ip:port` pair drawn from the WARP pool:
     *  - IPv4: a random host (1..254, network/broadcast skipped) inside a
     *    random one of the [Presets.WARP_V4] /24 blocks
     *  - IPv6: the v4-embedded twin of a random v4 (d0/d1 prefix) — the
     *    live-verified real pattern, unlike BPB's uniform-random low 64 bits
     *    which mostly lands on non-existent addresses
     *  - family BOTH splits the count v4/v6 like BPB does (half/half)
     *  - port 0 → each endpoint draws its own random port from the canonical
     *    [Presets.WARP_PORTS_FULL] list (BPB behavior); port > 0 → pinned
     *
     * Endpoints are deduplicated on the `ip:port` text, never on the IP —
     * the same IP with different ports is a different endpoint, exactly like
     * the BPB scanner's `seen` map.
     *
     * v3.10: the port-choices overload backs the recovery ladder's re-aim —
     * when a sweep proves only some ports pass this network, the rebuilt pool
     * draws its ports from exactly those winners instead of the full list.
     */
    fun generateEndpoints(
        family: NetFamily,
        count: Int,
        port: Int,
        random: Random = Random(System.nanoTime()),
    ): List<EndpointPair> = generateEndpoints(
        family, count,
        if (port > 0) listOf(port) else Presets.WARP_PORTS_FULL,
        random,
    )

    /** v3.10: [portChoices] — the exact port menu each drawn pair picks from
     *  (single pinned port, the full canonical list, or the sweep's winning
     *  ports). Empty/invalid lists fall back to the canonical list. */
    fun generateEndpoints(
        family: NetFamily,
        count: Int,
        portChoices: List<Int>,
        random: Random = Random(System.nanoTime()),
    ): List<EndpointPair> {
        if (count <= 0) return emptyList()
        val v4Blocks = CidrBlock.parseAll(Presets.WARP_V4)
        if (v4Blocks.isEmpty()) return emptyList()
        val choices = portChoices.filter { it in 1..65535 }.distinct()
            .ifEmpty { Presets.WARP_PORTS_FULL }
        val wantV4 = family != NetFamily.V6
        val wantV6 = family != NetFamily.V4
        // BPB split: half v4, half v6 when both families are requested
        val v4Quota = when {
            wantV4 && wantV6 -> count / 2
            wantV4 -> count
            else -> 0
        }
        val v6Quota = count - v4Quota
        val seen = HashSet<String>(count * 2)
        val out = ArrayList<EndpointPair>(count)

        fun nextPort(): Int = choices[random.nextInt(choices.size)]

        fun nextV4Bytes(): ByteArray {
            val block = v4Blocks[random.nextInt(v4Blocks.size)]
            val host = 1 + random.nextInt(254)
            return block.base.add(BigInteger.valueOf(host.toLong())).toAddressBytes(32)
        }

        fun add(c: Candidate, p: Int): Boolean {
            if (seen.add("${c.text}:$p")) {
                out.add(EndpointPair(c, p))
                return true
            }
            return false
        }

        // v4 pass
        var guard = 0
        val v4Guard = v4Quota * 20 + 64
        var made4 = 0
        while (made4 < v4Quota && guard < v4Guard) {
            guard++
            if (add(Candidate(nextV4Bytes()), nextPort())) made4++
        }
        // v6 pass (embedded twins of fresh random v4s)
        guard = 0
        val v6Guard = v6Quota * 20 + 64
        var made6 = 0
        val prefixes = listOf(Presets.WARP_V6_PREFIX_D0, Presets.WARP_V6_PREFIX_D1)
        while (made6 < v6Quota && guard < v6Guard) {
            guard++
            val v4 = nextV4Bytes()
            val prefix = prefixes[random.nextInt(prefixes.size)]
            val bytes = v6Embedded(prefix, v4) ?: continue
            if (add(Candidate(bytes), nextPort())) made6++
        }
        return out
    }

    fun estimate(cidrs: List<String>, family: NetFamily, samplesPerPrefix: Int): Int {
        val blocks = CidrBlock.parseAll(cidrs).filter {
            family == NetFamily.BOTH || (family == NetFamily.V4 && it.family == IpProtocol.IPv4) ||
                (family == NetFamily.V6 && it.family == IpProtocol.IPv6)
        }
        var total = 0
        for (b in blocks) {
            // v3.1.1: small blocks are capped by the samples knob now — the
            // estimate matches what sampleCandidates actually emits
            val enumerated = if (b.hostBitsValue() <= 10) {
                minOf(b.size.min(BigInteger.valueOf(2048)).toLong(), samplesPerPrefix.toLong()).toInt()
            } else samplesPerPrefix
            total += enumerated
        }
        return total
    }

    private fun CidrBlock.hostBitsValue(): Int = if (family == IpProtocol.IPv4) 32 - prefix else 128 - prefix
}
