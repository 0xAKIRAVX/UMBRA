//! Differential test vectors — byte-for-byte parity with the Kotlin
//! implementation (app/src/test/resources/warp_vectors.json) plus RFC
//! vectors. These pin the Rust port to the exact packet formats the
//! production Cloudflare WARP endpoints answered during live testing.

use umbra_core::crypto;
use umbra_core::util::{base64_decode, parse_json};
use umbra_core::wg;

fn hex(b: &[u8]) -> String {
    crypto::hex::encode(b)
}

fn unhex(s: &str) -> Vec<u8> {
    crypto::hex::decode_vec(s)
}

fn arr32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

/// Loads the vectors JSON shared with the Kotlin test suite.
fn vectors() -> umbra_core::util::Json {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../app/src/test/resources/warp_vectors.json");
    let text = std::fs::read_to_string(path)
        .expect("warp_vectors.json must sit next to the Kotlin tests");
    parse_json(&text).expect("vectors json parses")
}

#[test]
fn blake2s_vectors() {
    let v = vectors();
    for case in v.get("blake2s").unwrap().as_arr().unwrap() {
        let data = unhex(case.get("data").unwrap().as_str().unwrap());
        let out = crypto::blake2s(&data);
        assert_eq!(
            hex(&out),
            case.get("out").unwrap().as_str().unwrap(),
            "blake2s vector mismatch"
        );
    }
}

#[test]
fn blake2s_keyed_16_vectors() {
    // WireGuard mac1 form: keyed BLAKE2s with 16-byte digest
    let v = vectors();
    for case in v.get("blake2s_keyed128").unwrap().as_arr().unwrap() {
        let data = unhex(case.get("data").unwrap().as_str().unwrap());
        let key = unhex(case.get("key").unwrap().as_str().unwrap());
        let out = crypto::blake2s_mac16(&key, &data);
        assert_eq!(
            hex(&out),
            case.get("out").unwrap().as_str().unwrap(),
            "keyed blake2s-128 vector mismatch"
        );
    }
}

#[test]
fn hmac_blake2s_vectors() {
    let v = vectors();
    for case in v.get("hmac_blake2s").unwrap().as_arr().unwrap() {
        let key = unhex(case.get("key").unwrap().as_str().unwrap());
        let data = unhex(case.get("data").unwrap().as_str().unwrap());
        let out = crypto::hmac_blake2s(&key, &[&data]);
        assert_eq!(
            hex(&out),
            case.get("out").unwrap().as_str().unwrap(),
            "hmac-blake2s vector mismatch"
        );
    }
}

#[test]
fn x25519_vectors() {
    let v = vectors();
    for case in v.get("x25519").unwrap().as_arr().unwrap() {
        let priv_ = arr32(case.get("priv").unwrap().as_str().unwrap());
        let peer = arr32(case.get("peer_pub").unwrap().as_str().unwrap());
        let shared = crypto::x25519(&priv_, &peer);
        assert_eq!(
            hex(&shared),
            case.get("shared").unwrap().as_str().unwrap(),
            "x25519 shared mismatch"
        );
        // pub self-consistency
        let pub_ = crypto::x25519_base(&priv_);
        assert_eq!(hex(&pub_), case.get("pub").unwrap().as_str().unwrap());
    }
    // RFC 7748 vector
    let rfc = v.get("x25519_rfc7748").unwrap();
    let scalar = arr32(rfc.get("scalar").unwrap().as_str().unwrap());
    let u = arr32(rfc.get("u").unwrap().as_str().unwrap());
    let out = crypto::x25519(&scalar, &u);
    assert_eq!(hex(&out), rfc.get("out").unwrap().as_str().unwrap());
}

#[test]
fn aead_vectors() {
    let v = vectors();
    for case in v.get("aead").unwrap().as_arr().unwrap() {
        let key = arr32(case.get("key").unwrap().as_str().unwrap());
        let nonce: [u8; 12] = unhex(case.get("nonce").unwrap().as_str().unwrap())
            .try_into()
            .unwrap();
        let pt = unhex(case.get("pt").unwrap().as_str().unwrap());
        let aad = unhex(case.get("ad").unwrap().as_str().unwrap());
        let expect = case.get("ct").unwrap().as_str().unwrap();

        let sealed = crypto::aead_seal(&key, &nonce, &pt, &aad);
        assert_eq!(hex(&sealed), expect, "aead seal mismatch");

        let opened = crypto::aead_open(&key, &nonce, &sealed, &aad).unwrap();
        assert_eq!(opened, pt);
    }
}

#[test]
fn handshake_vector_closed_loop() {
    let v = vectors();
    let hs = v.get("handshake").unwrap();

    let init_priv = arr32(hs.get("init_static_priv").unwrap().as_str().unwrap());
    let init_pub = arr32(hs.get("init_static_pub").unwrap().as_str().unwrap());
    let resp_priv = arr32(hs.get("resp_static_priv").unwrap().as_str().unwrap());
    let resp_pub = arr32(hs.get("resp_static_pub").unwrap().as_str().unwrap());
    let eph_priv = arr32(hs.get("eph_priv").unwrap().as_str().unwrap());
    let resp_eph_priv = arr32(hs.get("resp_eph_priv").unwrap().as_str().unwrap());
    let timestamp: [u8; 12] = unhex(hs.get("timestamp").unwrap().as_str().unwrap())
        .try_into()
        .unwrap();
    let sender_index = hs.get("sender_index").unwrap().as_i64().unwrap() as u32;
    let their_index = hs.get("their_index").unwrap().as_i64().unwrap() as u32;

    // sanity: the vector's static keys are self-consistent
    assert_eq!(hex(&crypto::x25519_base(&init_priv)), hex(&init_pub));
    assert_eq!(hex(&crypto::x25519_base(&resp_priv)), hex(&resp_pub));

    // ---- 1. initiator builds the initiation (vector timestamp passed explicitly) ----
    let (packet, pending) = wg::build_initiation(
        &init_priv,
        &init_pub,
        &resp_pub,
        sender_index,
        &eph_priv,
        &timestamp,
    );
    let expect_init = hs.get("init_packet").unwrap().as_str().unwrap();
    assert_eq!(hex(&packet), expect_init, "initiation packet mismatch");

    // ---- 2. test-responder consumes it and builds the response ----
    let response = build_test_response(&packet, &resp_priv, &resp_eph_priv, their_index);
    let expect_resp = hs.get("response_packet").unwrap().as_str().unwrap();
    assert_eq!(hex(&response), expect_resp, "response packet mismatch");

    // ---- 3. initiator consumes the response ----
    let (session, err) = wg::consume_response(pending.as_ref().unwrap(), &init_priv, &response);
    let session = session.expect(&format!("response must verify: {}", err));
    assert_eq!(hex(&session.send_key), hs.get("send_key").unwrap().as_str().unwrap());
    assert_eq!(hex(&session.recv_key), hs.get("recv_key").unwrap().as_str().unwrap());
    assert_eq!(session.our_index, sender_index);
    assert_eq!(session.their_index, their_index);

    // ---- 4. transport request ----
    let tr = v.get("transport_req").unwrap();
    let ident = tr.get("ident").unwrap().as_i64().unwrap() as u16;
    let seq = tr.get("seq").unwrap().as_i64().unwrap() as u16;
    let inner = unhex(tr.get("inner").unwrap().as_str().unwrap());
    // the vector's inner packet: ip src 172.16.0.2 dst 1.1.1.1, ident, seq
    let built = wg::icmp_echo_request(&[172, 16, 0, 2], &[1, 1, 1, 1], ident, seq);
    assert_eq!(hex(&built), hex(&inner), "icmp echo request mismatch");

    let mut sess = session;
    let transport = sess.build_transport(&inner);
    assert_eq!(
        hex(&transport),
        tr.get("packet").unwrap().as_str().unwrap(),
        "transport packet mismatch"
    );

    // ---- 5. transport reply opens with the same session ----
    let reply = v.get("transport_reply").unwrap();
    let reply_pkt = unhex(reply.get("packet").unwrap().as_str().unwrap());
    let opened = sess.open_transport(&reply_pkt).expect("transport reply must open");
    assert_eq!(hex(&opened), reply.get("inner").unwrap().as_str().unwrap());
    assert!(wg::parse_echo_reply(&opened, ident, seq), "echo reply must parse");
}

/// Minimal WIREGUARD RESPONDER for the closed-loop test (initiator-side
/// semantics only; mac1/mac2 left zero like the vector).
fn build_test_response(
    initiation: &[u8],
    resp_static_priv: &[u8; 32],
    resp_eph_priv: &[u8; 32],
    their_index: u32,
) -> Vec<u8> {
    use umbra_core::crypto as c;

    assert_eq!(initiation.len(), wg::INITIATION_SIZE);
    let eph_pub: [u8; 32] = initiation[8..40].try_into().unwrap();
    let static_ct = &initiation[40..88];
    let ts_ct = &initiation[88..116];
    let init_sender_index = u32::from_le_bytes(initiation[4..8].try_into().unwrap());

    // noise state (responder side mirrors the initiator chain)
    let construction = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    let identifier = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
    let init_ck = c::blake2s(construction);
    let mut ckh = Vec::new();
    ckh.extend_from_slice(&init_ck);
    ckh.extend_from_slice(identifier);
    let init_h = c::blake2s(&ckh);

    let resp_static_pub = c::x25519_base(resp_static_priv);

    let mix_hash = |h: &[u8; 32], d: &[u8]| -> [u8; 32] {
        let mut b = Vec::with_capacity(32 + d.len());
        b.extend_from_slice(h);
        b.extend_from_slice(d);
        c::blake2s(&b)
    };
    let mix_key = |ck: &[u8; 32], d: &[u8]| -> [u8; 32] {
        let inner = c::hmac_blake2s(ck, &[d]);
        c::hmac_blake2s(&inner, &[&[1u8][..]])
    };
    let kdf2 = |key: &[u8; 32], input: &[u8]| -> ([u8; 32], [u8; 32]) {
        let prk = c::hmac_blake2s(key, &[input]);
        let t0 = c::hmac_blake2s(&prk, &[&[1u8][..]]);
        let mut t0b = t0.to_vec();
        t0b.push(2);
        let t1 = c::hmac_blake2s(&prk, &[&t0b]);
        (t0, t1)
    };
    let kdf3 = |key: &[u8; 32], input: &[u8]| -> ([u8; 32], [u8; 32], [u8; 32]) {
        let prk = c::hmac_blake2s(key, &[input]);
        let t0 = c::hmac_blake2s(&prk, &[&[1u8][..]]);
        let mut a = t0.to_vec();
        a.push(2);
        let t1 = c::hmac_blake2s(&prk, &[&a]);
        let mut b = t1.to_vec();
        b.push(3);
        let t2 = c::hmac_blake2s(&prk, &[&b]);
        (t0, t1, t2)
    };
    let zero_nonce = [0u8; 12];

    let mut h = mix_hash(&init_h, &resp_static_pub);
    let mut ck = mix_key(&init_ck, &eph_pub);
    h = mix_hash(&h, &eph_pub);

    // decrypt initiator static: ee = DH(responder_static_priv, initiator_eph_pub)
    // (== the initiator's DH(eph_i, responder_pub))
    let ee = c::x25519_shared(resp_static_priv, &eph_pub).unwrap();
    let (ck1, k_static) = kdf2(&ck, &ee);
    ck = ck1;
    let init_static: [u8; 32] = c::aead_open(&k_static, &zero_nonce, static_ct, &h)
        .expect("initiator static must decrypt")
        .try_into()
        .unwrap();
    h = mix_hash(&h, static_ct);

    // decrypt + verify timestamp (initiator static <-> responder static)
    let ss = c::x25519_shared(resp_static_priv, &init_static).unwrap();
    let (ck2, k_ts) = kdf2(&ck, &ss);
    ck = ck2;
    let _ts = c::aead_open(&k_ts, &zero_nonce, ts_ct, &h).expect("timestamp must decrypt");
    h = mix_hash(&h, ts_ct);

    // build the response: ee2 = DH(eph_r, eph_i); se2 = DH(eph_r, static_i)
    let resp_eph_pub = c::x25519_base(resp_eph_priv);
    h = mix_hash(&h, &resp_eph_pub);
    ck = mix_key(&ck, &resp_eph_pub);
    let ee2 = c::x25519_shared(resp_eph_priv, &eph_pub).unwrap();
    ck = mix_key(&ck, &ee2);
    let se2 = c::x25519_shared(resp_eph_priv, &init_static).unwrap();
    ck = mix_key(&ck, &se2);
    let psk = [0u8; 32];
    let (ck3, tau, k) = kdf3(&ck, &psk);
    ck = ck3;
    h = mix_hash(&h, &tau);
    let empty_ct = c::aead_seal(&k, &zero_nonce, &[], &h);
    h = mix_hash(&h, &empty_ct);
    let (send_key, recv_key) = kdf2(&ck, &[]);

    let mut packet = vec![0u8; wg::RESPONSE_SIZE];
    packet[0..4].copy_from_slice(&(wg::MSG_RESPONSE as u32).to_le_bytes());
    packet[4..8].copy_from_slice(&their_index.to_le_bytes());
    packet[8..12].copy_from_slice(&init_sender_index.to_le_bytes());
    packet[12..44].copy_from_slice(&resp_eph_pub);
    packet[44..60].copy_from_slice(&empty_ct);
    // mac1 = keyed BLAKE2s-128 over bytes 0..60, key = BLAKE2s("mac1----" || INITIATOR static pub)
    let mut mac_key_in = Vec::with_capacity(39);
    mac_key_in.extend_from_slice(b"mac1----");
    mac_key_in.extend_from_slice(&init_static);
    let mac1_key = c::blake2s(&mac_key_in);
    let mac1 = c::blake2s_mac16(&mac1_key, &packet[0..60]);
    packet[60..76].copy_from_slice(&mac1);
    // mac2 stays zero (no cookie)

    // session keys from the RESPONDER's perspective: send = what the
    // initiator will receive with. (unused here; kept for clarity)
    let _ = (send_key, recv_key);
    packet
}

#[test]
fn tai64n_monotonic_bumps() {
    wg::reset_mark();
    let a = wg::tai64n_now();
    let b = wg::tai64n_now();
    assert!(b > a, "timestamps must strictly increase");
    // bump-by-1ns semantics: the pair differs in the last byte at most
    // unless the nanos wrapped (astronomically unlikely in a test)
    assert_eq!(a[0..8], b[0..8]);
    wg::reset_mark();
}

#[test]
fn base64_interop() {
    // the identity JSON the Kotlin side sends uses standard base64
    let key = [0xABu8; 32];
    let enc = umbra_core::util::base64_encode(&key);
    let dec = base64_decode(&enc).unwrap();
    assert_eq!(dec, key);
    // Accepts the 43-char unpadded form too? (Kotlin always pads — we only
    // need to tolerate whitespace)
    let spaced = format!("{} ", enc);
    assert_eq!(base64_decode(&spaced).unwrap(), key);
}
