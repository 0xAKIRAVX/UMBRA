//! probe_once smoke test on the host — dead IP, fast budget.

#[test]
fn probe_once_dead_ip() {
    let cfg = r#"{"identity":{"priv":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "pub":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        "peer":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "v4":"172.16.0.2"},
        "attempts":1,"timeout_ms":400,"inter_ms":0,"noise":false,"debug":true}"#;
    let mut out = Vec::new();
    let n = umbra_core::scanner::probe_once_json("203.0.113.1", 2408, cfg, &mut out);
    let s = String::from_utf8(out).unwrap();
    println!("probe_once_json -> len={} {}", n, s);
    assert!(s.contains("\"ok\":true"));
    assert!(s.contains("\"dbg\":[") && !s.contains("\"dbg\":[]"), "debug lines must narrate: {}", s);
}
