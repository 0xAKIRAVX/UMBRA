//! Minimal utilities: JSON parse/write, base64, IP parsing.
//! Zero dependencies — std only.

// ---------------------------------------------------------------- JSON ----

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        if let Json::Obj(pairs) = self {
            for (k, v) in pairs {
                if k == key { return Some(v); }
            }
        }
        None
    }

    pub fn as_str(&self) -> Option<&str> {
        if let Json::Str(s) = self { Some(s) } else { None }
    }

    pub fn as_f64(&self) -> Option<f64> {
        if let Json::Num(n) = self { Some(*n) } else { None }
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.as_f64().map(|f| f as i64)
    }

    pub fn as_u16(&self) -> Option<u16> {
        self.as_f64().map(|f| f as i64 as u16)
    }

    pub fn as_bool(&self) -> Option<bool> {
        if let Json::Bool(b) = self { Some(*b) } else { None }
    }

    pub fn as_arr(&self) -> Option<&Vec<Json>> {
        if let Json::Arr(a) = self { Some(a) } else { None }
    }
}

pub fn parse_json(text: &str) -> Option<Json> {
    let bytes: Vec<char> = text.chars().collect();
    let mut pos = 0usize;
    let v = parse_value(&bytes, &mut pos)?;
    skip_ws(&bytes, &mut pos);
    if pos != bytes.len() { return None; }
    Some(v)
}

fn skip_ws(b: &[char], pos: &mut usize) {
    while *pos < b.len() && (b[*pos] == ' ' || b[*pos] == '\t' || b[*pos] == '\n' || b[*pos] == '\r') {
        *pos += 1;
    }
}

fn parse_value(b: &[char], pos: &mut usize) -> Option<Json> {
    skip_ws(b, pos);
    if *pos >= b.len() { return None; }
    match b[*pos] {
        '{' => {
            *pos += 1;
            let mut pairs = Vec::new();
            skip_ws(b, pos);
            if *pos < b.len() && b[*pos] == '}' { *pos += 1; return Some(Json::Obj(pairs)); }
            loop {
                skip_ws(b, pos);
                let key = parse_string(b, pos)?;
                skip_ws(b, pos);
                if *pos >= b.len() || b[*pos] != ':' { return None; }
                *pos += 1;
                let val = parse_value(b, pos)?;
                pairs.push((key, val));
                skip_ws(b, pos);
                if *pos >= b.len() { return None; }
                if b[*pos] == ',' { *pos += 1; continue; }
                if b[*pos] == '}' { *pos += 1; return Some(Json::Obj(pairs)); }
                return None;
            }
        }
        '[' => {
            *pos += 1;
            let mut items = Vec::new();
            skip_ws(b, pos);
            if *pos < b.len() && b[*pos] == ']' { *pos += 1; return Some(Json::Arr(items)); }
            loop {
                let val = parse_value(b, pos)?;
                items.push(val);
                skip_ws(b, pos);
                if *pos >= b.len() { return None; }
                if b[*pos] == ',' { *pos += 1; continue; }
                if b[*pos] == ']' { *pos += 1; return Some(Json::Arr(items)); }
                return None;
            }
        }
        '"' => parse_string(b, pos).map(Json::Str),
        't' => {
            if b.len() >= *pos + 4 && b[*pos..*pos + 4].iter().collect::<String>() == "true" {
                *pos += 4; Some(Json::Bool(true))
            } else { None }
        }
        'f' => {
            if b.len() >= *pos + 5 && b[*pos..*pos + 5].iter().collect::<String>() == "false" {
                *pos += 5; Some(Json::Bool(false))
            } else { None }
        }
        'n' => {
            if b.len() >= *pos + 4 && b[*pos..*pos + 4].iter().collect::<String>() == "null" {
                *pos += 4; Some(Json::Null)
            } else { None }
        }
        _ => {
            let start = *pos;
            while *pos < b.len()
                && (b[*pos].is_ascii_digit()
                    || b[*pos] == '-'
                    || b[*pos] == '+'
                    || b[*pos] == '.'
                    || b[*pos] == 'e'
                    || b[*pos] == 'E')
            {
                *pos += 1;
            }
            if start == *pos { return None; }
            let s: String = b[start..*pos].iter().collect();
            s.parse::<f64>().ok().map(Json::Num)
        }
    }
}

fn parse_string(b: &[char], pos: &mut usize) -> Option<String> {
    skip_ws(b, pos);
    if *pos >= b.len() || b[*pos] != '"' { return None; }
    *pos += 1;
    let mut out = String::new();
    while *pos < b.len() {
        let c = b[*pos];
        *pos += 1;
        match c {
            '"' => return Some(out),
            '\\' => {
                if *pos >= b.len() { return None; }
                let e = b[*pos];
                *pos += 1;
                match e {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'u' => {
                        if *pos + 4 > b.len() { return None; }
                        let hexs: String = b[*pos..*pos + 4].iter().collect();
                        *pos += 4;
                        let cp = u32::from_str_radix(&hexs, 16).ok()?;
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                        }
                    }
                    _ => return None,
                }
            }
            _ => out.push(c),
        }
    }
    None
}

/// JSON string escaping for the writer side.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ------------------------------------------------------------- base64 ----

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64_ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64_ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let clean: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    let mut i = 0;
    while i + 3 < clean.len() || (i < clean.len() && clean[i] != b'=') {
        // process groups of 4
        if i + 4 > clean.len() { return None; }
        let c0 = val(clean[i])?;
        let c1 = val(clean[i + 1])?;
        let has2 = clean[i + 2] != b'=';
        let has3 = clean[i + 3] != b'=';
        let c2 = if has2 { val(clean[i + 2])? } else { 0 };
        let c3 = if has3 { val(clean[i + 3])? } else { 0 };
        let n = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
        out.push((n >> 16) as u8);
        if has2 { out.push((n >> 8) as u8); }
        if has3 { out.push(n as u8); }
        i += 4;
        if !has2 || !has3 { break; }
    }
    Some(out)
}

// ------------------------------------------------------------------ IP ----

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parses "162.159.192.42" or "[2606:4700:d0::a29f:c02a]" or bare v6.
pub fn parse_ip(text: &str) -> Option<IpAddr> {
    let t = text.trim();
    let t = if t.starts_with('[') && t.ends_with(']') { &t[1..t.len() - 1] } else { t };
    t.parse::<IpAddr>().ok()
}

/// Renders an IpAddr; v6 gets brackets (endpoint display convention).
pub fn format_ip_port(ip: &IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v) => format!("{}:{}", v, port),
        IpAddr::V6(v) => format!("[{}]:{}", v, port),
    }
}

pub fn is_v6(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(_))
}

/// Parses "172.16.0.2" into 4 bytes.
pub fn parse_v4_bytes(text: &str) -> Option<[u8; 4]> {
    match parse_ip(text) {
        Some(IpAddr::V4(v)) => Some(v.octets()),
        _ => None,
    }
}

#[allow(dead_code)]
pub fn v6_from_v4_embedded(prefix: &str, v4: [u8; 4]) -> Option<IpAddr> {
    // prefix like "2606:4700:d0::" + embedded v4 bytes
    let mut s = prefix.to_string();
    for b in v4 {
        s.push_str(&format!("{:02x}", b));
    }
    // insert colons: last 4 bytes = 2 groups
    let base = prefix.trim_end_matches(':').to_string();
    let h1 = format!("{:02x}{:02x}", v4[0], v4[1]);
    let h2 = format!("{:02x}{:02x}", v4[2], v4[3]);
    let full = format!("{}:{}:{}", base, h1, h2);
    full.parse::<IpAddr>().ok().or_else(|| s.parse::<IpAddr>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip() {
        let v = parse_json(r#"{"a":1,"b":[1,2,"x"],"c":{"d":true,"e":null},"f":-2.5}"#).unwrap();
        assert_eq!(v.get("a").unwrap().as_i64(), Some(1));
        assert_eq!(v.get("b").unwrap().as_arr().unwrap().len(), 3);
        assert_eq!(v.get("c").unwrap().get("d").unwrap().as_bool(), Some(true));
        assert_eq!(v.get("f").unwrap().as_f64(), Some(-2.5));
        assert!(parse_json("{bad json").is_none());
    }

    #[test]
    fn b64_roundtrip() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len as u8).map(|x| x.wrapping_mul(7).wrapping_add(3)).collect();
            let enc = base64_encode(&data);
            let dec = base64_decode(&enc).unwrap();
            assert_eq!(dec, data);
        }
        // known vector
        assert_eq!(base64_encode(b"abc"), "YWJj");
        assert_eq!(base64_decode("YWJj").unwrap(), b"abc");
        assert_eq!(base64_decode("dGVzdA==").unwrap(), b"test");
    }

    #[test]
    fn ips() {
        assert!(parse_ip("162.159.192.42").is_some());
        assert!(parse_ip("[2606:4700:d0::a29f:c02a]").is_some());
        assert!(parse_ip("not-an-ip").is_none());
        assert_eq!(parse_v4_bytes("172.16.0.2"), Some([172, 16, 0, 2]));
    }
}
