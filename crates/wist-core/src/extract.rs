use serde_json::{json, Value};
use std::collections::HashSet;

const UNRESERVED: &[u8; 66] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

fn is_unreserved(b: u8) -> bool {
    UNRESERVED.contains(&b)
}

const NAMED_REFS: [(&[u8], char); 5] = [
    (b"amp", '&'),
    (b"lt", '<'),
    (b"gt", '>'),
    (b"quot", '"'),
    (b"apos", '\''),
];

enum RefBody<'a> {
    Named(char),
    Numeric { digits: &'a [u8], base: u32 },
}

fn next_char_ref(bytes: &[u8], from: usize) -> Option<(usize, usize, RefBody<'_>)> {
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            for (name, ch) in NAMED_REFS {
                let name_end = i + 1 + name.len();
                if bytes.get(i + 1..name_end) == Some(name) && bytes.get(name_end) == Some(&b';') {
                    return Some((i, name_end + 1, RefBody::Named(ch)));
                }
            }
            if bytes.get(i + 1) == Some(&b'#') {
                let (base, digit_start) = if matches!(bytes.get(i + 2), Some(b'x') | Some(b'X')) {
                    (16u32, i + 3)
                } else {
                    (10u32, i + 2)
                };
                let is_digit: fn(u8) -> bool = if base == 16 {
                    |b: u8| b.is_ascii_hexdigit()
                } else {
                    |b: u8| b.is_ascii_digit()
                };
                let mut j = digit_start;
                while bytes.get(j).is_some_and(|&b| is_digit(b)) {
                    j += 1;
                }
                if j > digit_start && bytes.get(j) == Some(&b';') {
                    return Some((
                        i,
                        j + 1,
                        RefBody::Numeric {
                            digits: &bytes[digit_start..j],
                            base,
                        },
                    ));
                }
            }
        }
        i += 1;
    }
    None
}

fn numeric_codepoint(digits: &[u8], base: u32) -> Option<u32> {
    let lead_zeros = digits.iter().take_while(|&&b| b == b'0').count();
    let sig_len = if lead_zeros == digits.len() {
        1
    } else {
        digits.len() - lead_zeros
    };
    let max_digits = if base == 10 { 7 } else { 6 };
    if sig_len > max_digits {
        return None;
    }
    let start = if lead_zeros == digits.len() {
        digits.len() - 1
    } else {
        lead_zeros
    };
    let mut cp: u32 = 0;
    for &b in &digits[start..] {
        let d = (b as char).to_digit(base)?;
        cp = cp.checked_mul(base)?.checked_add(d)?;
    }
    if cp > 0x10FFFF || (0xD800..=0xDFFF).contains(&cp) {
        return None;
    }
    Some(cp)
}

fn decode_entities(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut pos = 0usize;
    loop {
        match next_char_ref(bytes, pos) {
            None => {
                out.push_str(&s[pos..]);
                return Some(out);
            }
            Some((start, end, body)) => {
                out.push_str(&s[pos..start]);
                match body {
                    RefBody::Named(c) => out.push(c),
                    RefBody::Numeric { digits, base } => {
                        let cp = numeric_codepoint(digits, base)?;
                        out.push(char::from_u32(cp)?);
                    }
                }
                pos = end;
            }
        }
    }
}

fn decode_text_entities(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut pos = 0usize;
    loop {
        match next_char_ref(bytes, pos) {
            None => {
                out.push_str(&s[pos..]);
                return out;
            }
            Some((start, end, body)) => {
                out.push_str(&s[pos..start]);
                match body {
                    RefBody::Named(c) => out.push(c),
                    RefBody::Numeric { digits, base } => match numeric_codepoint(digits, base) {
                        Some(cp) => match char::from_u32(cp) {
                            Some(c) => out.push(c),
                            None => out.push_str(&s[start..end]),
                        },
                        None => out.push_str(&s[start..end]),
                    },
                }
                pos = end;
            }
        }
    }
}

fn at_tag_boundary(low: &[u8], pos: usize) -> bool {
    pos >= low.len() || matches!(low[pos], b' ' | b'\t' | b'\n' | 0x0c | b'\r' | b'/' | b'>')
}

fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > hay.len() || needle.is_empty() || hay.len() - from < needle.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn find_byte_from(hay: &[u8], needle: u8, from: usize) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..]
        .iter()
        .position(|&b| b == needle)
        .map(|p| p + from)
}

fn tag_end(html: &[u8], pos: usize) -> usize {
    let n = html.len();
    let mut j = pos;
    while j < n {
        let c = html[j];
        if c == b'"' || c == b'\'' {
            j = match find_byte_from(html, c, j + 1) {
                Some(end_q) => end_q + 1,
                None => n,
            };
            continue;
        }
        if c == b'>' {
            return j;
        }
        j += 1;
    }
    n
}

const RAWTEXT_TAGS: [&[u8]; 3] = [b"script", b"style", b"textarea"];

fn find_rawtext_tag(low: &[u8], i: usize) -> Option<&'static [u8]> {
    if low.get(i) != Some(&b'<') {
        return None;
    }
    RAWTEXT_TAGS.into_iter().find(|t| {
        low.get(i + 1..i + 1 + t.len()) == Some(*t) && at_tag_boundary(low, i + 1 + t.len())
    })
}

fn iter_hrefs(html: &[u8]) -> Vec<String> {
    let low = html.to_ascii_lowercase();
    let n = html.len();
    let mut i = 0usize;
    let mut out = Vec::new();
    while i < n {
        if low[i..].starts_with(b"<!--") {
            i = find_from(&low, b"-->", i + 4).map(|e| e + 3).unwrap_or(n);
            continue;
        }
        if let Some(tag) = find_rawtext_tag(&low, i) {
            let open_end = tag_end(html, i + 1 + tag.len());
            let close_pat = [b"</".as_slice(), tag].concat();
            i = find_from(&low, &close_pat, open_end).unwrap_or(n);
            continue;
        }
        if low.get(i) == Some(&b'<')
            && low.get(i + 1) == Some(&b'a')
            && at_tag_boundary(&low, i + 2)
        {
            let mut j = i + 2;
            let mut href_value: Option<Vec<u8>> = None;
            while j < n {
                let c = html[j];
                if c == b'>' {
                    j += 1;
                    break;
                }
                if matches!(c, b' ' | b'\t' | b'\n' | 0x0c | b'\r' | b'/') {
                    j += 1;
                    continue;
                }
                let name_start = j;
                while j < n
                    && !matches!(
                        html[j],
                        b' ' | b'\t' | b'\n' | 0x0c | b'\r' | b'=' | b'>' | b'/'
                    )
                {
                    j += 1;
                }
                let name = &low[name_start..j];
                while j < n && matches!(html[j], b' ' | b'\t' | b'\n' | 0x0c | b'\r') {
                    j += 1;
                }
                let mut value: Option<Vec<u8>> = None;
                if j < n && html[j] == b'=' {
                    j += 1;
                    while j < n && matches!(html[j], b' ' | b'\t' | b'\n' | 0x0c | b'\r') {
                        j += 1;
                    }
                    if j < n && (html[j] == b'"' || html[j] == b'\'') {
                        let quote = html[j];
                        j += 1;
                        let val_start = j;
                        match find_byte_from(html, quote, j) {
                            Some(end_q) => {
                                value = Some(html[val_start..end_q].to_vec());
                                j = end_q + 1;
                            }
                            None => {
                                value = Some(html[val_start..n].to_vec());
                                j = n;
                            }
                        }
                    } else {
                        let val_start = j;
                        while j < n
                            && !matches!(html[j], b' ' | b'\t' | b'\n' | 0x0c | b'\r' | b'>')
                        {
                            j += 1;
                        }
                        value = Some(html[val_start..j].to_vec());
                    }
                }
                if name == b"href" && href_value.is_none() {
                    href_value = Some(value.unwrap_or_default());
                }
            }
            if let Some(hv) = href_value {
                let s = String::from_utf8_lossy(&hv).into_owned();
                if let Some(decoded) = decode_entities(&s) {
                    out.push(decoded);
                }
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

fn valid_scheme(s: &str) -> bool {
    let mut it = s.bytes();
    match it.next() {
        Some(b) if b.is_ascii_alphabetic() => {}
        _ => return false,
    }
    it.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

struct UriRef {
    scheme: Option<String>,
    authority: Option<String>,
    path: String,
    query: Option<String>,
}

fn split_uri_ref(s: &str) -> UriRef {
    let mut rest = s;
    let scheme = if let Some(colon) = rest.find(':') {
        let candidate = &rest[..colon];
        if valid_scheme(candidate) {
            let sc = candidate.to_ascii_lowercase();
            rest = &rest[colon + 1..];
            Some(sc)
        } else {
            None
        }
    } else {
        None
    };
    let authority = if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let auth = after[..end].to_string();
        rest = &after[end..];
        Some(auth)
    } else {
        None
    };
    let path_end = rest.find(['?', '#']).unwrap_or(rest.len());
    let path = rest[..path_end].to_string();
    rest = &rest[path_end..];
    let query = rest.strip_prefix('?').map(|after| {
        let end = after.find('#').unwrap_or(after.len());
        after[..end].to_string()
    });
    UriRef {
        scheme,
        authority,
        path,
        query,
    }
}

fn merge(base_has_authority: bool, base_path: &str, r_path: &str) -> String {
    if base_has_authority && base_path.is_empty() {
        format!("/{r_path}")
    } else {
        match base_path.rfind('/') {
            Some(idx) => format!("{}{r_path}", &base_path[..=idx]),
            None => r_path.to_string(),
        }
    }
}

fn remove_dot_segments(path: &str) -> String {
    let mut path = path.to_string();
    let mut output: Vec<String> = Vec::new();
    while !path.is_empty() {
        if let Some(rest) = path.strip_prefix("../") {
            path = rest.to_string();
        } else if let Some(rest) = path.strip_prefix("./") {
            path = rest.to_string();
        } else if let Some(rest) = path.strip_prefix("/./") {
            path = format!("/{rest}");
        } else if path == "/." {
            path = "/".to_string();
        } else if let Some(rest) = path.strip_prefix("/../") {
            path = format!("/{rest}");
            output.pop();
        } else if path == "/.." {
            path = "/".to_string();
            output.pop();
        } else if path == "." || path == ".." {
            path.clear();
        } else {
            let start = if path.starts_with('/') { 1 } else { 0 };
            match path[start..].find('/') {
                Some(rel_idx) => {
                    let idx = rel_idx + start;
                    output.push(path[..idx].to_string());
                    path = path[idx..].to_string();
                }
                None => {
                    output.push(path.clone());
                    path.clear();
                }
            }
        }
    }
    output.concat()
}

fn transform_references(base: &UriRef, r: &UriRef) -> UriRef {
    if let Some(scheme) = &r.scheme {
        UriRef {
            scheme: Some(scheme.clone()),
            authority: r.authority.clone(),
            path: remove_dot_segments(&r.path),
            query: r.query.clone(),
        }
    } else if let Some(auth) = &r.authority {
        UriRef {
            scheme: base.scheme.clone(),
            authority: Some(auth.clone()),
            path: remove_dot_segments(&r.path),
            query: r.query.clone(),
        }
    } else if r.path.is_empty() {
        UriRef {
            scheme: base.scheme.clone(),
            authority: base.authority.clone(),
            path: base.path.clone(),
            query: r.query.clone().or_else(|| base.query.clone()),
        }
    } else {
        let path = if r.path.starts_with('/') {
            remove_dot_segments(&r.path)
        } else {
            remove_dot_segments(&merge(base.authority.is_some(), &base.path, &r.path))
        };
        UriRef {
            scheme: base.scheme.clone(),
            authority: base.authority.clone(),
            path,
            query: r.query.clone(),
        }
    }
}

fn split_host_port(authority: &str) -> (String, Option<String>) {
    if let Some(rest) = authority.strip_prefix('[') {
        match rest.find(']') {
            Some(idx) => {
                let host = rest[..idx].to_string();
                let after = &rest[idx + 1..];
                let port = after.strip_prefix(':').map(|p| p.to_string());
                (host, port)
            }
            None => (rest.to_string(), None),
        }
    } else {
        match authority.find(':') {
            Some(idx) => (
                authority[..idx].to_string(),
                Some(authority[idx + 1..].to_string()),
            ),
            None => (authority.to_string(), None),
        }
    }
}

enum PortResult {
    Absent,
    Valid(u16),
    Invalid,
}

fn parse_port(p: Option<String>) -> PortResult {
    match p {
        None => PortResult::Absent,
        Some(s) if s.is_empty() => PortResult::Absent,
        Some(s) => {
            if s.bytes().all(|b| b.is_ascii_digit()) {
                match s.parse::<u32>() {
                    Ok(v) if v <= 65535 => PortResult::Valid(v as u16),
                    _ => PortResult::Invalid,
                }
            } else {
                PortResult::Invalid
            }
        }
    }
}

fn is_ldh_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(*bytes.last().unwrap()) {
        return false;
    }
    bytes.iter().all(|&b| is_alnum(b) || b == b'-')
}

fn is_ldh_host(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    host.split('.').all(is_ldh_label)
}

fn renormalize_escapes(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let h1 = *bytes.get(i + 1)?;
            let h2 = *bytes.get(i + 2)?;
            if !h1.is_ascii_hexdigit() || !h2.is_ascii_hexdigit() {
                return None;
            }
            let octet = (h1 as char).to_digit(16)? as u8 * 16 + (h2 as char).to_digit(16)? as u8;
            if is_unreserved(octet) {
                out.push(octet as char);
            } else {
                out.push('%');
                out.push(h1.to_ascii_uppercase() as char);
                out.push(h2.to_ascii_uppercase() as char);
            }
            i += 3;
        } else {
            let ch = s[i..].chars().next()?;
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    Some(out)
}

pub fn normalize_url(candidate: &str, base: &str) -> Option<String> {
    if candidate.chars().any(|c| (c as u32) < 0x20) {
        return None;
    }
    let r = split_uri_ref(candidate);
    let b = split_uri_ref(base);
    let target = transform_references(&b, &r);

    if target.scheme.as_deref() != Some("https") {
        return None;
    }
    let authority = target.authority?;
    if authority.contains('@') {
        return None;
    }
    let (host_raw, port_part) = split_host_port(&authority);
    let host = host_raw.to_lowercase();
    if !is_ldh_host(&host) {
        return None;
    }
    let port = match parse_port(port_part) {
        PortResult::Invalid => return None,
        PortResult::Absent => None,
        PortResult::Valid(v) => Some(v),
    };
    let netloc = match port {
        Some(p) if p != 443 => format!("{host}:{p}"),
        _ => host,
    };

    let path = renormalize_escapes(&target.path)?;
    let path = remove_dot_segments(&path);
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path
    };

    let mut out = format!("https://{netloc}{path}");
    if let Some(q) = target.query {
        let q = renormalize_escapes(&q)?;
        out.push('?');
        out.push_str(&q);
    }
    Some(out)
}

fn host_of_normalized(url: &str) -> &str {
    let rest = &url[b"https://".len()..];
    let end = rest.find(['/', ':']).unwrap_or(rest.len());
    &rest[..end]
}

fn external(url: &str, publisher_domain: &str) -> bool {
    let host = host_of_normalized(url);
    host != publisher_domain && !host.ends_with(&format!(".{publisher_domain}"))
}

pub fn extract_links(html: &[u8], base_url: &str, publisher_domain: &str) -> (Vec<String>, u64) {
    let mut seen = HashSet::new();
    let mut urls = Vec::new();
    for candidate in iter_hrefs(html) {
        let trimmed = candidate.trim();
        if let Some(url) = normalize_url(trimmed, base_url) {
            if external(&url, publisher_domain) && seen.insert(url.clone()) {
                urls.push(url);
            }
        }
    }
    let total = urls.len() as u64;
    (urls, total)
}

pub fn links_member(urls: &[String], total: u64, cap_bytes: usize) -> Value {
    for k in (0..=urls.len()).rev() {
        let member = json!({ "total": total, "urls": urls[..k] });
        if let Ok(bytes) = crate::jcs::canonicalize(&member) {
            if bytes.len() <= cap_bytes {
                return member;
            }
        }
    }
    // WIST-4 §9: links_cap_bytes MUST be >= 21 octets, so this is an operator
    // config bug, not attacker-reachable HTML; mirrors the Python reference's
    // AssertionError rather than papering over a cap that admits no member.
    panic!(
        "cap_bytes={cap_bytes} is below the minimal links object {{\"total\": {total}, \"urls\": []}}; no conforming member exists"
    );
}

pub fn extract_text(html: &[u8]) -> String {
    let low = html.to_ascii_lowercase();
    let n = html.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut i = 0usize;
    while i < n {
        if low[i..].starts_with(b"<!--") {
            i = find_from(&low, b"-->", i + 4).map(|e| e + 3).unwrap_or(n);
            out.push(b' ');
            continue;
        }
        if let Some(tag) = find_rawtext_tag(&low, i) {
            let start_end = tag_end(html, i);
            let close_pat = [b"</".as_slice(), tag].concat();
            i = match find_from(&low, &close_pat, start_end) {
                Some(close) => tag_end(html, close) + 1,
                None => n,
            };
            out.push(b' ');
            continue;
        }
        let c = html[i];
        if c == b'<' {
            let next_byte = html.get(i + 1).copied();
            let opens_tag = next_byte.is_some_and(|b| b.is_ascii_alphabetic())
                || matches!(next_byte, Some(b'/') | Some(b'!') | Some(b'?'));
            if opens_tag {
                i = tag_end(html, i) + 1;
                out.push(b' ');
                continue;
            }
        }
        let search_from = if c == b'<' { i + 1 } else { i };
        let nxt = find_byte_from(html, b'<', search_from).unwrap_or(n);
        out.extend_from_slice(&html[i..nxt]);
        i = nxt;
    }
    let text = String::from_utf8_lossy(&out).into_owned();
    let text = decode_text_entities(&text);
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn shingles<T: Eq + std::hash::Hash + Clone>(units: &[T], n: usize) -> HashSet<Vec<T>> {
    let len = units.len();
    let count = (len + 1).saturating_sub(n);
    (0..count).map(|k| units[k..k + n].to_vec()).collect()
}

fn contained_micro<T: Eq + std::hash::Hash + Clone>(a_units: &[T], b_units: &[T], n: usize) -> u64 {
    let a = shingles(a_units, n);
    let b = shingles(b_units, n);
    let inter = a.intersection(&b).count() as u64;
    (inter * 1_000_000) / (a.len() as u64)
}

pub fn similarity(reference: &str, observed: &str, min_observed_words: u64) -> Option<u64> {
    let ref_folded = reference.to_lowercase();
    let obs_folded = observed.to_lowercase();
    let ref_words: Vec<&str> = ref_folded.split_whitespace().collect();
    let obs_words: Vec<&str> = obs_folded.split_whitespace().collect();
    if (obs_words.len() as u64) < min_observed_words {
        return None;
    }
    if ref_words.len() >= 8 && obs_words.len() >= 8 {
        Some(contained_micro(&ref_words, &obs_words, 8))
    } else {
        let ref_chars: Vec<char> = ref_folded.chars().collect();
        let obs_chars: Vec<char> = obs_folded.chars().collect();
        let n = ref_chars.len().min(obs_chars.len()).min(8);
        Some(contained_micro(&ref_chars, &obs_chars, n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const BASE: &str = "https://example.com/blog/post-1";

    #[test]
    fn normalize_oracle() {
        let cases: &[(&str, Option<&str>)] = &[
            (
                "https://example.com/blog/a/b/..",
                Some("https://example.com/blog/a/"),
            ),
            ("a/b/..", Some("https://example.com/blog/a/")),
            ("https://example.com:99999/x", None),
            ("https://example.com:abc/x", None),
            (
                "https://example.org/%7euser",
                Some("https://example.org/~user"),
            ),
            (
                "https://example.com/a%2fb",
                Some("https://example.com/a%2Fb"),
            ),
            ("https://user@example.com/x", None),
            ("https://[::1]/x", None),
            ("https://exa mple.com/x", None),
            ("https://example.com/x#frag", Some("https://example.com/x")),
            ("https://example.com:443/x", Some("https://example.com/x")),
            ("https://example.com", Some("https://example.com/")),
            ("https://example.com/\tx", None),
            ("a//b", Some("https://example.com/blog/a//b")),
            ("x//", Some("https://example.com/blog/x//")),
        ];
        for (candidate, expected) in cases {
            assert_eq!(
                normalize_url(candidate, BASE).as_deref(),
                *expected,
                "candidate {candidate:?}"
            );
        }
    }

    #[test]
    fn scan_oracle() {
        let cases: &[(&[u8], &[&str])] = &[
            (br#"<a data-href="https://example.org/x">t</a>"#, &[]),
            (br#"<!-- <a href="https://example.org/x">t</a> -->"#, &[]),
            (
                br#"<a title="a>b" href="https://example.org/x">t</a>"#,
                &["https://example.org/x"],
            ),
            (
                br#"<a href="https://example.org/x?y=1&amp;z=2">t</a>"#,
                &["https://example.org/x?y=1&z=2"],
            ),
            (
                br#"<a href="https://example.org/x?y=&#99999999999;">t</a>"#,
                &[],
            ),
            (br#"<a href="https://example.org/x?y=&#xD800;">t</a>"#, &[]),
        ];
        for (html, expected) in cases {
            let (urls, total) = extract_links(html, BASE, "example.com");
            assert_eq!(urls, *expected, "html {:?}", String::from_utf8_lossy(html));
            assert_eq!(total, expected.len() as u64);
        }
        let long = [
            b"<a href=\"https://example.org/x?y=&#".as_slice(),
            &[b'9'; 4301],
            b";\">t</a>",
        ]
        .concat();
        assert_eq!(
            extract_links(&long, BASE, "example.com").0,
            Vec::<String>::new()
        );
        let arabic = "<a href=\"https://example.org/x?y=&#٦٥;z\">t</a>".as_bytes();
        assert_eq!(
            extract_links(arabic, BASE, "example.com").0,
            vec!["https://example.org/x?y=&"]
        );
    }
}
