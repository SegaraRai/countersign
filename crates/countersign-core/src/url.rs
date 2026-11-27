//! Checks on configured URLs. countersign assumes no particular network, so
//! everything it talks to or links to is HTTPS, except on this machine.

use std::net::IpAddr;

/// An `http://` URL on this machine (`localhost`, `127.0.0.1`, `[::1]`),
/// which browsers and clients treat as secure.
pub fn is_local_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains(['@', '\\']) {
        return false;
    }
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((addr, "")) => (addr, None),
            Some((addr, tail)) => match tail.strip_prefix(':') {
                Some(p) => (addr, Some(p)),
                None => return false,
            },
            None => return false,
        },
        None => match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        },
    };
    if port.is_some_and(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    host.eq_ignore_ascii_case("localhost") || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// An `https://` URL, or an `http://` one on this machine.
pub fn is_secure(url: &str) -> bool {
    url.starts_with("https://") || is_local_http(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_or_this_machine() {
        for ok in ["https://cs.example.test", "http://localhost:8080", "http://127.0.0.1", "http://[::1]:9/x"] {
            assert!(is_secure(ok), "{ok}");
        }
        for bad in [
            "http://cs.example.test",
            "http://localhost.example.test",
            "http://localhost@evil.test",
            "http://localhost:pass@evil.test",
            "http://127.0.0.1:pass@evil.test",
            "http://[::1]@evil.test",
            "http://[::1]evil.test",
            "http://localhost\\@evil.test",
            "http://127.0.0.1:notaport",
            "http://10.0.0.1",
            "localhost",
            "",
        ] {
            assert!(!is_secure(bad), "{bad}");
        }
    }
}
