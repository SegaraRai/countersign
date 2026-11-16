//! Checks on configured URLs. countersign assumes no particular network, so
//! everything it talks to or links to is HTTPS, except on this machine.

use std::net::IpAddr;

/// An `http://` URL on this machine (`localhost`, `127.0.0.1`, `[::1]`),
/// which browsers and clients treat as secure.
pub fn is_local_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => authority.split(':').next().unwrap_or_default(),
    };
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
        for bad in ["http://cs.example.test", "http://localhost.example.test", "http://10.0.0.1", "localhost", ""] {
            assert!(!is_secure(bad), "{bad}");
        }
    }
}
