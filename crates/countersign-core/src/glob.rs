//! Minimal glob matching: `*` matches any run of characters, `?` matches one.

pub fn matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn cases() {
        assert!(matches("*", ""));
        assert!(matches("*", "anything"));
        assert!(matches("staging-*", "staging-web"));
        assert!(!matches("staging-*", "prod-web"));
        assert!(matches("a?c", "abc"));
        assert!(!matches("a?c", "ac"));
        assert!(matches("*-db-*", "eu-db-1"));
        assert!(!matches("*-db-*", "eu-db"));
        assert!(matches("exact", "exact"));
        assert!(!matches("exact", "exactly"));
        assert!(matches("a*b*c", "aXXbYYc"));
        assert!(!matches("a*b*c", "aXXbYY"));
    }
}
