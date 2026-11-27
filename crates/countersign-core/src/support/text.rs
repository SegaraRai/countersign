//! Showing untrusted text to people without letting it hide anything.
//!
//! Requesters (and backends) choose commands, reasons and names. Besides
//! control characters, Unicode has characters that render as nothing or
//! reorder the text around them (bidirectional overrides), so a command could
//! look different from what runs. Everything shown to approvers goes through
//! [`escape`] or [`is_hidden`].

/// Characters that are invisible or change how surrounding text is displayed:
/// control characters, bidirectional controls, zero-width characters,
/// variation selectors, tag characters and blank-looking fillers.
#[must_use]
pub fn is_hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{17B4}'
                | '\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E007F}'
                | '\u{E0100}'..='\u{E01EF}'
        )
}

/// `s` with every [hidden](is_hidden) character written out as an escape
/// (`\n`, `\u{202e}`), so what is shown is all there is.
#[must_use]
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_hidden(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// Like [`escape`], but line breaks are kept: for multi-line text such as a
/// reason or a question. Tabs become spaces.
#[must_use]
pub fn escape_lines(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push('\n'),
            '\t' => out.push(' '),
            '\r' => {}
            c if is_hidden(c) => out.extend(c.escape_default()),
            c => out.push(c),
        }
    }
    out
}

/// Arguments joined as a POSIX shell would read them back, so the line can
/// be copied and means the same: plain words as they are, others in single
/// quotes, and arguments with [hidden](is_hidden) characters in `$'...'`
/// with those characters escaped. Two different argument lists never give
/// the same line.
#[must_use]
pub fn shell_join(args: &[String]) -> String {
    args.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ")
}

/// One argument, quoted for a POSIX shell where needed (see [`shell_join`]).
#[must_use]
pub fn shell_quote(a: &str) -> String {
    use std::fmt::Write as _;
    let plain = |b: u8| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b);
    if !a.is_empty() && a.bytes().all(plain) {
        return a.to_owned();
    }
    if !a.chars().any(is_hidden) {
        return format!("'{}'", a.replace('\'', r"'\''"));
    }
    let mut out = String::from("$'");
    for c in a.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '\'' => out.push_str(r"\'"),
            '\n' => out.push_str(r"\n"),
            '\t' => out.push_str(r"\t"),
            '\r' => out.push_str(r"\r"),
            '\u{1b}' => out.push_str(r"\e"),
            c if is_hidden(c) && u32::from(c) <= 0xFFFF => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c if is_hidden(c) => {
                let _ = write!(out, "\\U{:08X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn join(s: &[&str]) -> String {
        shell_join(&s.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn shell_lines_read_back_the_same() {
        assert_eq!(join(&["sudo", "-u", "postgres", "--", "psql"]), "sudo -u postgres -- psql");
        assert_eq!(join(&["psql", "-c", "DROP TABLE x"]), "psql -c 'DROP TABLE x'");
        assert_eq!(join(&["echo", "it's", ""]), r"echo 'it'\''s' ''");
        assert_eq!(join(&["echo", "ログ"]), "echo 'ログ'");
        assert_eq!(join(&["echo", "\u{202e}/ fr- mr"]), r"echo $'\u202E/ fr- mr'");
        assert_eq!(join(&["printf", "a\nb'\\"]), r"printf $'a\nb\'\\'");
        assert_eq!(join(&["x\u{E0041}"]), r"$'x\U000E0041'");
        assert_ne!(join(&["a b"]), join(&["a", "b"]));
    }

    #[test]
    fn multi_line_text_keeps_its_lines() {
        assert_eq!(escape_lines("a\r\nb\tc\u{200b}"), "a\nb c\\u{200b}");
    }

    #[test]
    fn hidden_characters_are_written_out() {
        assert_eq!(escape("id"), "id");
        assert_eq!(escape("a\nb\u{1b}[2J"), "a\\nb\\u{1b}[2J");
        // "rm -rf /" shown reversed by a right-to-left override.
        assert_eq!(escape("echo \u{202e}/ fr- mr"), "echo \\u{202e}/ fr- mr");
        assert_eq!(escape("i\u{200b}d"), "i\\u{200b}d");
        assert_eq!(escape("x\u{E0041}"), "x\\u{e0041}");
        // Ordinary non-ASCII text is left alone.
        assert_eq!(escape("café ログ"), "café ログ");
    }
}
