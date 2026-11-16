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

#[cfg(test)]
mod tests {
    use super::*;

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
