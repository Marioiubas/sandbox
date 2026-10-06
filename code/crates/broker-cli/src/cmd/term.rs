//! Text from the agent or an MCP server on the user's terminal: every
//! control the terminal could act on is escaped (approval views, ADR-037
//! and ADR-047).

/// `s` with C0/DEL (serde_json escapes these inside strings only), C1
/// (e.g. U+009B, CSI), bidi embeddings, overrides and isolates, zero-width
/// and line separators escaped; newlines are kept.
pub fn terminal_safe(s: &str) -> String {
    s.chars()
        .map(|c| match c as u32 {
            0x0a => c.to_string(),
            0x00..=0x1f | 0x7f..=0x9f | 0x061c | 0x200b..=0x200f | 0x2028..=0x202e | 0x2060..=0x2069 | 0xfeff => {
                format!("\\u{{{:04x}}}", c as u32)
            }
            _ => c.to_string(),
        })
        .collect()
}

/// As [`terminal_safe`], with newlines escaped too: for a value shown on
/// one line, which must not be able to start a line of its own.
pub fn one_line(s: &str) -> String {
    terminal_safe(&s.replace('\n', "\\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_are_escaped_and_one_line_values_stay_on_one_line() {
        assert_eq!(terminal_safe("a\u{1b}[31mb\n\u{202e}c\u{9b}"), "a\\u{001b}[31mb\n\\u{202e}c\\u{009b}");
        assert_eq!(one_line("tool a\n  tool b"), "tool a\\n  tool b");
        assert_eq!(one_line("x\r\u{2028}y"), "x\\u{000d}\\u{2028}y");
    }
}
