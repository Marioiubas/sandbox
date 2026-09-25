//! The GraphQL lexer (GraphQL spec, "Appendix: Grammar Summary", lexical
//! tokens), stricter than the spec where a difference could let the broker
//! and the server read a document differently:
//!
//! - outside strings only ASCII tokens, and the ignored tokens (BOM, space,
//!   tab, line terminators, commas, comments);
//! - comments may hold printable ASCII and tab only (no NUL, no Unicode line
//!   separators that another lexer might end a comment on);
//! - no control characters in strings; escapes `\uXXXX` only (with
//!   surrogate pairs), not the newer `\u{…}` form;
//! - block strings are kept raw: the adapter never reads a value from one.

/// One lexical token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tok<'a> {
    /// One of `! $ & ( ) : = @ [ ] { | }`.
    Punct(u8),
    /// `...`
    Spread,
    Name(&'a str),
    Int(&'a str),
    Float(&'a str),
    /// A string value, escapes decoded.
    Str(String),
    /// A block string, raw (between the quotes, `\"""` not undone).
    Block(&'a str),
}

/// Most tokens in one document (bounds work on hostile input).
pub const MAX_TOKENS: usize = 100_000;

pub fn tokens(src: &str) -> Result<Vec<Tok<'_>>, &'static str> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if out.len() > MAX_TOKENS {
            return Err("too many tokens");
        }
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\n' | b'\r' | b',' => i += 1,
            0xEF if b[i..].starts_with(&[0xEF, 0xBB, 0xBF]) => i += 3,
            b'#' => {
                i += 1;
                while i < b.len() && b[i] != b'\n' && b[i] != b'\r' {
                    if !(b[i] == b'\t' || (0x20..0x7F).contains(&b[i])) {
                        return Err("comment holds a control or non-ASCII character");
                    }
                    i += 1;
                }
            }
            b'!' | b'$' | b'&' | b'(' | b')' | b':' | b'=' | b'@' | b'[' | b']' | b'{' | b'|' | b'}' => {
                out.push(Tok::Punct(c));
                i += 1;
            }
            b'.' => {
                if b[i..].starts_with(b"...") {
                    out.push(Tok::Spread);
                    i += 3;
                } else {
                    return Err("stray '.'");
                }
            }
            b'_' | b'A'..=b'Z' | b'a'..=b'z' => {
                let s = i;
                while i < b.len() && name_continue(b[i]) {
                    i += 1;
                }
                out.push(Tok::Name(&src[s..i]));
            }
            b'-' | b'0'..=b'9' => {
                let (t, n) = number(&src[i..])?;
                out.push(t);
                i += n;
            }
            b'"' if b[i..].starts_with(b"\"\"\"") => {
                let (t, n) = block(&src[i..])?;
                out.push(t);
                i += n;
            }
            b'"' => {
                let (t, n) = string(&src[i..])?;
                out.push(t);
                i += n;
            }
            _ => return Err("unexpected character"),
        }
    }
    Ok(out)
}

fn name_continue(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

fn digits(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    i
}

/// IntValue or FloatValue, with the spec's lookahead restriction: no `.` or
/// name start directly after a number (`1.`, `0x1`, `1e` are errors).
fn number(s: &str) -> Result<(Tok<'_>, usize), &'static str> {
    let b = s.as_bytes();
    let mut i = usize::from(b[0] == b'-');
    let start = i;
    i = digits(b, i);
    if i == start {
        return Err("'-' without digits");
    }
    if b[start] == b'0' && i - start > 1 {
        return Err("leading zero");
    }
    let mut float = false;
    if i < b.len() && b[i] == b'.' {
        let f = digits(b, i + 1);
        if f == i + 1 {
            return Err("'.' without digits");
        }
        i = f;
        float = true;
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        let mut e = i + 1;
        if e < b.len() && (b[e] == b'+' || b[e] == b'-') {
            e += 1;
        }
        let d = digits(b, e);
        if d == e {
            return Err("exponent without digits");
        }
        i = d;
        float = true;
    }
    if i < b.len() && (b[i] == b'.' || b[i] == b'_' || b[i].is_ascii_alphabetic()) {
        return Err("number followed by a name or '.'");
    }
    Ok((if float { Tok::Float(&s[..i]) } else { Tok::Int(&s[..i]) }, i))
}

fn hex4(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None;
    }
    let s = std::str::from_utf8(&b[..4]).ok()?;
    if !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(s, 16).ok()
}

/// A `"…"` string: returns the decoded value and the bytes consumed.
fn string(s: &str) -> Result<(Tok<'static>, usize), &'static str> {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 1;
    loop {
        let Some(&c) = b.get(i) else { return Err("unterminated string") };
        match c {
            b'"' => return Ok((Tok::Str(out), i + 1)),
            b'\\' => {
                let e = *b.get(i + 1).ok_or("unterminated escape")?;
                i += 2;
                out.push(match e {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{8}',
                    b'f' => '\u{c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    b'u' => {
                        let hi = hex4(&b[i..]).ok_or("bad \\u escape")?;
                        i += 4;
                        let cp = if (0xD800..0xDC00).contains(&hi) {
                            if !b[i..].starts_with(b"\\u") {
                                return Err("lone surrogate");
                            }
                            let lo = hex4(&b[i + 2..]).ok_or("bad \\u escape")?;
                            if !(0xDC00..0xE000).contains(&lo) {
                                return Err("lone surrogate");
                            }
                            i += 6;
                            0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                        } else {
                            hi
                        };
                        char::from_u32(cp).ok_or("lone surrogate")?
                    }
                    _ => return Err("unknown escape"),
                });
            }
            0x00..=0x1F | 0x7F => return Err("control character in string"),
            _ => {
                // Copy one UTF-8 scalar (the source is a &str).
                let ch = s[i..].chars().next().ok_or("bad UTF-8")?;
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
}

/// A `"""…"""` block string, kept raw.
fn block(s: &str) -> Result<(Tok<'_>, usize), &'static str> {
    let b = s.as_bytes();
    let mut i = 3;
    loop {
        if i >= b.len() {
            return Err("unterminated block string");
        }
        if b[i..].starts_with(b"\\\"\"\"") {
            i += 4;
        } else if b[i..].starts_with(b"\"\"\"") {
            return Ok((Tok::Block(&s[3..i]), i + 3));
        } else if (b[i] < 0x20 && !matches!(b[i], b'\t' | b'\n' | b'\r')) || b[i] == 0x7F {
            return Err("control character in block string");
        } else {
            i += 1;
        }
    }
}
