//! Glob matching for tool and server names.
//!
//! Tool patterns are globs rather than regular expressions, for two reasons.
//!
//! The first is that a policy file is read far more often than it is written,
//! usually under time pressure during an incident, and `github.create_*` is
//! unambiguous at a glance in a way that `^github\.create_.*$` is not. Anchoring
//! mistakes in hand-written regexes are a classic source of rules that quietly
//! match more than their author intended.
//!
//! The second is complexity. The matcher below is a well-known linear-time
//! algorithm with a single backtrack point, so a pattern cannot be written that
//! makes matching blow up. Argument values are matched with the `regex` crate,
//! which compiles to a finite automaton and carries the same guarantee, so
//! neither half of the policy language has a pathological input.
//!
//! # Syntax
//!
//! - `*` matches any run of characters, including none
//! - `?` matches exactly one character
//! - everything else matches itself, case-sensitively
//!
//! There is no escape character. A pattern that needs to match a literal `*` in
//! a tool name cannot be written, which has not come up, because tool names are
//! identifiers.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A compiled glob pattern.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub struct Pattern {
    source: String,
    /// Pre-decoded pattern characters. Matching walks characters, not bytes, so
    /// a multi-byte name cannot be split in the middle by `?`.
    chars: Vec<char>,
    /// True when the pattern contains no metacharacters, which lets the common
    /// case skip the matcher entirely.
    literal: bool,
}

impl Pattern {
    /// Compiles a pattern. Compilation cannot fail; every string is a pattern.
    pub fn new(source: impl Into<String>) -> Self {
        let source = source.into();
        let chars: Vec<char> = source.chars().collect();
        let literal = !chars.iter().any(|c| matches!(c, '*' | '?'));
        Self {
            source,
            chars,
            literal,
        }
    }

    /// The pattern as written.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Whether the pattern contains no wildcards.
    pub fn is_literal(&self) -> bool {
        self.literal
    }

    /// Whether the pattern matches `text` in full.
    pub fn matches(&self, text: &str) -> bool {
        if self.literal {
            return self.source == text;
        }

        let pattern = &self.chars;
        let text: Vec<char> = text.chars().collect();

        let mut p = 0usize;
        let mut t = 0usize;
        // Position of the most recent `*`, and where in the text it was
        // matched from. Backtracking rewinds to these and lets the star consume
        // one more character, which is what keeps this linear in practice.
        let mut star: Option<usize> = None;
        let mut star_text = 0usize;

        while t < text.len() {
            if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
                p += 1;
                t += 1;
            } else if p < pattern.len() && pattern[p] == '*' {
                star = Some(p);
                star_text = t;
                p += 1;
            } else if let Some(star_pos) = star {
                p = star_pos + 1;
                star_text += 1;
                t = star_text;
            } else {
                return false;
            }
        }

        // Trailing stars may match the empty remainder.
        while p < pattern.len() && pattern[p] == '*' {
            p += 1;
        }
        p == pattern.len()
    }

    /// Whether this pattern matches every possible name.
    ///
    /// Used by policy validation to warn about rules after a catch-all, which
    /// can never be reached under first-match-wins evaluation.
    pub fn is_catch_all(&self) -> bool {
        !self.chars.is_empty() && self.chars.iter().all(|c| *c == '*')
    }
}

impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pattern({:?})", self.source)
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

impl From<String> for Pattern {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for Pattern {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<Pattern> for String {
    fn from(value: Pattern) -> Self {
        value.source
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[track_caller]
    fn assert_matches(pattern: &str, text: &str) {
        assert!(
            Pattern::new(pattern).matches(text),
            "{pattern:?} should match {text:?}"
        );
    }

    #[track_caller]
    fn assert_no_match(pattern: &str, text: &str) {
        assert!(
            !Pattern::new(pattern).matches(text),
            "{pattern:?} should not match {text:?}"
        );
    }

    #[test]
    fn literal_patterns_match_exactly() {
        assert_matches("fs.read_file", "fs.read_file");
        assert_no_match("fs.read_file", "fs.read_file_2");
        assert_no_match("fs.read_file", "xfs.read_file");
        assert!(Pattern::new("fs.read_file").is_literal());
    }

    #[test]
    fn matching_is_case_sensitive() {
        assert_no_match("fs.Read", "fs.read");
    }

    #[test]
    fn star_matches_any_run_including_empty() {
        assert_matches("fs.*", "fs.read_file");
        assert_matches("fs.*", "fs.");
        assert_matches("*", "anything");
        assert_matches("*", "");
        assert_matches("github.create_*", "github.create_issue");
        assert_no_match("github.create_*", "github.delete_issue");
    }

    #[test]
    fn question_mark_matches_exactly_one_character() {
        assert_matches("fs.?", "fs.a");
        assert_no_match("fs.?", "fs.");
        assert_no_match("fs.?", "fs.ab");
    }

    #[test]
    fn multiple_stars_work() {
        assert_matches("*.create_*", "github.create_issue");
        assert_matches("a*b*c", "abc");
        assert_matches("a*b*c", "axxbyyc");
        assert_no_match("a*b*c", "axxcyyb");
    }

    #[test]
    fn star_backtracks_correctly() {
        // The classic case that a naive greedy matcher gets wrong: the star
        // must give characters back so the literal tail can match.
        assert_matches("*.json", "config.json");
        assert_matches("*abc", "zzabcabc");
        assert_matches("*a*b", "aaab");
        assert_no_match("*.json", "config.json.bak");
    }

    #[test]
    fn patterns_operate_on_characters_not_bytes() {
        // `?` must consume one character, not one byte, or a multi-byte name
        // would match a pattern its author never intended.
        assert_matches("?", "\u{00e9}");
        assert_no_match("??", "\u{00e9}");
        assert_matches("caf?", "caf\u{00e9}");
    }

    #[test]
    fn pathological_patterns_stay_fast() {
        // A backtracking regex engine takes exponential time on this shape.
        // This must return promptly; the test failing means the algorithm was
        // replaced with something that backtracks without bound.
        let pattern = Pattern::new("a*".repeat(24));
        let text = "a".repeat(120);
        let started = std::time::Instant::now();
        assert!(pattern.matches(&text));
        assert!(
            started.elapsed().as_millis() < 500,
            "matching blew up: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn recognises_catch_all_patterns() {
        assert!(Pattern::new("*").is_catch_all());
        assert!(Pattern::new("**").is_catch_all());
        assert!(!Pattern::new("fs.*").is_catch_all());
        assert!(!Pattern::new("").is_catch_all());
    }

    #[test]
    fn round_trips_through_serde_as_a_plain_string() {
        let pattern = Pattern::new("github.*");
        let encoded = serde_json::to_string(&pattern).unwrap();
        assert_eq!(encoded, "\"github.*\"");
        let decoded: Pattern = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, pattern);
        assert!(decoded.matches("github.create_issue"));
    }
}
