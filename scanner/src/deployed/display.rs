//! Text that came from the network is untrusted: it is printed in a terminal and published in tables.

const YOCTO_PER_NEAR: u128 = 10u128.pow(24);

/// Characters that are not control characters but still change how text is laid out or read: zero-width and
/// directional marks and overrides (which can make a line read differently from what it says), joiners, the
/// word joiner and the byte order mark, and the line and paragraph separators.
fn is_deceptive(c: char) -> bool {
    matches!(c,
        '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

/// `text` with control characters (terminal escapes, newlines) and invisible or direction-changing characters
/// replaced by `?`, and cut to `max_chars`.
pub(crate) fn clean(text: &str, max_chars: usize) -> String {
    let mut out: String =
        text.chars().take(max_chars).map(|c| if c.is_control() || is_deceptive(c) { '?' } else { c }).collect();
    if text.chars().nth(max_chars).is_some() {
        out.push('…');
    }
    out
}

/// The first `max` items joined with commas, then the number left out: `a, b, c (and 2 more)`.
pub(crate) fn list<S: AsRef<str>>(items: &[S], max: usize) -> String {
    let shown: Vec<String> = items.iter().take(max).map(|item| clean(item.as_ref(), 80)).collect();
    match items.len().saturating_sub(max) {
        0 => shown.join(", "),
        more => format!("{} (and {more} more)", shown.join(", ")),
    }
}

/// A yoctoNEAR amount as NEAR with four decimals, truncated: `1.5 NEAR` is `1.5000 NEAR`.
pub(crate) fn near(yocto: u128) -> String {
    let whole = yocto / YOCTO_PER_NEAR;
    let ten_thousandths = (yocto % YOCTO_PER_NEAR) / (YOCTO_PER_NEAR / 10_000);
    format!("{whole}.{ten_thousandths:04} NEAR")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_cannot_reach_the_terminal() {
        assert_eq!(clean("a\u{1b}[31mred\nline\r", 100), "a?[31mred?line?");
    }

    #[test]
    fn invisible_and_direction_changing_characters_cannot_disguise_text() {
        let hostile = "a\u{200B}b\u{200F}c\u{202E}d\u{2060}e\u{2069}f\u{061C}g\u{FEFF}h\u{2028}i";
        assert_eq!(clean(hostile, 100), "a?b?c?d?e?f?g?h?i");
        // Visible neighbours of the ranges stay.
        assert_eq!(clean("\u{2010}\u{2030}\u{205F}\u{00E9}", 100), "\u{2010}\u{2030}\u{205F}\u{00E9}");
    }

    #[test]
    fn long_text_is_cut_with_an_ellipsis() {
        assert_eq!(clean("abcdef", 3), "abc…");
        assert_eq!(clean("abc", 3), "abc");
    }

    #[test]
    fn lists_are_capped_and_say_how_many_were_left_out() {
        assert_eq!(list(&["a", "b"], 3), "a, b");
        assert_eq!(list(&["a", "b", "c", "d", "e"], 3), "a, b, c (and 2 more)");
    }

    #[test]
    fn near_amounts_are_truncated_to_four_decimals() {
        assert_eq!(near(0), "0.0000 NEAR");
        assert_eq!(near(1_500_000_000_000_000_000_000_000), "1.5000 NEAR");
        assert_eq!(near(36_678_067_749_681_231_043_963_243_662_126), "36678067.7496 NEAR");
        assert_eq!(near(u128::MAX), "340282366920938.4634 NEAR");
    }
}
