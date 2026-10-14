//! Compile time checks of the free-form values, run in `const` items by the `csp!` macro.

/// Checks one value of a directive at compile time; keywords need no check, they are fixed strings.
#[doc(hidden)]
#[macro_export]
macro_rules! __csp_check_value {
    ($value:literal) => {
        const _: () = assert!(
            $crate::__private::is_valid_value($value),
            concat!(
                "invalid CSP value ",
                stringify!($value),
                ": it must be non-empty and must not contain whitespace, quotes, `;` or `,` \
                 (write keywords as names, e.g. self instead of \"'self'\")"
            )
        );
    };
    (sha256($hash:literal)) => {
        const _: () = assert!(
            $crate::__private::is_valid_hash($hash, 44),
            concat!(
                "invalid sha256 hash ",
                stringify!($hash),
                ": expected 44 base64 characters"
            )
        );
    };
    (sha384($hash:literal)) => {
        const _: () = assert!(
            $crate::__private::is_valid_hash($hash, 64),
            concat!(
                "invalid sha384 hash ",
                stringify!($hash),
                ": expected 64 base64 characters"
            )
        );
    };
    (sha512($hash:literal)) => {
        const _: () = assert!(
            $crate::__private::is_valid_hash($hash, 88),
            concat!(
                "invalid sha512 hash ",
                stringify!($hash),
                ": expected 88 base64 characters"
            )
        );
    };
    ($keyword:tt $(($argument:literal))?) => {};
}

/// Returns whether `value` can be written into a directive as a single token.
///
/// A valid value is non-empty and contains only visible ASCII characters except `'`, `"`, `;` and
/// `,`: whitespace would split it into several values, `;` would start a new directive, `,` would
/// start a new policy, and quotes are reserved for keywords.
///
/// # Arguments
///
/// * `value` - A host, scheme, report endpoint or trusted types policy name
///
/// # Returns
///
/// `true` if the value is safe to emit as is
#[must_use]
pub const fn is_valid_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return false;
    }

    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' | b';' | b',' => return false,
            byte if !byte.is_ascii_graphic() => return false,
            _ => {}
        }
        index += 1;
    }
    true
}

/// Returns whether `hash` is a base64 (or base64url) encoded digest of the expected length.
///
/// # Arguments
///
/// * `hash` - The encoded digest, without the `sha256-` prefix and quotes
/// * `expected_length` - The encoded length of the digest (44 for SHA-256, 64 for SHA-384, 88 for SHA-512)
///
/// # Returns
///
/// `true` if the length matches and every character is in the base64 or base64url alphabet
#[must_use]
pub const fn is_valid_hash(hash: &str, expected_length: usize) -> bool {
    let bytes = hash.as_bytes();
    if bytes.len() != expected_length {
        return false;
    }

    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'-' | b'_' | b'=' => {}
            _ => return false,
        }
        index += 1;
    }
    true
}

/// Removes the `"; "` that the `csp!` macro writes before every directive, including the first.
///
/// # Arguments
///
/// * `policy` - The joined directives, each prefixed with `"; "`
///
/// # Returns
///
/// The policy without the leading separator
///
/// # Panics
///
/// Panics (a compile error when called in a `const` item) if `policy` does not start with `"; "`;
/// the `csp!` macro always writes it, since it requires at least one directive.
#[must_use]
pub const fn strip_leading_separator(policy: &str) -> &str {
    match policy.as_bytes() {
        [b';', b' ', rest @ ..] => match core::str::from_utf8(rest) {
            Ok(stripped) => stripped,
            Err(_) => panic!("the CSP policy is not valid UTF-8 after the separator"),
        },
        _ => panic!("the CSP policy does not start with the separator"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_hosts_and_schemes() {
        for value in [
            "https://cdn.example.com",
            "*.example.com",
            "custom-scheme:",
            "example.com:8080/path",
        ] {
            assert!(is_valid_value(value), "{value}");
        }
    }

    #[test]
    fn rejects_values_that_break_the_header() {
        for value in [
            "",
            "a b",
            "a\tb",
            "'self'",
            "\"x\"",
            "a;b",
            "a,b",
            "árvíztűrő.hu",
        ] {
            assert!(!is_valid_value(value), "{value}");
        }
    }

    #[test]
    fn checks_hash_length_and_alphabet() {
        let sha256 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

        assert!(is_valid_hash(sha256, 44));
        assert!(!is_valid_hash(sha256, 64));
        assert!(!is_valid_hash(
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuF!=",
            44
        ));
    }

    #[test]
    fn strips_only_the_leading_separator() {
        assert_eq!(strip_leading_separator("; a; b"), "a; b");
    }
}
