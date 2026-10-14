#![doc = include_str!("../README.md")]
#![no_std]

mod directive;
mod source;
mod validate;

#[doc(hidden)]
pub mod __private {
    pub use crate::validate::{is_valid_hash, is_valid_value, strip_leading_separator};
}

/// Builds a `Content-Security-Policy` header value as a `&'static str` at compile time.
///
/// Each directive is a name, optionally followed by `: [values]`. Directive names and keyword
/// values are Rust identifiers (`script_src`, `self`, `unsafe_inline`), so a typo is a compile error
/// instead of a policy that the browser silently ignores. Hosts, schemes and other free-form values
/// are string literals; they are checked at compile time and may not contain whitespace, quotes,
/// `;` or `,`.
///
/// The directives are emitted in the order they are written, separated by `"; "`.
///
/// # Examples
///
/// ```
/// const POLICY: &str = const_csp::csp! {
///     default_src: [self],
///     img_src: [self, data, "https://images.example.com"],
///     object_src: [none],
///     upgrade_insecure_requests,
/// };
///
/// assert_eq!(
///     POLICY,
///     "default-src 'self'; img-src 'self' data: https://images.example.com; \
///      object-src 'none'; upgrade-insecure-requests"
/// );
/// ```
///
/// A misspelled directive or keyword does not compile:
///
/// ```compile_fail
/// const POLICY: &str = const_csp::csp! { img_scr: [self] };
/// ```
///
/// ```compile_fail
/// const POLICY: &str = const_csp::csp! { img_src: [slef] };
/// ```
///
/// A string value that would break the header (or smuggle in another directive) does not compile:
///
/// ```compile_fail
/// const POLICY: &str = const_csp::csp! { img_src: ["https://a.example.com; script-src *"] };
/// ```
#[macro_export]
macro_rules! csp {
    (
        $(
            $directive:ident $(: [$($value:tt $(($argument:literal))?),* $(,)?])?
        ),+ $(,)?
    ) => {{
        $($($($crate::__csp_check_value!($value $(($argument))?);)*)?)+
        const POLICY: &str = concat!(
            $("; ", $crate::__csp_directive!($directive $(: [$($value $(($argument))?),*])?)),+
        );
        const STRIPPED: &str = $crate::__private::strip_leading_separator(POLICY);
        STRIPPED
    }};
}
