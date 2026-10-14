//! Sources of the source-list directives (`script-src`, `img-src`, `frame-ancestors`, ...).

/// Expands one source to a string literal.
///
/// Nonce sources are deliberately missing: a nonce must be unpredictable and different on every response, so a nonce fixed at compile time would give no protection.
#[doc(hidden)]
#[macro_export]
macro_rules! __csp_source {
    // keywords
    (self) => { "'self'" };
    (none) => { "'none'" };
    (unsafe_inline) => { "'unsafe-inline'" };
    (unsafe_eval) => { "'unsafe-eval'" };
    (unsafe_hashes) => { "'unsafe-hashes'" };
    (strict_dynamic) => { "'strict-dynamic'" };
    (report_sample) => { "'report-sample'" };
    (wasm_unsafe_eval) => { "'wasm-unsafe-eval'" };
    (inline_speculation_rules) => { "'inline-speculation-rules'" };
    (*) => { "*" };

    // schemes
    (http) => { "http:" };
    (https) => { "https:" };
    (ws) => { "ws:" };
    (wss) => { "wss:" };
    (data) => { "data:" };
    (blob) => { "blob:" };
    (mediastream) => { "mediastream:" };
    (filesystem) => { "filesystem:" };

    // hashes of inline scripts and styles, base64 encoded
    (sha256($hash:literal)) => { concat!("'sha256-", $hash, "'") };
    (sha384($hash:literal)) => { concat!("'sha384-", $hash, "'") };
    (sha512($hash:literal)) => { concat!("'sha512-", $hash, "'") };

    // host and scheme sources, e.g. "https://cdn.example.com", "*.example.com", "custom-scheme:"
    ($host:literal) => { $host };

    ($($other:tt)*) => {
        compile_error!(concat!(
            "unknown CSP source `", stringify!($($other)*),
            "`: use a keyword (self, none, unsafe_inline, ...), a scheme (https, data, blob, ...), \
             sha256(\"...\") or a host string"
        ))
    };
}
