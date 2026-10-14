# const-csp

Typed `Content-Security-Policy` header values, built at compile time.

```rust
const POLICY: &str = const_csp::csp! {
    default_src: [self],
    script_src: [self, "https://cdn.example.com"],
    style_src: [self, unsafe_inline],
    img_src: [self, data, blob],
    object_src: [none],
    frame_ancestors: [none],
    upgrade_insecure_requests,
};

assert_eq!(
    POLICY,
    "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; \
     img-src 'self' data: blob:; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests"
);
```

- **Typed:** directive names and keywords are identifiers, so `img_scr` or `unsafe_inlien` is a compile error,
  not a policy that the browser silently ignores.
- **Compile time:** the result is a `&'static str`, ready for `HeaderValue::from_static` or any other header API;
  nothing is allocated or joined at runtime.
- **Checked strings:** hosts, schemes and other free-form values are string literals, checked at compile time. They
  may not contain whitespace, quotes, `;` or `,`, so a value cannot add a directive or a policy of its own.
- **No dependencies**, `#![no_std]`, plain `macro_rules!`.

## Syntax

Each directive is a name, optionally followed by `: [values]`, separated by commas. The directives are emitted in the
order they are written.

| Kind               | Directives                                                                                                                                                                                                                                                                                             | Values                                                        |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| Source list        | `child_src`, `connect_src`, `default_src`, `fenced_frame_src`, `font_src`, `frame_src`, `img_src`, `manifest_src`, `media_src`, `object_src`, `script_src`, `script_src_attr`, `script_src_elem`, `style_src`, `style_src_attr`, `style_src_elem`, `worker_src`, `base_uri`, `form_action`, `frame_ancestors` | sources (below)                                               |
| Sandbox            | `sandbox`, `sandbox: [...]`                                                                                                                                                                                                                                                                            | `allow_forms`, `allow_scripts`, `allow_same_origin`, ... |
| Reporting          | `report_to: ["endpoint"]`, `report_uri: ["https://...", ...]`                                                                                                                                                                                                                                          | strings                                                       |
| Trusted Types      | `require_trusted_types_for: [script]`, `trusted_types`, `trusted_types: [...]`                                                                                                                                                                                                                         | `none`, `allow_duplicates`, `*`, policy name strings          |
| Other              | `upgrade_insecure_requests`, `webrtc: [allow]`, `webrtc: [block]`                                                                                                                                                                                                                                      |                                                               |

Sources:

| Written as                                                                                                                  | Emitted as                                    |
|-----------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|
| `self`, `none`, `unsafe_inline`, `unsafe_eval`, `unsafe_hashes`, `strict_dynamic`, `report_sample`, `wasm_unsafe_eval`, `inline_speculation_rules` | `'self'`, `'none'`, `'unsafe-inline'`, ...    |
| `*`                                                                                                                         | `*`                                           |
| `http`, `https`, `ws`, `wss`, `data`, `blob`, `mediastream`, `filesystem`                                                   | `http:`, `https:`, ...                        |
| `sha256("...")`, `sha384("...")`, `sha512("...")` (base64 digest, length checked)                                            | `'sha256-...'`, ...                           |
| `"https://cdn.example.com"`, `"*.example.com"`, `"custom-scheme:"`                                                          | as written                                    |

Nonce sources are not supported on purpose: a nonce must be unpredictable and different on every response, and a
nonce fixed at compile time gives no protection. If you need nonces, build that directive at runtime.

## What is not checked

The macro checks names and the shape of every value, not the meaning of the whole policy. It does not reject a
directive written twice (browsers use the first one), `none` combined with other sources (browsers ignore `'none'`
then), or a host string that is not a valid host.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
