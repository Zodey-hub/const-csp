//! Every directive and value form of the `csp!` macro, compared with the expected header value.

use const_csp::csp;

#[test]
fn single_directive_has_no_separator() {
    const POLICY: &str = csp! { object_src: [none] };

    assert_eq!(POLICY, "object-src 'none'");
}

#[test]
fn trailing_commas_are_allowed() {
    const POLICY: &str = csp! { img_src: [self, data,], upgrade_insecure_requests, };

    assert_eq!(POLICY, "img-src 'self' data:; upgrade-insecure-requests");
}

#[test]
fn empty_source_list_is_allowed() {
    const POLICY: &str = csp! { default_src: [] };

    assert_eq!(POLICY, "default-src");
}

#[test]
fn source_list_directives() {
    const POLICY: &str = csp! {
        child_src: [self], connect_src: [self], default_src: [self], fenced_frame_src: [self],
        font_src: [self], frame_src: [self], img_src: [self], manifest_src: [self], media_src: [self],
        object_src: [self], script_src: [self], script_src_attr: [self], script_src_elem: [self],
        style_src: [self], style_src_attr: [self], style_src_elem: [self], worker_src: [self],
        base_uri: [self], form_action: [self], frame_ancestors: [self],
    };

    assert_eq!(
        POLICY,
        "child-src 'self'; connect-src 'self'; default-src 'self'; fenced-frame-src 'self'; \
         font-src 'self'; frame-src 'self'; img-src 'self'; manifest-src 'self'; media-src 'self'; \
         object-src 'self'; script-src 'self'; script-src-attr 'self'; script-src-elem 'self'; \
         style-src 'self'; style-src-attr 'self'; style-src-elem 'self'; worker-src 'self'; \
         base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
    );
}

#[test]
fn keyword_sources() {
    const POLICY: &str = csp! {
        script_src: [
            self, none, unsafe_inline, unsafe_eval, unsafe_hashes, strict_dynamic, report_sample,
            wasm_unsafe_eval, inline_speculation_rules, *,
        ],
    };

    assert_eq!(
        POLICY,
        "script-src 'self' 'none' 'unsafe-inline' 'unsafe-eval' 'unsafe-hashes' 'strict-dynamic' \
         'report-sample' 'wasm-unsafe-eval' 'inline-speculation-rules' *"
    );
}

#[test]
fn scheme_sources() {
    const POLICY: &str = csp! {
        connect_src: [http, https, ws, wss, data, blob, mediastream, filesystem],
    };

    assert_eq!(
        POLICY,
        "connect-src http: https: ws: wss: data: blob: mediastream: filesystem:"
    );
}

#[test]
fn host_and_hash_sources() {
    const POLICY: &str = csp! {
        script_src: [
            "https://cdn.example.com",
            "*.example.com",
            sha256("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="),
            sha384("OLBgp1GsljhM2TJ-sbHjaiH9txEUvgdDTAzHv2P24donTt6_529l-9Ua0vFImLlb"),
            sha512("z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg_SpIdNs6c5H0NE8XYXysP-DGNKHfuwvY7kxvUdBeoGlODJ6-SfaPg=="),
        ],
    };

    assert_eq!(
        POLICY,
        "script-src https://cdn.example.com *.example.com \
         'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' \
         'sha384-OLBgp1GsljhM2TJ-sbHjaiH9txEUvgdDTAzHv2P24donTt6_529l-9Ua0vFImLlb' \
         'sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg_SpIdNs6c5H0NE8XYXysP-DGNKHfuwvY7kxvUdBeoGlODJ6-SfaPg=='"
    );
}

#[test]
fn sandbox() {
    const EMPTY: &str = csp! { sandbox };
    const FLAGS: &str = csp! {
        sandbox: [
            allow_downloads, allow_forms, allow_modals, allow_orientation_lock, allow_pointer_lock,
            allow_popups, allow_popups_to_escape_sandbox, allow_presentation, allow_same_origin,
            allow_scripts, allow_storage_access_by_user_activation, allow_top_navigation,
            allow_top_navigation_by_user_activation, allow_top_navigation_to_custom_protocols,
        ],
    };

    assert_eq!(EMPTY, "sandbox");
    assert_eq!(
        FLAGS,
        "sandbox allow-downloads allow-forms allow-modals allow-orientation-lock allow-pointer-lock \
         allow-popups allow-popups-to-escape-sandbox allow-presentation allow-same-origin \
         allow-scripts allow-storage-access-by-user-activation allow-top-navigation \
         allow-top-navigation-by-user-activation allow-top-navigation-to-custom-protocols"
    );
}

#[test]
fn reporting() {
    const POLICY: &str = csp! {
        report_to: ["csp-endpoint"],
        report_uri: ["https://a.example.com/csp", "/csp-report"],
    };

    assert_eq!(
        POLICY,
        "report-to csp-endpoint; report-uri https://a.example.com/csp /csp-report"
    );
}

#[test]
fn trusted_types_and_other_directives() {
    const POLICY: &str = csp! {
        require_trusted_types_for: [script],
        trusted_types: ["default", "dompurify", allow_duplicates],
        trusted_types,
        trusted_types: [none],
        trusted_types: [*],
        upgrade_insecure_requests,
        webrtc: [allow],
        webrtc: [block],
    };

    assert_eq!(
        POLICY,
        "require-trusted-types-for 'script'; trusted-types default dompurify 'allow-duplicates'; \
         trusted-types; trusted-types 'none'; trusted-types *; upgrade-insecure-requests; \
         webrtc 'allow'; webrtc 'block'"
    );
}

#[test]
fn usable_outside_const_items() {
    let policy = csp! { default_src: [self] };

    assert_eq!(policy, "default-src 'self'");
}
