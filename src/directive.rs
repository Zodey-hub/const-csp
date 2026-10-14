//! Directive names and the kind of value list each directive accepts.

/// Expands one directive with its values to a string literal (without the `"; "` separator).
#[doc(hidden)]
#[macro_export]
macro_rules! __csp_directive {
    // fetch directives
    (child_src: [$($sources:tt)*]) => { $crate::__csp_source_directive!("child-src", $($sources)*) };
    (connect_src: [$($sources:tt)*]) => { $crate::__csp_source_directive!("connect-src", $($sources)*) };
    (default_src: [$($sources:tt)*]) => { $crate::__csp_source_directive!("default-src", $($sources)*) };
    (fenced_frame_src: [$($sources:tt)*]) => { $crate::__csp_source_directive!("fenced-frame-src", $($sources)*) };
    (font_src: [$($sources:tt)*]) => { $crate::__csp_source_directive!("font-src", $($sources)*) };
    (frame_src: [$($sources:tt)*]) => { $crate::__csp_source_directive!("frame-src", $($sources)*) };
    (img_src: [$($sources:tt)*]) => { $crate::__csp_source_directive!("img-src", $($sources)*) };
    (manifest_src: [$($sources:tt)*]) => { $crate::__csp_source_directive!("manifest-src", $($sources)*) };
    (media_src: [$($sources:tt)*]) => { $crate::__csp_source_directive!("media-src", $($sources)*) };
    (object_src: [$($sources:tt)*]) => { $crate::__csp_source_directive!("object-src", $($sources)*) };
    (script_src: [$($sources:tt)*]) => { $crate::__csp_source_directive!("script-src", $($sources)*) };
    (script_src_attr: [$($sources:tt)*]) => { $crate::__csp_source_directive!("script-src-attr", $($sources)*) };
    (script_src_elem: [$($sources:tt)*]) => { $crate::__csp_source_directive!("script-src-elem", $($sources)*) };
    (style_src: [$($sources:tt)*]) => { $crate::__csp_source_directive!("style-src", $($sources)*) };
    (style_src_attr: [$($sources:tt)*]) => { $crate::__csp_source_directive!("style-src-attr", $($sources)*) };
    (style_src_elem: [$($sources:tt)*]) => { $crate::__csp_source_directive!("style-src-elem", $($sources)*) };
    (worker_src: [$($sources:tt)*]) => { $crate::__csp_source_directive!("worker-src", $($sources)*) };

    // document directives
    (base_uri: [$($sources:tt)*]) => { $crate::__csp_source_directive!("base-uri", $($sources)*) };
    (sandbox) => { "sandbox" };
    (sandbox: [$($flags:ident),*]) => { concat!("sandbox" $(, " ", $crate::__csp_sandbox_flag!($flags))*) };

    // navigation directives
    (form_action: [$($sources:tt)*]) => { $crate::__csp_source_directive!("form-action", $($sources)*) };
    (frame_ancestors: [$($sources:tt)*]) => { $crate::__csp_source_directive!("frame-ancestors", $($sources)*) };

    // reporting directives
    (report_to: [$endpoint:literal]) => { concat!("report-to ", $endpoint) };
    (report_uri: [$($uris:literal),+]) => { concat!("report-uri" $(, " ", $uris)+) };

    // other directives
    (require_trusted_types_for: [script]) => { "require-trusted-types-for 'script'" };
    (trusted_types) => { "trusted-types" };
    (trusted_types: [$($policies:tt),*]) => { concat!("trusted-types" $(, " ", $crate::__csp_trusted_types_value!($policies))*) };
    (upgrade_insecure_requests) => { "upgrade-insecure-requests" };
    (webrtc: [allow]) => { "webrtc 'allow'" };
    (webrtc: [block]) => { "webrtc 'block'" };

    ($($other:tt)*) => {
        compile_error!(concat!(
            "invalid CSP directive `", stringify!($($other)*),
            "`: unknown directive name, or a value list this directive does not accept"
        ))
    };
}

/// A directive whose value is a source list, e.g. `script-src 'self' https://cdn.example.com`.
#[doc(hidden)]
#[macro_export]
macro_rules! __csp_source_directive {
    ($name:literal, $($source:tt $(($argument:literal))?),*) => {
        concat!($name $(, " ", $crate::__csp_source!($source $(($argument))?))*)
    };
}

/// A flag of the `sandbox` directive.
#[doc(hidden)]
#[macro_export]
macro_rules! __csp_sandbox_flag {
    (allow_downloads) => {
        "allow-downloads"
    };
    (allow_forms) => {
        "allow-forms"
    };
    (allow_modals) => {
        "allow-modals"
    };
    (allow_orientation_lock) => {
        "allow-orientation-lock"
    };
    (allow_pointer_lock) => {
        "allow-pointer-lock"
    };
    (allow_popups) => {
        "allow-popups"
    };
    (allow_popups_to_escape_sandbox) => {
        "allow-popups-to-escape-sandbox"
    };
    (allow_presentation) => {
        "allow-presentation"
    };
    (allow_same_origin) => {
        "allow-same-origin"
    };
    (allow_scripts) => {
        "allow-scripts"
    };
    (allow_storage_access_by_user_activation) => {
        "allow-storage-access-by-user-activation"
    };
    (allow_top_navigation) => {
        "allow-top-navigation"
    };
    (allow_top_navigation_by_user_activation) => {
        "allow-top-navigation-by-user-activation"
    };
    (allow_top_navigation_to_custom_protocols) => {
        "allow-top-navigation-to-custom-protocols"
    };
    ($other:tt) => {
        compile_error!(concat!(
            "unknown CSP sandbox flag `",
            stringify!($other),
            "`"
        ))
    };
}

/// A value of the `trusted-types` directive: a policy name or a keyword.
#[doc(hidden)]
#[macro_export]
macro_rules! __csp_trusted_types_value {
    (none) => {
        "'none'"
    };
    (allow_duplicates) => {
        "'allow-duplicates'"
    };
    (*) => {
        "*"
    };
    ($policy:literal) => {
        $policy
    };
    ($other:tt) => {
        compile_error!(concat!(
            "invalid trusted-types value `",
            stringify!($other),
            "`: use none, allow_duplicates, * or a policy name string"
        ))
    };
}
