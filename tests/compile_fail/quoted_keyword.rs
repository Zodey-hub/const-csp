const POLICY: &str = const_csp::csp! { img_src: ["'self'"] };

fn main() {
    let _ = POLICY;
}
