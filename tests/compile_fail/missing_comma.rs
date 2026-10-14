const POLICY: &str = const_csp::csp! { img_src: [self data] };

fn main() {
    let _ = POLICY;
}
