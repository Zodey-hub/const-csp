const POLICY: &str = const_csp::csp! { script_src: [sha256("abc=")] };

fn main() {
    let _ = POLICY;
}
