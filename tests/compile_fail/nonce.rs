const POLICY: &str = const_csp::csp! { script_src: [nonce("abc")] };

fn main() {
    let _ = POLICY;
}
