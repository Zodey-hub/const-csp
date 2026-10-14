const POLICY: &str = const_csp::csp! { sandbox: [allow_script] };

fn main() {
    let _ = POLICY;
}
