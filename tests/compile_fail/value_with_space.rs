const POLICY: &str = const_csp::csp! { img_src: ["https://a.example.com https://b.example.com"] };

fn main() {
    let _ = POLICY;
}
