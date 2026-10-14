const POLICY: &str = const_csp::csp! { img_src: ["https://a.example.com; script-src *"] };

fn main() {
    let _ = POLICY;
}
