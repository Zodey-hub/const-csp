//! The misspellings and broken values that `csp!` must reject, with the error they produce.

#[test]
fn compile_fail() {
    trybuild::TestCases::new().compile_fail("tests/compile_fail/*.rs");
}
