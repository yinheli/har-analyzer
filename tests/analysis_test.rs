use har_analyzer::analysis;

#[test]
fn analysis_test() {
    let r = analysis::analysis("tests/testsdata/har.har", None);
    assert!(!r.is_err())
}
