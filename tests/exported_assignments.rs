use envguard::scan_bytes;
use std::path::Path;

#[test]
fn flags_exported_sensitive_assignment() {
    let content = b"export SERVICE_TOKEN=a-real-looking-secret-value\n";
    let findings = scan_bytes(Path::new("shell.env"), content);

    assert!(
        findings
            .iter()
            .any(|finding| finding.rule == "sensitive-assignment" && finding.line == 1),
        "expected exported secret assignment to be detected: {findings:?}"
    );
}
