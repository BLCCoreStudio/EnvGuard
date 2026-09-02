use std::borrow::Cow;
use std::path::Path;

const PRIVATE_KEY_BEGIN_MARKER: &str = "-----BEGIN ";
const PRIVATE_KEY_END_LABEL: &str = "PRIVATE KEY-----";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub rule: &'static str,
    pub message: &'static str,
}

pub fn scan_bytes(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    let display_path = path.to_string_lossy().into_owned();
    let mut findings = Vec::new();

    if let Some((rule, message)) = sensitive_filename(path) {
        findings.push(Finding {
            path: display_path.clone(),
            line: 0,
            rule,
            message,
        });
    }

    let Some(text) = decode_text(bytes) else {
        return findings;
    };

    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let mut matched_specific_rule = false;

        if line.contains(PRIVATE_KEY_BEGIN_MARKER) && line.contains(PRIVATE_KEY_END_LABEL) {
            findings.push(Finding {
                path: display_path.clone(),
                line: line_number,
                rule: "private-key-block",
                message: "private key material appears in file content",
            });
            matched_specific_rule = true;
        }

        for (prefix, min_tail, rule, message) in [
            (
                "github_pat_",
                40,
                "github-token",
                "GitHub token-like value detected",
            ),
            (
                "ghp_",
                30,
                "github-token",
                "GitHub token-like value detected",
            ),
            (
                "xoxb-",
                20,
                "slack-token",
                "Slack token-like value detected",
            ),
            (
                "xoxp-",
                20,
                "slack-token",
                "Slack token-like value detected",
            ),
            (
                "sk-",
                20,
                "api-key-prefix",
                "API key-like value with an sk- prefix detected",
            ),
        ] {
            if contains_prefixed_token(line, prefix, min_tail) {
                findings.push(Finding {
                    path: display_path.clone(),
                    line: line_number,
                    rule,
                    message,
                });
                matched_specific_rule = true;
            }
        }

        if contains_aws_access_key(line) {
            findings.push(Finding {
                path: display_path.clone(),
                line: line_number,
                rule: "aws-access-key",
                message: "AWS access key ID-like value detected",
            });
            matched_specific_rule = true;
        }

        if !matched_specific_rule && looks_like_sensitive_assignment(line) {
            findings.push(Finding {
                path: display_path.clone(),
                line: line_number,
                rule: "sensitive-assignment",
                message: "non-placeholder value assigned to a sensitive-looking variable",
            });
        }
    }

    findings
}

fn decode_text(bytes: &[u8]) -> Option<Cow<'_, str>> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Some(Cow::Borrowed(text));
    }

    decode_utf16(bytes).map(Cow::Owned)
}

fn decode_utf16(bytes: &[u8]) -> Option<String> {
    let (endianness, payload) = if let Some(payload) = bytes.strip_prefix(&[0xff, 0xfe]) {
        (Utf16Endianness::Little, payload)
    } else if let Some(payload) = bytes.strip_prefix(&[0xfe, 0xff]) {
        (Utf16Endianness::Big, payload)
    } else {
        (infer_utf16_endianness(bytes)?, bytes)
    };

    if payload.is_empty() || payload.len() % 2 != 0 {
        return None;
    }

    let units = payload
        .chunks_exact(2)
        .map(|pair| match endianness {
            Utf16Endianness::Little => u16::from_le_bytes([pair[0], pair[1]]),
            Utf16Endianness::Big => u16::from_be_bytes([pair[0], pair[1]]),
        })
        .collect::<Vec<_>>();

    String::from_utf16(&units).ok()
}

#[derive(Clone, Copy)]
enum Utf16Endianness {
    Little,
    Big,
}

fn infer_utf16_endianness(bytes: &[u8]) -> Option<Utf16Endianness> {
    if bytes.len() < 8 || bytes.len() % 2 != 0 {
        return None;
    }

    let pairs = bytes.len() / 2;
    let zero_even = bytes.iter().step_by(2).filter(|byte| **byte == 0).count();
    let zero_odd = bytes
        .iter()
        .skip(1)
        .step_by(2)
        .filter(|byte| **byte == 0)
        .count();
    let threshold = (pairs * 2).div_ceil(3);

    if zero_odd >= threshold && zero_even <= pairs / 4 {
        Some(Utf16Endianness::Little)
    } else if zero_even >= threshold && zero_odd <= pairs / 4 {
        Some(Utf16Endianness::Big)
    } else {
        None
    }
}

fn sensitive_filename(path: &Path) -> Option<(&'static str, &'static str)> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();

    if name == ".env"
        || (name.starts_with(".env.")
            && !name.ends_with(".example")
            && !name.ends_with(".sample")
            && !name.ends_with(".template"))
    {
        return Some((
            "env-file",
            "environment file may contain credentials or other secrets",
        ));
    }

    if matches!(
        name.as_str(),
        "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519"
    ) {
        return Some((
            "ssh-private-key-file",
            "filename matches a common SSH private key",
        ));
    }

    if name.ends_with(".p12") || name.ends_with(".pfx") {
        return Some((
            "key-store-file",
            "PKCS#12 key-store file may contain private keys",
        ));
    }

    None
}

fn contains_prefixed_token(line: &str, prefix: &str, min_tail: usize) -> bool {
    let mut offset = 0;
    while let Some(relative) = line[offset..].find(prefix) {
        let start = offset + relative + prefix.len();
        let tail_len = line[start..]
            .chars()
            .take_while(|character| {
                character.is_ascii_alphanumeric() || *character == '_' || *character == '-'
            })
            .count();

        if tail_len >= min_tail {
            return true;
        }
        offset = start;
    }
    false
}

fn contains_aws_access_key(line: &str) -> bool {
    line.as_bytes().windows(20).any(|window| {
        window.starts_with(b"AKIA")
            && window[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

fn looks_like_sensitive_assignment(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
        return false;
    }

    let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    let Some((key, value)) = trimmed.split_once('=') else {
        return false;
    };

    let key = key.trim();
    let mut key_characters = key.chars();
    let Some(first_character) = key_characters.next() else {
        return false;
    };
    if !(first_character.is_ascii_alphabetic() || first_character == '_')
        || !key_characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return false;
    }

    let key = key.to_ascii_uppercase();
    let sensitive_name = [
        "API_KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PRIVATE_KEY",
        "ACCESS_KEY",
    ]
    .iter()
    .any(|needle| key.contains(needle));

    if !sensitive_name {
        return false;
    }

    let value = value
        .trim()
        .trim_matches(|character| character == '\'' || character == '"');
    if value.len() < 8 {
        return false;
    }

    let upper = value.to_ascii_uppercase();
    if [
        "EXAMPLE",
        "CHANGEME",
        "CHANGE_ME",
        "PLACEHOLDER",
        "REPLACE_ME",
        "YOUR_",
        "DUMMY",
    ]
    .iter()
    .any(|placeholder| upper.contains(placeholder))
    {
        return false;
    }

    if value
        .chars()
        .all(|character| character == '*' || character == 'x' || character == 'X')
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_le_bom(value: &str) -> Vec<u8> {
        let mut bytes = vec![0xff, 0xfe];
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn utf16_be(value: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn flags_dot_env_filename() {
        let findings = scan_bytes(Path::new(".env"), b"APP_MODE=development\n");
        assert!(findings.iter().any(|finding| finding.rule == "env-file"));
    }

    #[test]
    fn allows_env_example_filename() {
        let key = ["API", "_KEY"].concat();
        let value = ["YOUR", "_API_KEY_HERE"].concat();
        let content = format!("{key}={value}\n");
        let findings = scan_bytes(Path::new(".env.example"), content.as_bytes());
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_private_key_material() {
        let begin = ["-----BEGIN OPENSSH", " "].concat();
        let end = ["PRIVATE ", "KEY-----\nabc\n"].concat();
        let content = format!("{begin}{end}");
        let findings = scan_bytes(Path::new("key.pem"), content.as_bytes());
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "private-key-block"));
    }

    #[test]
    fn flags_github_token_prefix() {
        let prefix = ["gh", "p_"].concat();
        let content = format!("VALUE={prefix}{}\n", "a".repeat(36));
        let findings = scan_bytes(Path::new("config.txt"), content.as_bytes());
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "github-token"));
    }

    #[test]
    fn flags_aws_access_key_shape() {
        let prefix = ["AK", "IA"].concat();
        let content = format!("AWS={prefix}{}\n", "A".repeat(16));
        let findings = scan_bytes(Path::new("config.txt"), content.as_bytes());
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "aws-access-key"));
    }

    #[test]
    fn flags_sensitive_assignment() {
        let key = ["DATABASE_", "PASSWORD"].concat();
        let content = format!("{key}=correct-horse-battery-staple\n");
        let findings = scan_bytes(Path::new("settings.conf"), content.as_bytes());
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "sensitive-assignment"));
    }

    #[test]
    fn scans_utf16_le_with_bom() {
        let key = ["SERVICE_", "TOKEN"].concat();
        let content = utf16_le_bom(&format!("MODE=dev\n{key}=a-real-looking-secret-value\n"));
        let findings = scan_bytes(Path::new("settings.conf"), &content);
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "sensitive-assignment" && finding.line == 2));
    }

    #[test]
    fn scans_bomless_utf16_be_when_byte_pattern_is_clear() {
        let prefix = ["gh", "p_"].concat();
        let content = utf16_be(&format!("VALUE={prefix}{}\n", "a".repeat(36)));
        let findings = scan_bytes(Path::new("settings.conf"), &content);
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "github-token"));
    }

    #[test]
    fn ignores_placeholder_assignment() {
        let key = ["API", "_KEY"].concat();
        let value = ["YOUR", "_API_KEY_HERE"].concat();
        let content = format!("{key}={value}\n");
        let findings = scan_bytes(Path::new("settings.example"), content.as_bytes());
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_source_code_declaration() {
        let name = ["SERVICE_", "TOKEN"].concat();
        let content = format!("const {name}: &str = \"synthetic-value-only\";\n");
        let findings = scan_bytes(Path::new("source.rs"), content.as_bytes());
        assert!(findings.is_empty());
    }

    #[test]
    fn reports_line_number() {
        let key = ["SERVICE_", "TOKEN"].concat();
        let content = format!("MODE=dev\n{key}=a-real-looking-secret-value\n");
        let findings = scan_bytes(Path::new("settings.conf"), content.as_bytes());
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn binary_content_is_not_scanned_as_text() {
        let findings = scan_bytes(Path::new("image.bin"), &[0xff, 0x00, b's', b'k', b'-']);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_common_ssh_private_key_filename() {
        let findings = scan_bytes(Path::new(".ssh/id_ed25519"), b"synthetic test content\n");
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "ssh-private-key-file"));
    }

    #[test]
    fn source_does_not_trigger_its_own_rules() {
        let findings = scan_bytes(Path::new("src/lib.rs"), include_bytes!("lib.rs"));
        assert!(findings.is_empty(), "self-scan findings: {findings:?}");
    }
}
