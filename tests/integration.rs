use leakguard::{Kind, Mask, Match, Redactor};

#[test]
fn email_basic() {
    let s = Redactor::only(&[Kind::Email]);
    assert_eq!(
        s.clean("ping alice@example.com now"),
        "ping [REDACTED:EMAIL] now"
    );
    assert_eq!(s.clean("a.b+tag@sub.example.co.uk"), "[REDACTED:EMAIL]");
}

#[test]
fn email_no_false_positive() {
    let s = Redactor::only(&[Kind::Email]);
    // No TLD -> not an email.
    assert_eq!(
        s.clean("@handle and user@localhost"),
        "@handle and user@localhost"
    );
}

#[test]
fn credit_card_luhn() {
    let s = Redactor::only(&[Kind::CreditCard]);
    // Valid Visa test number, spaced.
    assert_eq!(
        s.clean("pay 4111 1111 1111 1111"),
        "pay [REDACTED:CREDIT_CARD]"
    );
    // Hyphenated.
    assert_eq!(s.clean("4111-1111-1111-1111"), "[REDACTED:CREDIT_CARD]");
    // Fails Luhn -> untouched.
    assert_eq!(s.clean("4111 1111 1111 1112"), "4111 1111 1111 1112");
}

#[test]
fn credit_card_rejects_more_than_19_digits() {
    let s = Redactor::only(&[Kind::CreditCard]);
    // First 19 digits pass Luhn, but the full candidate has 20 digits.
    let long = "41111111111111000060";
    assert_eq!(s.clean(long), long);
    // Also reject long grouped candidates instead of redacting a suffix group.
    let grouped = "4111 1111 1111 1100 0060";
    assert_eq!(s.clean(grouped), grouped);
}

#[test]
fn ipv4_range_checked() {
    let s = Redactor::only(&[Kind::IpV4]);
    assert_eq!(s.clean("from 192.168.0.1!"), "from [REDACTED:IPV4]!");
    // 999 is out of range.
    assert_eq!(s.clean("999.1.1.1"), "999.1.1.1");
    // Version-like string, 5 components, not an IP.
    assert_eq!(s.clean("1.2.3.4.5"), "1.2.3.4.5");
}

#[test]
fn ipv6_forms() {
    let s = Redactor::only(&[Kind::IpV6]);
    assert_eq!(s.clean("addr 2001:db8::1 end"), "addr [REDACTED:IPV6] end");
    assert_eq!(
        s.clean("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        "[REDACTED:IPV6]"
    );
}

#[test]
fn jwt_detected() {
    let s = Redactor::only(&[Kind::Jwt]);
    let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dQw4w9WgXcQ";
    assert_eq!(s.clean(&format!("Bearer {token}")), "Bearer [REDACTED:JWT]");
}

#[test]
fn us_ssn() {
    let s = Redactor::only(&[Kind::UsSsn]);
    assert_eq!(s.clean("ssn 123-45-6789."), "ssn [REDACTED:US_SSN].");
    // Invalid area 000.
    assert_eq!(s.clean("000-45-6789"), "000-45-6789");
}

#[test]
fn mac_address() {
    let s = Redactor::only(&[Kind::MacAddress]);
    assert_eq!(s.clean("mac 00:1A:2B:3C:4D:5E"), "mac [REDACTED:MAC]");
    assert_eq!(s.clean("00-1a-2b-3c-4d-5e"), "[REDACTED:MAC]");
}

#[test]
fn aws_access_key() {
    let s = Redactor::only(&[Kind::AwsAccessKey]);
    assert_eq!(
        s.clean("key=AKIAIOSFODNN7EXAMPLE end"),
        "key=[REDACTED:AWS_ACCESS_KEY] end"
    );
}

#[test]
fn url_credentials() {
    let s = Redactor::only(&[Kind::UrlCredentials]);
    assert_eq!(
        s.clean("clone https://user:secret@github.com/x.git"),
        "clone https://[REDACTED:URL_CREDENTIALS]@github.com/x.git"
    );
    // No password -> left alone.
    assert_eq!(s.clean("https://github.com/x"), "https://github.com/x");
}

#[test]
fn masks() {
    let s = Redactor::only(&[Kind::IpV4]).mask(Mask::fixed("***"));
    assert_eq!(s.clean("ip 10.0.0.1"), "ip ***");

    let s = Redactor::only(&[Kind::CreditCard]).mask(Mask::Partial {
        keep_last: 4,
        ch: '*',
    });
    assert_eq!(s.clean("4111 1111 1111 1111"), "***************1111");

    let s = Redactor::only(&[Kind::Email]).mask(Mask::Char('#'));
    assert_eq!(s.clean("a@b.com"), "#######");

    let replacement = String::from("<hidden>");
    let s = Redactor::only(&[Kind::IpV4]).mask(Mask::fixed(replacement));
    assert_eq!(s.clean("ip 10.0.0.1"), "ip <hidden>");
}

#[test]
fn hash_mask_is_stable() {
    let s = Redactor::only(&[Kind::Email]).mask(Mask::Hash);
    let a = s.clean("a@b.com and a@b.com");
    // Same email hashes to the same token.
    let parts: Vec<&str> = a.split(" and ").collect();
    assert_eq!(parts[0], parts[1]);
    assert!(parts[0].starts_with("[EMAIL#"));
}

#[test]
fn multiple_kinds_no_overlap_corruption() {
    let s = Redactor::new();
    let input = "user alice@example.com logged in from 192.168.1.10 ssn 123-45-6789";
    let cleaned = s.clean(input);
    assert_eq!(
        cleaned,
        "user [REDACTED:EMAIL] logged in from [REDACTED:IPV4] ssn [REDACTED:US_SSN]"
    );
}

#[test]
fn find_returns_byte_offsets_on_boundaries() {
    let s = Redactor::only(&[Kind::Email]);
    let input = "héllo a@b.com"; // multibyte before the match
    let matches = s.find(input);
    assert_eq!(matches.len(), 1);
    // Slicing at returned offsets must be valid UTF-8 (no panic).
    assert_eq!(matches[0].text(input), "a@b.com");
}

#[test]
fn custom_detector() {
    use leakguard::FnDetector;
    let det = FnDetector::new(
        Kind::Custom("TICKET"),
        |input: &str, out: &mut Vec<Match>| {
            let mut from = 0;
            while let Some(i) = input[from..].find("JIRA-") {
                let start = from + i;
                let mut end = start + 5;
                let b = input.as_bytes();
                while end < b.len() && b[end].is_ascii_digit() {
                    end += 1;
                }
                out.push(Match::new(Kind::Custom("TICKET"), start, end));
                from = end;
            }
        },
    );
    let s = Redactor::empty().with_detector(det);
    assert_eq!(
        s.clean("see JIRA-1234 please"),
        "see [REDACTED:TICKET] please"
    );
}

#[test]
fn clean_idempotent_when_nothing_matches() {
    let s = Redactor::new();
    let input = "just a normal sentence, nothing to see.";
    assert_eq!(s.clean(input), input);
    assert!(!s.is_dirty(input));
}

// --- Additional built-in detectors ---

#[test]
fn github_tokens() {
    let s = Redactor::only(&[Kind::GitHubToken]);
    assert_eq!(
        s.clean("ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
        "[REDACTED:GITHUB_TOKEN]"
    );
    assert_eq!(
        s.clean("auth github_pat_11ABCDEFG0abcdefghij_KLMNOPQRSTUVWXYZ1234567890abcdef end"),
        "auth [REDACTED:GITHUB_TOKEN] end"
    );
}

#[test]
fn slack_tokens() {
    let s = Redactor::only(&[Kind::SlackToken]);
    assert_eq!(
        s.clean("xoxb-123456789012-1234567890123-abcdefABCDEF1234567890ab"),
        "[REDACTED:SLACK_TOKEN]"
    );
}

#[test]
fn stripe_keys() {
    let s = Redactor::only(&[Kind::StripeKey]);
    assert_eq!(
        s.clean("key sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH ok"),
        "key [REDACTED:STRIPE_KEY] ok"
    );
    assert_eq!(
        s.clean("pk_test_TYooMQauvdEDq54NiTphI7jx"),
        "[REDACTED:STRIPE_KEY]"
    );
}

#[test]
fn google_api_key() {
    let s = Redactor::only(&[Kind::GoogleApiKey]);
    let key = format!("AIza{}", "a".repeat(35)); // exactly 39 chars
    assert_eq!(s.clean(&format!("k={key}")), "k=[REDACTED:GOOGLE_API_KEY]");
    // One char too short -> no match.
    let short = format!("AIza{}", "a".repeat(34));
    assert_eq!(s.clean(&short), short);
}

#[test]
fn openai_keys() {
    let s = Redactor::only(&[Kind::OpenAiKey]);
    assert_eq!(
        s.clean("openai sk-proj-abcdEFGH1234567890ijklMNOP1234 here"),
        "openai [REDACTED:OPENAI_KEY] here"
    );
    assert_eq!(
        s.clean("sk-abcdEFGH1234567890ijklMNOPqrst1234"),
        "[REDACTED:OPENAI_KEY]"
    );
}

#[test]
fn every_multi_prefix_token_variant_is_detected() {
    for (kind, prefix, body_len) in [
        (Kind::GitHubToken, "github_pat_", 20),
        (Kind::GitHubToken, "ghp_", 30),
        (Kind::GitHubToken, "gho_", 30),
        (Kind::GitHubToken, "ghu_", 30),
        (Kind::GitHubToken, "ghs_", 30),
        (Kind::GitHubToken, "ghr_", 30),
        (Kind::SlackToken, "xoxb-", 10),
        (Kind::SlackToken, "xoxp-", 10),
        (Kind::SlackToken, "xoxa-", 10),
        (Kind::SlackToken, "xoxr-", 10),
        (Kind::SlackToken, "xoxs-", 10),
        (Kind::SlackToken, "xoxo-", 10),
        (Kind::StripeKey, "sk_live_", 10),
        (Kind::StripeKey, "sk_test_", 10),
        (Kind::StripeKey, "rk_live_", 10),
        (Kind::StripeKey, "rk_test_", 10),
        (Kind::StripeKey, "pk_live_", 10),
        (Kind::StripeKey, "pk_test_", 10),
        (Kind::OpenAiKey, "sk-proj-", 20),
        (Kind::OpenAiKey, "sk-", 20),
    ] {
        let secret = format!("{prefix}{}", "a".repeat(body_len));
        let redactor = Redactor::only(core::slice::from_ref(&kind));
        let matches = redactor.find(&secret);
        assert_eq!(matches.len(), 1, "prefix: {prefix}");
        assert_eq!(matches[0].kind, kind, "prefix: {prefix}");
        assert_eq!(matches[0].text(&secret), secret, "prefix: {prefix}");
    }
}

#[test]
fn private_key_block() {
    let s = Redactor::only(&[Kind::PrivateKey]);
    let pem = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc123\n-----END RSA PRIVATE KEY-----\nafter";
    assert_eq!(s.clean(pem), "before\n[REDACTED:PRIVATE_KEY]\nafter");
    // A non-private PEM (certificate) is left alone.
    let cert = "-----BEGIN CERTIFICATE-----\nXYZ\n-----END CERTIFICATE-----";
    assert_eq!(s.clean(cert), cert);
}

#[test]
fn cli_redacts_multiline_private_key_from_stdin() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let pem = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc123\n-----END RSA PRIVATE KEY-----\nafter";
    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    let mut stdin = child.stdin.take().expect("open stdin");
    stdin.write_all(pem.as_bytes()).expect("write pem");
    drop(stdin);

    let output = child.wait_with_output().expect("wait for CLI");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "before\n[REDACTED:PRIVATE_KEY]\nafter"
    );
}

#[test]
fn cli_check_detects_multiline_private_key_from_stdin() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let pem = "-----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----\n";
    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .arg("--check")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    let mut stdin = child.stdin.take().expect("open stdin");
    stdin.write_all(pem.as_bytes()).expect("write pem");
    drop(stdin);

    let output = child.wait_with_output().expect("wait for CLI");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

#[test]
fn cli_lists_supported_kinds() {
    use std::process::Command;

    let output = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .arg("--list-kinds")
        .output()
        .expect("run leakguard --list-kinds");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.lines().any(|line| line == "email"));
    assert!(stdout.lines().any(|line| line == "private_key"));
    assert!(stdout.lines().any(|line| line == "iban"));
}

#[test]
fn cli_without_excludes_detector_from_stdin() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--without", "email"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    let mut stdin = child.stdin.take().expect("open stdin");
    stdin
        .write_all(b"alice@example.com from 10.0.0.1")
        .expect("write input");
    drop(stdin);

    let output = child.wait_with_output().expect("wait for CLI");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "alice@example.com from [REDACTED:IPV4]"
    );
}

#[test]
fn cli_only_and_without_can_be_combined() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--only", "email,ipv4", "--without", "ipv4"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    let mut stdin = child.stdin.take().expect("open stdin");
    stdin
        .write_all(b"alice@example.com from 10.0.0.1")
        .expect("write input");
    drop(stdin);

    let output = child.wait_with_output().expect("wait for CLI");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "[REDACTED:EMAIL] from 10.0.0.1"
    );
}

#[test]
fn cli_check_verbose_reports_kind_without_secret_value() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--check", "--verbose"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    let mut stdin = child.stdin.take().expect("open stdin");
    stdin
        .write_all(b"contact alice@example.com")
        .expect("write input");
    drop(stdin);

    let output = child.wait_with_output().expect("wait for CLI");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("EMAIL"));
    assert!(stderr.contains("<stdin>"));
    assert!(!stderr.contains("alice@example.com"));
}

#[test]
fn cli_redacts_file_input_and_preserves_no_trailing_newline() {
    use std::fs;
    use std::process::Command;

    let path = std::env::temp_dir().join(format!(
        "leakguard-cli-file-{}-{}.log",
        std::process::id(),
        line!()
    ));
    fs::write(&path, "ip 10.0.0.1").expect("write temp input");

    let output = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .arg(&path)
        .output()
        .expect("run leakguard CLI with file");
    let _ = fs::remove_file(&path);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        "ip [REDACTED:IPV4]"
    );
}

#[test]
fn iban_checksum() {
    let s = Redactor::only(&[Kind::Iban]);
    // Valid German IBAN (well-known test value).
    assert_eq!(
        s.clean("pay DE89370400440532013000 now"),
        "pay [REDACTED:IBAN] now"
    );
    // Corrupted checksum -> not matched.
    assert_eq!(s.clean("DE89370400440532013001"), "DE89370400440532013001");
}

#[test]
fn phone_numbers() {
    let s = Redactor::only(&[Kind::PhoneNumber]);
    assert_eq!(
        s.clean("call +1 (415) 555-0132 now"),
        "call [REDACTED:PHONE] now"
    );
    assert_eq!(s.clean("415-555-0132"), "[REDACTED:PHONE]");
    assert_eq!(s.clean("+44 20 7946 0958"), "[REDACTED:PHONE]");
}

#[test]
fn phone_no_false_positives() {
    let s = Redactor::only(&[Kind::PhoneNumber]);
    // Bare integers, years, short ids are not phones.
    assert_eq!(s.clean("year 2024 and 2025"), "year 2024 and 2025");
    assert_eq!(s.clean("plain 1234567 here"), "plain 1234567 here");
    assert_eq!(s.clean("id 12345"), "id 12345");
}

#[test]
fn high_entropy_opt_in() {
    use leakguard::detectors::HighEntropy;
    let s = Redactor::empty().with_detector(HighEntropy::default());
    assert!(s.is_dirty("token aB3xK9mP2qR7sT1vW5yZ8nL4jH6gF0dC"));
    // Ordinary prose is not flagged.
    assert_eq!(
        s.clean("the quick brown fox jumps over the lazy dog"),
        "the quick brown fox jumps over the lazy dog"
    );
    // Not enabled by default.
    let d = Redactor::new();
    assert!(!d.is_dirty("plainword aaaaaaaaaaaaaaaaaaaaaaaa"));
}

#[test]
fn defaults_cover_new_detectors() {
    let s = Redactor::new();
    let cleaned =
        s.clean("gh ghp_1234567890abcdefghijklmnopqrstuvwxyz iban DE89370400440532013000");
    assert!(cleaned.contains("[REDACTED:GITHUB_TOKEN]"));
    assert!(cleaned.contains("[REDACTED:IBAN]"));
}

#[test]
fn azure_connection_string() {
    let s = Redactor::only(&[Kind::AzureConnectionString]);
    let conn = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abcdef123456==;";
    assert_eq!(s.clean(conn), "[REDACTED:AZURE_CONNECTION_STRING]");
}

#[test]
fn telegram_token() {
    let s = Redactor::only(&[Kind::TelegramToken]);
    let token = "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ1234567890";
    assert_eq!(
        s.clean(&format!("bot {token}")),
        "bot [REDACTED:TELEGRAM_TOKEN]"
    );
}

#[test]
fn discord_token() {
    let s = Redactor::only(&[Kind::DiscordToken]);
    let mfa = format!("mfa.{}", "a".repeat(84));
    assert_eq!(s.clean(&mfa), "[REDACTED:DISCORD_TOKEN]");
}

#[test]
fn clean_iter_helper() {
    let s = Redactor::new();
    let inputs = ["alice@example.com", "10.0.0.1"];
    let cleaned = s.clean_iter(inputs);
    assert_eq!(cleaned[0], "[REDACTED:EMAIL]");
    assert_eq!(cleaned[1], "[REDACTED:IPV4]");
}

#[test]
fn cli_json_output() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    let mut stdin = child.stdin.take().expect("open stdin");
    stdin
        .write_all(b"contact alice@example.com")
        .expect("write input");
    drop(stdin);

    let output = child.wait_with_output().expect("wait for CLI");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("EMAIL"));
    assert!(stdout.contains("matches"));
}

// --- 0.7.0 CLI regressions ---

#[test]
fn cli_json_emits_ndjson_one_object_per_line() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .arg("--json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"contact alice@example.com\nip 10.0.0.1\nnothing here\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");

    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 3, "expected one JSON object per input line");
    // Each line must be a self-contained object: balanced braces, no newline
    // inside. A dependency-free structural check stands in for a JSON parser.
    for line in lines {
        assert!(
            line.starts_with('{') && line.ends_with('}'),
            "not compact: {line}"
        );
        let opens = line.matches('{').count();
        let closes = line.matches('}').count();
        assert_eq!(opens, closes, "unbalanced braces in {line}");
    }
}

#[test]
fn cli_json_omits_secret_values_by_default() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    for args in [vec!["--json"], vec!["--check", "--json"]] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn leakguard CLI");
        child
            .stdin
            .take()
            .expect("open stdin")
            .write_all(b"aws AKIAIOSFODNN7EXAMPLE\n")
            .expect("write input");

        let output = child.wait_with_output().expect("wait for CLI");
        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert!(
            !stdout.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret leaked with {args:?}: {stdout}"
        );
        assert!(stdout.contains("AWS_ACCESS_KEY"), "kind missing: {stdout}");
    }
}

#[test]
fn cli_json_show_values_opts_into_secret_text() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--json", "--show-values"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"aws AKIAIOSFODNN7EXAMPLE\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(
        stdout.contains("\"text\":\"AKIAIOSFODNN7EXAMPLE\""),
        "got: {stdout}"
    );
}

#[test]
fn cli_json_escapes_control_characters() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // A control character inside the matched text must be escaped as \u00XX,
    // otherwise the emitted JSON is invalid per RFC 8259. This goes through
    // stdin rather than a filename because Windows rejects bytes 0x00-0x1F in
    // paths, which made the earlier filename-based version fail there.
    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--json", "--show-values"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"DefaultEndpointsProtocol=https;AccountName=x;AccountKey=abc\x01def123==;\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(
        stdout.contains("\\u0001"),
        "control char not escaped: {stdout}"
    );
    assert!(
        !stdout.contains('\u{1}'),
        "raw control char emitted: {stdout}"
    );
}

#[test]
fn cli_unterminated_private_key_preserves_content_and_streams() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // An unterminated PEM must not be dropped, and single-line secrets inside
    // the buffered fragment must still be redacted.
    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"-----BEGIN RSA PRIVATE KEY-----\nbody\nalice@example.com\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(stdout.contains("[REDACTED:EMAIL]"));
    assert!(!stdout.contains("alice@example.com"));
}

#[test]
fn cli_keep_larger_than_match_still_masks() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--mask", "partial", "--keep", "99"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"ip 10.0.0.1\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(
        !stdout.contains("10.0.0.1"),
        "value survived --keep 99: {stdout}"
    );
    assert!(stdout.contains('*'), "expected masking: {stdout}");
}
