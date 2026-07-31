use leakguard::{Kind, Mask, Redactor};

#[test]
fn test_ignore_single_and_list() {
    let r = Redactor::new()
        .ignore("10.0.0.1")
        .ignore_list(["admin@example.com", "not-a-secret"]);

    let input = "ip 10.0.0.1 and ip 192.168.1.1 email admin@example.com and alice@example.com";

    // 10.0.0.1 and admin@example.com should be ignored
    let clean = r.clean(input);
    assert_eq!(
        clean,
        "ip 10.0.0.1 and ip [REDACTED:IPV4] email admin@example.com and [REDACTED:EMAIL]"
    );

    let matches = r.find(input);
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].kind, Kind::IpV4);
    assert_eq!(matches[0].text(input), "192.168.1.1");
    assert_eq!(matches[1].kind, Kind::Email);
    assert_eq!(matches[1].text(input), "alice@example.com");

    // is_dirty should be false when only ignored matches are present
    assert!(!r.is_dirty("ip 10.0.0.1 email admin@example.com"));
    assert!(r.is_dirty("ip 10.0.0.1 email alice@example.com"));
}

#[test]
fn test_redact_literal_and_words() {
    let r = Redactor::new()
        .redact_literal("AcmeCorp", Kind::Custom("CLIENT"))
        .redact_words(["ProjectX", "SuperSecret"], Kind::Custom("KEYWORD"));

    let input =
        "Welcome to AcmeCorp working on ProjectX with SuperSecret key and alice@example.com";
    let clean = r.clean(input);
    assert_eq!(
        clean,
        "Welcome to [REDACTED:CLIENT] working on [REDACTED:KEYWORD] with [REDACTED:KEYWORD] key and [REDACTED:EMAIL]"
    );
}

#[test]
fn test_mask_template() {
    let r = Redactor::new().mask(Mask::template("<{LABEL}:{label}>"));
    assert_eq!(r.clean("ip 10.0.0.1"), "ip <IPV4:ipv4>");

    let r_plain = Redactor::new().mask(Mask::template("STATIC"));
    assert_eq!(r_plain.clean("ip 10.0.0.1"), "ip STATIC");

    let r_kind = Redactor::new().mask(Mask::template("({KIND}/{kind})"));
    assert_eq!(
        r_kind.clean("email alice@example.com"),
        "email (EMAIL/email)"
    );
}

#[test]
fn test_find_located_lines_and_columns() {
    let r = Redactor::new();
    let input =
        "first line no match\nsecond line alice@example.com and 10.0.0.1\nthird 🙂 192.168.0.1";
    let located = r.find_located(input);

    assert_eq!(located.len(), 3);

    // alice@example.com on line 2
    assert_eq!(located[0].line, 2);
    assert_eq!(located[0].column, 13);
    assert_eq!(located[0].matched.kind, Kind::Email);

    // 10.0.0.1 on line 2
    assert_eq!(located[1].line, 2);
    assert_eq!(located[1].column, 35);
    assert_eq!(located[1].matched.kind, Kind::IpV4);

    // 192.168.0.1 on line 3 (after multi-byte emoji 🙂)
    assert_eq!(located[2].line, 3);
    assert_eq!(located[2].column, 9);
    assert_eq!(located[2].matched.kind, Kind::IpV4);
}

#[test]
fn test_redaction_stats_and_clean_with_stats() {
    let r = Redactor::new();
    let input = "contact alice@example.com or bob@example.com from 10.0.0.1";
    let (cleaned, stats) = r.clean_with_stats(input);

    assert_eq!(
        cleaned,
        "contact [REDACTED:EMAIL] or [REDACTED:EMAIL] from [REDACTED:IPV4]"
    );
    assert_eq!(stats.total_matches, 3);
    assert_eq!(stats.by_kind.get(&Kind::Email), Some(&2));
    assert_eq!(stats.by_kind.get(&Kind::IpV4), Some(&1));

    let stats_str = stats.to_string();
    assert!(stats_str.contains("3 matches"));
    assert!(stats_str.contains("EMAIL: 2 matches"));
    assert!(stats_str.contains("IPV4: 1 match"));

    let (cleaned_vec, merged_stats) =
        r.clean_iter_with_stats(["alice@example.com", "10.0.0.1", "no secret"]);
    assert_eq!(cleaned_vec.len(), 3);
    assert_eq!(merged_stats.total_matches, 2);
}

#[cfg(feature = "parallel")]
#[test]
fn test_parallel_stats_and_located() {
    let r = Redactor::new();
    // Create an input larger than PARALLEL_INPUT_THRESHOLD (256 KiB)
    let mut input = String::with_capacity(300 * 1024);
    for i in 0..10_000 {
        input.push_str(&format!("line {} alice@example.com 10.0.0.1\n", i));
    }

    let serial_located = r.find_located(&input);
    let parallel_located = r.find_located_parallel(&input);
    assert_eq!(parallel_located, serial_located);

    let serial_stats = r.stats(&input);
    let parallel_stats = r.stats_parallel(&input);
    assert_eq!(parallel_stats, serial_stats);

    let (clean_serial, stats_serial_c) = r.clean_with_stats(&input);
    let (clean_parallel, stats_parallel_c) = r.clean_with_stats_parallel(&input);
    assert_eq!(clean_parallel, clean_serial);
    assert_eq!(stats_parallel_c, stats_serial_c);
}

// --- CLI integration tests for new features ---

#[test]
fn cli_ignore_flag_skips_matches() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--ignore", "10.0.0.1,admin@example.com"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"ip 10.0.0.1 and 192.168.0.1 email admin@example.com\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(
        stdout.contains("10.0.0.1"),
        "10.0.0.1 should not be redacted: {stdout}"
    );
    assert!(
        stdout.contains("admin@example.com"),
        "admin@example.com should not be redacted: {stdout}"
    );
    assert!(
        stdout.contains("[REDACTED:IPV4]"),
        "other ip should be redacted: {stdout}"
    );
}

#[test]
fn cli_ignore_file_skips_matches() {
    use std::fs;
    use std::io::Write;
    use std::process::{Command, Stdio};

    let path = std::env::temp_dir().join(format!(
        "leakguard-cli-ignore-{}-{}.txt",
        std::process::id(),
        line!()
    ));
    fs::write(&path, "# comment\n10.0.0.1\n\nadmin@example.com\n").expect("write ignore file");

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--ignore-file", path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"ip 10.0.0.1 email admin@example.com\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    let _ = fs::remove_file(path);
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("10.0.0.1"));
    assert!(stdout.contains("admin@example.com"));
}

#[test]
fn cli_redact_word_flag() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--redact-word", "AcmeCorp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"Welcome to AcmeCorp system\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert_eq!(stdout, "Welcome to [REDACTED:KEYWORD] system\n");
}

#[test]
fn cli_redact_literal_flag_with_custom_kind() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--redact-literal", "AcmeCorp:email"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"Welcome to AcmeCorp system\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert_eq!(stdout, "Welcome to [REDACTED:EMAIL] system\n");
}

#[test]
fn cli_redact_words_file() {
    use std::fs;
    use std::io::Write;
    use std::process::{Command, Stdio};

    let path = std::env::temp_dir().join(format!(
        "leakguard-cli-words-{}-{}.txt",
        std::process::id(),
        line!()
    ));
    fs::write(&path, "# comment\nProjectX\nSecretName\n").expect("write words file");

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--redact-words-file", path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"Working on ProjectX with SecretName\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    let _ = fs::remove_file(path);
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert_eq!(
        stdout,
        "Working on [REDACTED:KEYWORD] with [REDACTED:KEYWORD]\n"
    );
}

#[test]
fn cli_mask_template_flag() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--mask", "template", "--template", "<{LABEL}:{label}>"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"contact alice@example.com\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert_eq!(stdout, "contact <EMAIL:email>\n");
}

#[test]
fn cli_stats_flag_prints_summary_to_stderr() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .arg("--stats")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"contact alice@example.com from 10.0.0.1\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");

    assert_eq!(stdout, "contact [REDACTED:EMAIL] from [REDACTED:IPV4]\n");
    assert!(
        stderr.contains("=== leakguard redaction summary ==="),
        "missing summary header: {stderr}"
    );
    assert!(stderr.contains("2 matches"), "got: {stderr}");
    assert!(stderr.contains("EMAIL: 1 match"), "got: {stderr}");
    assert!(stderr.contains("IPV4: 1 match"), "got: {stderr}");
}

#[test]
fn cli_json_output_includes_line_and_column() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"hello\ncontact alice@example.com\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");

    assert!(
        stdout.contains("\"line\":2"),
        "missing line number: {stdout}"
    );
    assert!(
        stdout.contains("\"column\":9"),
        "missing column number: {stdout}"
    );
}

#[test]
fn cli_check_verbose_includes_line_and_column() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .args(["--check", "-v"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn leakguard CLI");
    child
        .stdin
        .take()
        .expect("open stdin")
        .write_all(b"hello\ncontact alice@example.com\n")
        .expect("write input");

    let output = child.wait_with_output().expect("wait for CLI");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");

    assert!(
        stderr.contains("line 2"),
        "missing line number in stderr: {stderr}"
    );
    assert!(
        stderr.contains("col 9"),
        "missing column number in stderr: {stderr}"
    );
}
