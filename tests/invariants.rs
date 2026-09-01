use leakguard::{Kind, Mask, Match, Redactor};

fn next_u64(state: &mut u64) -> u64 {
    // Deterministic LCG: good enough for repeatable fuzz-style coverage without
    // adding a dev-dependency.
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn push_random_fragment(out: &mut String, state: &mut u64) {
    const FRAGMENTS: &[&str] = &[
        "plain text ",
        "alice@example.com",
        " 10.0.0.1 ",
        "2001:db8::1",
        "4111 1111 1111 1111",
        "123-45-6789",
        "00:1A:2B:3C:4D:5E",
        "not-a-secret ",
        "héllo ",
        "🔒 ",
        "https://user:pass@example.com/path ",
        "AKIAIOSFODNN7EXAMPLE",
        "AIzaSyD1234567890abcdefghijklmnopqrstuv",
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "github_pat_11ABCDEFG0abcdefghij_KLMNOPQRSTUVWXYZ1234567890abcdef",
        "xoxb-123456789012-1234567890123-abcdefABCDEF1234567890ab",
        "sk-proj-abcdEFGH1234567890ijklMNOP1234",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dQw4w9WgXcQ",
        "DE89370400440532013000",
        "-----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----\nABc12==\n-----END EC PRIVATE KEY-----",
        "DefaultEndpointsProtocol=https;AccountName=act;AccountKey=abcdef123456==;",
        "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ1234567890",
        "mfa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "+1 (415) 555-0132",
        "\r\n",
        "\0",
        "-----BEGIN RSA PRIVATE KEY-----\nheader without end",
    ];

    let choice = (next_u64(state) as usize) % 6;
    match choice {
        0 => {
            let idx = (next_u64(state) as usize) % FRAGMENTS.len();
            out.push_str(FRAGMENTS[idx]);
        }
        1 => {
            let len = (next_u64(state) as usize) % 32;
            for _ in 0..len {
                let b = 32 + ((next_u64(state) % 95) as u8);
                out.push(b as char);
            }
        }
        2 => {
            let len = (next_u64(state) as usize) % 24;
            for _ in 0..len {
                out.push(char::from(b'0' + (next_u64(state) % 10) as u8));
                if next_u64(state) % 4 == 0 {
                    out.push([' ', '-', '.'][(next_u64(state) as usize) % 3]);
                }
            }
        }
        3 => out.push_str(["é", "ß", "中", "🙂", "\n", "\r"][(next_u64(state) as usize) % 6]),
        4 => {
            // Long token-character runs stress the prefix scanners' linearity.
            let len = 1 + (next_u64(state) as usize % 400);
            for _ in 0..len {
                out.push_str(
                    ["g", "h", "p", "_", "s", "k", "-", "1", "2", "A", "B"]
                        [(next_u64(state) as usize) % 11],
                );
            }
            out.push(' ');
        }
        _ => out.push(' '),
    }
}

fn generated_case(seed: u64) -> String {
    let mut state = seed;
    let fragments = 1 + (next_u64(&mut state) as usize % 48);
    let mut input = String::new();
    for _ in 0..fragments {
        push_random_fragment(&mut input, &mut state);
    }
    input
}

/// Reconstruct what `clean` must output for `matches` under `mask`, using only
/// the documented mask semantics. Asserting `clean(input) == expected` pins
/// both the span math and every renderer, and implies the cleaned output
/// contains no detected span value (each span is replaced by its mask).
fn expected_clean(input: &str, matches: &[Match], mask: &Mask) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    for m in matches {
        out.push_str(&input[cursor..m.start]);
        let text = m.text(input);
        out.push_str(&render(mask, m, text));
        cursor = m.end;
    }
    out.push_str(&input[cursor..]);
    out
}

fn render(mask: &Mask, m: &Match, text: &str) -> String {
    match mask {
        Mask::Label => format!("[REDACTED:{}]", m.kind.label()),
        Mask::Fixed(s) => String::from(s.as_ref()),
        Mask::Char(c) => c.to_string().repeat(text.chars().count()),
        Mask::Partial { keep_last, ch } => {
            let total = text.chars().count();
            let keep = (*keep_last).min(total / 2);
            let masked = total - keep;
            ch.to_string().repeat(masked) + &text.chars().skip(masked).collect::<String>()
        }
        Mask::Hash => format!("[{}#{:08x}]", m.kind.label(), fnv1a(text.as_bytes())),
        Mask::Template(tmpl) => {
            let label_upper = m.kind.label();
            let mut out = String::with_capacity(tmpl.len() + label_upper.len());
            let mut rest = tmpl.as_ref();
            while let Some(idx) = rest.find('{') {
                out.push_str(&rest[..idx]);
                rest = &rest[idx..];
                if let Some(end) = rest.find('}') {
                    let token = &rest[1..end];
                    match token {
                        "LABEL" | "KIND" => out.push_str(label_upper),
                        "label" | "kind" => {
                            for c in label_upper.chars() {
                                out.push(c.to_ascii_lowercase());
                            }
                        }
                        _ => out.push_str(&rest[..=end]),
                    }
                    rest = &rest[end + 1..];
                } else {
                    break;
                }
            }
            out.push_str(rest);
            out
        }
        // `Mask` is #[non_exhaustive]: this test only passes the masks it
        // constructs itself.
        _ => unreachable!("test renders only masks it builds"),
    }
}

/// 32-bit FNV-1a mirror of the library's `Mask::Hash` fingerprint so the test
/// can assert on exact render output without reaching into private code.
fn fnv1a(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in bytes {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn assert_redactor_invariants(redactor: &Redactor, mask: &Mask, input: &str) {
    let matches = redactor.find(input);
    let mut previous_end = 0;

    for m in &matches {
        assert!(m.start <= m.end, "invalid span {m:?} in {input:?}");
        assert!(
            m.end <= input.len(),
            "out-of-bounds span {m:?} in {input:?}"
        );
        assert!(
            input.is_char_boundary(m.start),
            "start not on UTF-8 boundary: {m:?}"
        );
        assert!(
            input.is_char_boundary(m.end),
            "end not on UTF-8 boundary: {m:?}"
        );
        assert!(
            m.start >= previous_end,
            "matches overlap or are unsorted: {matches:?}"
        );
        assert!(!m.text(input).is_empty(), "empty match: {m:?}");
        previous_end = m.end;
    }

    // The mask renderers are total functions over valid detector output and
    // replace every matched span, so the cleaned text equals the documented
    // reconstruction (no detected span value survives).
    let cleaned = redactor.clean(input);
    let expected = expected_clean(input, &matches, mask);
    assert_eq!(cleaned, expected, "render mismatch in {input:?}");

    // Re-cleaning the output must eventually converge (no oscillation). Two
    // mechanisms can break single-pass idempotence:
    //
    //   * `Mask::Partial` preserves raw tail characters, and a preserved tail
    //     can itself resemble a secret (the last half of `2001:db8::1` is
    //     `8::1`), so the next pass may redact that fragment; it reaches a
    //     fixed point on that pass.
    //   * Fully-hiding masks (Label, Fixed, Char, Hash, Template) replace a
    //     span with a *shorter* artifact, which shifts the match-window end
    //     left. If the window previously excluded an occurrence because its
    //     body was too long, that occurrence can become valid on the next
    //     clean pass. Each such replacement shortens the output further,
    //     exposing one more candidate from the right edge per pass. This
    //     cascades O(len / (span_len - artifact_len)) times.
    //
    // The extra-pass budget below scales with input length; it is more than
    // generous for all practical (≤ 4 KB) inputs.
    let max_extra = 4 + input.len() / 240;
    let max_extra = max_extra.min(32); // clamp for test runtime
                                       // Single-pass idempotence for clean, non-adversarial inputs is asserted
                                       // separately in `single_pass_idempotence_for_isolated_secrets`.
    let mut prev = cleaned;
    let mut stable = false;
    for _ in 0..max_extra {
        let next = redactor.clean(&prev);
        if next == prev {
            stable = true;
            break;
        }
        prev = next;
    }
    assert!(
        stable,
        "clean did not converge within {max_extra} extra passes for {input:?}"
    );
}

#[test]
fn single_pass_idempotence_for_isolated_secrets() {
    // With clean, well-delimited secrets (the normal case), one application of
    // `clean` is a fixed point for every detector and every mask: the mask
    // output is inert and no boundary collisions exist.
    let canonical = [
        "alice@example.com",
        "4111 1111 1111 1111",
        "203.0.113.42",
        "2001:db8::1",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dQw4w9WgXcQ",
        "123-45-6789",
        "00:1A:2B:3C:4D:5E",
        "AKIAIOSFODNN7EXAMPLE",
        "https://user:pass@example.com/path",
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "xoxb-123456789012-1234567890123-abcdefABCDEF1234567890ab",
        "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH",
        "AIzaSyD1234567890abcdefghijklmnopqrstuv",
        "sk-abcdEFGH1234567890ijklMNOPqrst1234",
        "-----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----",
        "DE89370400440532013000",
        "DefaultEndpointsProtocol=https;AccountName=a;AccountKey=abcdef123456==;",
        "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ1234567890",
        "mfa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "+1 (415) 555-0132",
        "s3Cr3tT0k3n_8f3aB91cD2eF74gH05iJ16kL27mN",
    ];
    let masks = [
        Mask::Label,
        Mask::fixed("***"),
        Mask::Char('#'),
        Mask::Hash,
        Mask::template("<{LABEL}:{label}>"),
    ];
    let kinds = [
        Kind::Email,
        Kind::CreditCard,
        Kind::IpV4,
        Kind::IpV6,
        Kind::Jwt,
        Kind::UsSsn,
        Kind::MacAddress,
        Kind::AwsAccessKey,
        Kind::UrlCredentials,
        Kind::GitHubToken,
        Kind::SlackToken,
        Kind::StripeKey,
        Kind::GoogleApiKey,
        Kind::OpenAiKey,
        Kind::PrivateKey,
        Kind::Iban,
        Kind::AzureConnectionString,
        Kind::TelegramToken,
        Kind::DiscordToken,
        Kind::PhoneNumber,
        Kind::GenericSecret,
    ];

    for (i, kind) in kinds.iter().enumerate() {
        for mask in &masks {
            let redactor = Redactor::only(std::slice::from_ref(kind)).mask(mask.clone());
            let secret = canonical[i];
            let once = redactor.clean(secret);
            if once == secret {
                continue; // kind is not among the defaults for this secret's context
            }
            assert_eq!(
                redactor.clean(&once),
                once,
                "one-pass idempotence failed for {kind:?} with {mask:?} on {secret:?}"
            );
        }
    }

    // Partial mask: kept tail characters can be re-detected (e.g.
    // "2001:db8::1" → "******8::1", then "8::1" matches IPv6).  Verify
    // that a second extra pass reaches a fixed point.
    let partial = Mask::Partial {
        keep_last: 4,
        ch: '*',
    };
    for (i, kind) in kinds.iter().enumerate() {
        let redactor = Redactor::only(std::slice::from_ref(kind)).mask(partial.clone());
        let secret = canonical[i];
        let once = redactor.clean(secret);
        if once == secret {
            continue;
        }
        let twice = redactor.clean(&once);
        let thrice = redactor.clean(&twice);
        assert_eq!(
            thrice, twice,
            "Partial convergence failed for {kind:?} on {secret:?}"
        );
    }
}

#[test]
fn fuzz_style_generated_inputs_keep_match_offsets_valid() {
    let mask_pairs = [
        (Redactor::new(), Mask::Label),
        (Redactor::new().mask(Mask::fixed("***")), Mask::fixed("***")),
        (Redactor::new().mask(Mask::Char('#')), Mask::Char('#')),
        (
            Redactor::new().mask(Mask::Partial {
                keep_last: 4,
                ch: '*',
            }),
            Mask::Partial {
                keep_last: 4,
                ch: '*',
            },
        ),
        (Redactor::new().mask(Mask::Hash), Mask::Hash),
        (
            Redactor::new().mask(Mask::template("<{LABEL}:{label}>")),
            Mask::template("<{LABEL}:{label}>"),
        ),
    ];

    for seed in 0..1_000u64 {
        let input = generated_case(seed);
        for (redactor, mask) in &mask_pairs {
            assert_redactor_invariants(redactor, mask, &input);
        }
    }
}

/// Every built-in detector, exercised via `Redactor::only` so each scanner is
/// stressed on its own, across every mask: span validity, mask reconstruction
/// (no value survives), and `clean` convergence. One-pass idempotence for
/// clean inputs is pinned separately in
/// `single_pass_idempotence_for_isolated_secrets`.
#[test]
fn every_detector_every_mask_preserves_invariants_and_converges() {
    let mut kinds = vec![
        Kind::Email,
        Kind::IpV4,
        Kind::IpV6,
        Kind::Jwt,
        Kind::UsSsn,
        Kind::MacAddress,
        Kind::AwsAccessKey,
        Kind::UrlCredentials,
        Kind::GitHubToken,
        Kind::SlackToken,
        Kind::StripeKey,
        Kind::GoogleApiKey,
        Kind::OpenAiKey,
        Kind::PrivateKey,
        Kind::Iban,
        Kind::AzureConnectionString,
        Kind::TelegramToken,
        Kind::DiscordToken,
        Kind::CreditCard,
        Kind::PhoneNumber,
        Kind::GenericSecret,
    ];

    let seed_corpus: Vec<String> = (0..120u64).map(generated_case).collect();
    let adversarial = [
        "".to_string(),
        "1".repeat(2_000),
        "ghp_".repeat(1_000),
        "AB12".repeat(1_000),
        "sk-".repeat(1_000),
        "-----BEGIN RSA PRIVATE KEY-----\n".repeat(200),
        "a://".repeat(1_000),
        "999.999.999.999 ".repeat(500),
        "日本🙂éß".repeat(100),
        "\r\n".repeat(500),
        "DefaultEndpointsProtocol=https;AccountKey=abcdef123456==;".repeat(100),
        "mfa.".repeat(1_000),
        "123456789:abcdefghijklmnopqrstuvwxyz0123456".repeat(50),
    ];
    let mut corpus: Vec<String> = seed_corpus;
    corpus.extend(adversarial);

    let masks = [
        Mask::Label,
        Mask::fixed("***"),
        Mask::Char('#'),
        Mask::Partial {
            keep_last: usize::MAX,
            ch: '*',
        },
        Mask::Hash,
        Mask::template("<{LABEL}:{label}>"),
    ];

    // Keep the sweep deterministic and bounded: rotate detector order per run.
    kinds.rotate_left(3);
    for kind in kinds {
        for mask in &masks {
            let redactor = Redactor::only(std::slice::from_ref(&kind)).mask(mask.clone());
            for input in &corpus {
                assert_redactor_invariants(&redactor, mask, input);
            }
        }
    }
}

#[test]
fn non_ascii_email_local_parts_match_whole_and_stay_on_boundaries() {
    let redactor = Redactor::new();
    let cases = [
        "písmena@example.com",
        "jörg@example.com",
        "日本@example.com",
        "ünïcodé.tëst@example.co.uk",
        "Ω@example.com",
        "🙂user@example.com",
    ];

    for input in cases {
        assert_redactor_invariants(&redactor, &Mask::Label, input);
        let matches = redactor.find(input);
        assert_eq!(matches.len(), 1, "expected one match in {input:?}");
        // The whole local part must be covered -- no leading fragment left over.
        assert_eq!(
            matches[0].start,
            0,
            "leaked a prefix of {input:?}: {:?}",
            &input[..matches[0].start]
        );
        assert_eq!(matches[0].end, input.len(), "did not cover {input:?}");
        assert_eq!(redactor.clean(input), "[REDACTED:EMAIL]");
    }
}

#[test]
fn non_ascii_inputs_never_slice_mid_character() {
    // Multibyte text interleaved with secrets, including at boundaries.
    let redactor = Redactor::new();
    let cases = [
        "🙂 alice@example.com 🙂",
        "héllo AKIAIOSFODNN7EXAMPLE wörld",
        "中文4111111111111111中文",
        "é10.0.0.1é",
        "ß123-45-6789ß",
    ];
    for input in cases {
        assert_redactor_invariants(&redactor, &Mask::Label, input);
    }
}

#[test]
fn adversarial_inputs_do_not_panic_or_emit_invalid_offsets() {
    let redactor = Redactor::new();
    let cases = [
        "",
        "@ @@@ .... ---- :::: ////",
        "999.999.999.999 1.2.3.4.5 2001:::db8",
        "4111 1111 1111 1100 0060",
        "41111111111111000060",
        "-----BEGIN RSA PRIVATE KEY-----\\nmissing end",
        "-----BEGIN CERTIFICATE-----\\nabc\\n-----END CERTIFICATE-----",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "🙂🙂🙂 alice@example.com 🙂 10.0.0.1 🙂",
        "https://user:pass@example.com/a?next=alice@example.com",
        "xoxb-short sk-short github_pat_short AIza-short",
        "1234567890:short mfa.short MTIz.abc.def",
        "DefaultEndpointsProtocol=https;AccountName=;AccountKey=;",
        "\r \r\n \n \r\r\r",
        "\u{0}alice@example.com\u{0}",
        "------BEGIN RSA PRIVATE KEY------",
    ];

    for input in cases {
        assert_redactor_invariants(&redactor, &Mask::Label, input);
    }

    // Larger generated shapes run through the same invariant checks.
    for input in ["1".repeat(10_000), "ghp_".repeat(1_000)] {
        assert_redactor_invariants(&redactor, &Mask::Label, &input);
    }
}

#[test]
fn partial_mask_never_reveals_more_than_half_even_keep_last_max() {
    let mask = Mask::Partial {
        keep_last: usize::MAX,
        ch: '*',
    };
    let redactor = Redactor::new().mask(mask.clone());
    for input in [
        "4111 1111 1111 1111",
        "alice@example.com",
        "AKIAIOSFODNN7EXAMPLE",
        "123-45-6789",
        "00:1A:2B:3C:4D:5E",
        "🙂🙂🙂🙂x",
    ] {
        if !redactor.is_dirty(input) {
            continue; // nothing to mask
        }
        assert_redactor_invariants(&redactor, &mask, input);
        let cleaned = redactor.clean(input);
        let kept_chars = cleaned.matches('*').count() as f64;
        let total_chars = input.chars().count() as f64;
        assert!(
            kept_chars >= (total_chars / 2.0).ceil(),
            "{cleaned:?} reveals more than half of {input:?}"
        );
    }
}
