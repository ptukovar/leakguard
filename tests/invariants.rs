use leakguard::{Mask, Redactor};

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
        "4111 1111 1111 1111",
        "not-a-secret ",
        "héllo ",
        "🔒 ",
        "https://user:pass@example.com/path ",
        "AKIAIOSFODNN7EXAMPLE",
        "DE89370400440532013000",
        "-----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----",
        "xoxb-123456789012-1234567890123-abcdefABCDEF1234567890ab",
        "sk-proj-abcdEFGH1234567890ijklMNOP1234",
        "2001:db8::1",
        "00:1A:2B:3C:4D:5E",
        "123-45-6789",
        "+1 (415) 555-0132",
        "\r\n",
        "\0",
    ];

    let choice = (next_u64(state) as usize) % 5;
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
        3 => out.push_str(["é", "ß", "中", "🙂", "\n"][(next_u64(state) as usize) % 5]),
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

fn assert_redactor_invariants(redactor: &Redactor, input: &str) {
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

    // All mask renderers should be total functions over valid detector output.
    let _ = redactor.clean(input);
}

#[test]
fn fuzz_style_generated_inputs_keep_match_offsets_valid() {
    let redactors = [
        Redactor::new(),
        Redactor::new().mask(Mask::fixed("***")),
        Redactor::new().mask(Mask::Char('#')),
        Redactor::new().mask(Mask::Partial {
            keep_last: 4,
            ch: '*',
        }),
        Redactor::new().mask(Mask::Hash),
    ];

    for seed in 0..1_000u64 {
        let input = generated_case(seed);
        for redactor in &redactors {
            assert_redactor_invariants(redactor, &input);
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
        assert_redactor_invariants(&redactor, input);
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
        assert_redactor_invariants(&redactor, input);
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
        "-----BEGIN RSA PRIVATE KEY-----\nmissing end",
        "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "🙂🙂🙂 alice@example.com 🙂 10.0.0.1 🙂",
        "https://user:pass@example.com/a?next=alice@example.com",
        "xoxb-short sk-short github_pat_short AIza-short",
    ];

    for input in cases {
        assert_redactor_invariants(&redactor, input);
    }
}
