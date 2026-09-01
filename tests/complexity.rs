//! Algorithmic-complexity guardrails.
//!
//! These assert that detection stays **sub-quadratic** on adversarial inputs.
//! Two O(n^2) regressions have shipped before (`UrlCredentials` scanning to
//! end-of-input per `://`, and the CLI re-scanning a buffered PEM block per
//! line), so the shapes that triggered them are pinned here.
//!
//! Wall-clock assertions are inherently noisy, so these are `#[ignore]`d by
//! default and excluded from the normal CI budget. Run them explicitly:
//!
//! ```sh
//! cargo test --release --test complexity -- --ignored --nocapture
//! ```
//!
//! Thresholds are deliberately loose: they catch a return to quadratic growth
//! (ratio ~4x per doubling), not a modest constant-factor slowdown.

use std::time::Instant;

use leakguard::{Kind, Redactor};

/// Growth ratio per input doubling that still counts as sub-quadratic.
/// Linear is 2.0; quadratic is 4.0. Allow headroom for noise and allocator
/// effects without letting true quadratic behaviour pass.
const MAX_RATIO_PER_DOUBLING: f64 = 2.8;

fn time_find(redactor: &Redactor, input: &str) -> f64 {
    // One warm-up pass so allocation and cache effects don't skew the sample.
    let _ = redactor.find(input);
    let start = Instant::now();
    let _ = redactor.find(input);
    start.elapsed().as_secs_f64()
}

#[test]
#[ignore = "timing-sensitive; run with --release --ignored"]
fn url_credentials_scales_sub_quadratically() {
    let redactor = Redactor::only(&[Kind::UrlCredentials]);
    // `a://` with no '@' anywhere is the worst case: every occurrence used to
    // trigger a scan to end-of-input.
    let sizes = [128 * 1024usize, 256 * 1024, 512 * 1024, 1024 * 1024];
    let mut previous: Option<f64> = None;

    for size in sizes {
        let input = "a://".repeat(size / 4);
        let elapsed = time_find(&redactor, &input);
        println!("  {:>9} B  {:>9.3} ms", input.len(), elapsed * 1000.0);

        if let Some(prev) = previous {
            let ratio = elapsed / prev.max(f64::EPSILON);
            assert!(
                ratio <= MAX_RATIO_PER_DOUBLING,
                "UrlCredentials growth {ratio:.2}x per doubling at {size} B \
                 exceeds {MAX_RATIO_PER_DOUBLING}x -- quadratic regression?"
            );
        }
        previous = Some(elapsed);
    }
}

#[test]
#[ignore = "timing-sensitive; run with --release --ignored"]
fn url_credentials_handles_one_mib_quickly() {
    let redactor = Redactor::only(&[Kind::UrlCredentials]);
    let input = "a://".repeat(1024 * 1024 / 4);
    let elapsed = time_find(&redactor, &input);
    println!("  1 MiB of 'a://' -> {:.3} ms", elapsed * 1000.0);
    // Was ~14 s before the fix; 50 ms is a generous ceiling for the linear scan.
    assert!(
        elapsed < 0.050,
        "1 MiB took {:.3} ms, expected < 50 ms",
        elapsed * 1000.0
    );
}

#[test]
#[ignore = "timing-sensitive; run with --release --ignored"]
fn all_default_detectors_scale_sub_quadratically() {
    let redactor = Redactor::new();
    // A mixed payload exercising several prefix scanners at once.
    let unit = "a:// eyJ sk- ghp_ xoxb- AIza 1234 user@host ";
    let sizes = [64 * 1024usize, 128 * 1024, 256 * 1024, 512 * 1024];
    let mut previous: Option<f64> = None;

    for size in sizes {
        let reps = size / unit.len();
        let input = unit.repeat(reps.max(1));
        let elapsed = time_find(&redactor, &input);
        println!("  {:>9} B  {:>9.3} ms", input.len(), elapsed * 1000.0);

        if let Some(prev) = previous {
            let ratio = elapsed / prev.max(f64::EPSILON);
            assert!(
                ratio <= MAX_RATIO_PER_DOUBLING,
                "default detectors grew {ratio:.2}x per doubling -- quadratic regression?"
            );
        }
        previous = Some(elapsed);
    }
}

#[test]
#[ignore = "timing-sensitive; run with --release --ignored"]
fn dense_matches_scale_sub_quadratically() {
    let redactor = Redactor::new();
    let unit = "alice@example.com 203.0.113.42 4111 1111 1111 1111\n";
    let sizes = [4_096usize, 8_192, 16_384, 32_768];
    let mut previous: Option<f64> = None;

    for repetitions in sizes {
        let input = unit.repeat(repetitions);
        let mut samples = [0.0; 5];
        for sample in &mut samples {
            *sample = time_find(&redactor, &input);
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let elapsed = samples[samples.len() / 2];
        println!("  {:>9} B  {:>9.3} ms", input.len(), elapsed * 1000.0);

        if let Some(prev) = previous {
            let ratio = elapsed / prev.max(f64::EPSILON);
            assert!(
                ratio <= MAX_RATIO_PER_DOUBLING,
                "dense matching grew {ratio:.2}x per doubling -- quadratic regression?"
            );
        }
        previous = Some(elapsed);
    }
}

#[test]
#[ignore = "timing-sensitive; run with --release --ignored"]
fn cli_unterminated_pem_scales_sub_quadratically() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // An unterminated PEM header used to make the CLI buffer to EOF and
    // re-scan the whole buffer per line.
    let run = |lines: usize| -> f64 {
        let mut payload = String::from("-----BEGIN RSA PRIVATE KEY-----\n");
        for i in 0..lines {
            payload.push_str(&format!("filler line {i}\n"));
        }
        let start = Instant::now();
        let mut child = Command::new(env!("CARGO_BIN_EXE_leakguard"))
            .arg("--check")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn leakguard");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.as_bytes())
            .expect("write payload");
        let _ = child.wait().expect("wait");
        start.elapsed().as_secs_f64()
    };

    let mut previous: Option<f64> = None;
    for lines in [10_000usize, 20_000, 40_000, 80_000] {
        let elapsed = run(lines);
        println!("  {lines:>6} lines -> {:.3} s", elapsed);
        if let Some(prev) = previous {
            let ratio = elapsed / prev.max(f64::EPSILON);
            assert!(
                ratio <= MAX_RATIO_PER_DOUBLING,
                "CLI PEM path grew {ratio:.2}x per doubling -- quadratic regression?"
            );
        }
        previous = Some(elapsed);
    }
}
