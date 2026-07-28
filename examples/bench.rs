//! Simple dependency-free benchmark harness.
//!
//! Run with:
//!     cargo run --release --example bench
//!
//! This is intentionally small and uses only `std::time::Instant` so the crate
//! can keep its normal and development dependency graph empty. For rigorous
//! performance work, run this several times on an otherwise idle machine.

use std::hint::black_box;
use std::time::{Duration, Instant};

use leakguard::{Mask, Redactor};

fn bench_case(name: &str, input: &str, iterations: usize, redactor: &Redactor) {
    let start = Instant::now();
    let mut bytes = 0usize;
    for _ in 0..iterations {
        let cleaned = redactor.clean(black_box(input));
        bytes += cleaned.len();
        black_box(cleaned);
    }
    report(name, input.len(), iterations, bytes, start.elapsed());
}

#[cfg(feature = "parallel")]
fn bench_parallel(name: &str, input: &str, iterations: usize, redactor: &Redactor) {
    let start = Instant::now();
    let mut bytes = 0usize;
    for _ in 0..iterations {
        let cleaned = redactor.clean_parallel(black_box(input));
        bytes += cleaned.len();
        black_box(cleaned);
    }
    report(name, input.len(), iterations, bytes, start.elapsed());
}

fn bench_check(name: &str, input: &str, iterations: usize, redactor: &Redactor) {
    let start = Instant::now();
    let mut dirty = 0usize;
    for _ in 0..iterations {
        if redactor.is_dirty(black_box(input)) {
            dirty += 1;
        }
    }
    black_box(dirty);
    report(
        name,
        input.len(),
        iterations,
        input.len() * iterations,
        start.elapsed(),
    );
}

fn report(name: &str, input_len: usize, iterations: usize, bytes: usize, elapsed: Duration) {
    let secs = elapsed.as_secs_f64();
    let ns_per_iter = elapsed.as_nanos() as f64 / iterations as f64;
    let mib_s = if secs > 0.0 {
        bytes as f64 / (1024.0 * 1024.0) / secs
    } else {
        0.0
    };
    println!(
        "{name:<28} input={input_len:>7}B iters={iterations:>6} {ns_per_iter:>10.1} ns/iter {mib_s:>9.1} MiB/s"
    );
}

fn main() {
    let clean_line = "2026-06-06T12:00:00Z level=info user=guest action=list_items status=200";
    let dirty_line = "user=alice@example.com ip=203.0.113.42 card=4111 1111 1111 1111 token=AKIAIOSFODNN7EXAMPLE";
    let pem = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc123\n-----END RSA PRIVATE KEY-----\nafter";
    let large_clean = clean_line.repeat(1_000);
    let large_dirty = [dirty_line, "\n", pem, "\n"].concat().repeat(500);
    #[cfg(feature = "parallel")]
    let parallel_input = [clean_line.repeat(20_000), dirty_line.into()].concat();

    let label = Redactor::new();
    let hash = Redactor::new().mask(Mask::Hash);

    println!(
        "leakguard {} dependency-free benchmark\n",
        env!("CARGO_PKG_VERSION")
    );
    bench_case("clean line / clean", clean_line, 100_000, &label);
    bench_case("dirty line / clean", dirty_line, 100_000, &label);
    bench_case("private key / clean", pem, 50_000, &label);
    bench_case("large clean / clean", &large_clean, 1_000, &label);
    bench_case("large dirty / clean", &large_dirty, 500, &label);
    bench_case("dirty line / hash", dirty_line, 100_000, &hash);
    bench_check("clean line / check", clean_line, 100_000, &label);
    bench_check("dirty line / check", dirty_line, 100_000, &label);
    #[cfg(feature = "parallel")]
    {
        bench_case("parallel input / serial", &parallel_input, 5, &label);
        bench_parallel("parallel input / parallel", &parallel_input, 5, &label);
    }
}
