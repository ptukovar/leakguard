//! No-dependency benchmark harness for leakguard.
//!
//!     cargo run --release --example bench
//!
//! Prints MiB/s throughput for serial (and parallel, when the `parallel`
//! feature is enabled) on a synthetic 8 MiB clean log payload, comparing
//! against the v0.8.1 baselines (serial ≥ 93.4 MiB/s, parallel ≥ 316.5 MiB/s).
//!
//! The "clean fast path" (`is_dirty` on a truly clean input) reuses a single
//! Vec across all detectors and therefore performs zero heap allocations after
//! the first warm-up call. This property is verified by code review of
//! `Redactor::is_dirty` and `find_raw` in `src/lib.rs`; an external tool such
//! as `valgrind --tool=callgrind` can confirm at runtime.

use std::hint::black_box;
use std::time::{Duration, Instant};

use leakguard::{Mask, Redactor};

fn bench(name: &str, input: &str, iters: usize, r: &Redactor) {
    let start = Instant::now();
    let mut bytes = 0usize;
    for _ in 0..iters {
        let out = r.clean(black_box(input));
        bytes += out.len();
        black_box(out);
    }
    emit(name, input.len(), iters, bytes, start.elapsed());
}

fn bench_check(name: &str, input: &str, iters: usize, r: &Redactor) {
    let start = Instant::now();
    let mut n = 0usize;
    for _ in 0..iters {
        if r.is_dirty(black_box(input)) {
            n += 1;
        }
    }
    black_box(n);
    emit(
        name,
        input.len(),
        iters,
        input.len() * iters,
        start.elapsed(),
    );
}

fn emit(name: &str, input_len: usize, iters: usize, bytes: usize, elapsed: Duration) {
    let secs = elapsed.as_secs_f64();
    let ns_per = elapsed.as_nanos() as f64 / iters as f64;
    let mibs = if secs > 0.0 {
        bytes as f64 / 1048576.0 / secs
    } else {
        0.0
    };
    println!("{name:<32} input={input_len:>8}B iters={iters:>6} {ns_per:>10.1} ns/iter {mibs:>9.1} MiB/s");
}

fn make_8mib_payload() -> String {
    const LINE: &str = "Jun 12 14:23:45 hostname service[1234]: INFO request_id=abc-123 user=guest action=view path=/api/status latency=42ms";
    LINE.repeat((8 * 1024 * 1024) / 92 + 1)
}

fn main() {
    let clean_line = "2026-06-06T12:00:00Z level=info user=guest action=list_items status=200";
    let dirty_line = "user=alice@example.com ip=203.0.113.42 card=4111 1111 1111 1111 token=AKIAIOSFODNN7EXAMPLE";
    let pem_input = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc123\n-----END RSA PRIVATE KEY-----\nafter";

    let large_clean = clean_line.repeat(1_000);
    let large_dirty = [dirty_line, "\n", pem_input, "\n"].concat().repeat(500);

    let payload_8mib = make_8mib_payload();

    let r = Redactor::new();
    let rh = Redactor::new().mask(Mask::Hash);

    println!(
        "leakguard {} dependency-free benchmark\n",
        env!("CARGO_PKG_VERSION")
    );

    bench("clean line / clean", clean_line, 100_000, &r);
    bench("dirty line / clean", dirty_line, 100_000, &r);
    bench("private key / clean", pem_input, 50_000, &r);
    bench("large clean / clean", &large_clean, 1_000, &r);
    bench("large dirty / clean", &large_dirty, 500, &r);
    bench("dirty line / hash", dirty_line, 100_000, &rh);
    bench_check("clean line / check", clean_line, 100_000, &r);
    bench_check("dirty line / check", dirty_line, 100_000, &r);

    println!();
    println!("--- 8 MiB clean payload ---");

    let iters = 8;
    let s_start = Instant::now();
    for _ in 0..iters {
        black_box(r.clean(black_box(&payload_8mib)));
    }
    let s_elapsed = s_start.elapsed();
    let s_secs = s_elapsed.as_secs_f64();
    let s_mibs = (payload_8mib.len() as f64 * iters as f64) / 1048576.0 / s_secs;
    println!(
        "{:<32} input={:>8}B iters={:>6} {:>10.1} ns/iter {:>9.1} MiB/s",
        "8 MiB clean / serial",
        payload_8mib.len(),
        iters,
        s_elapsed.as_nanos() as f64 / iters as f64,
        s_mibs
    );

    let baseline_s = 93.4;
    if s_mibs >= baseline_s {
        println!("  serial {:.1} MiB/s >= {:.1}  PASS", s_mibs, baseline_s);
    } else {
        println!("  serial {:.1} MiB/s < {:.1}  FAIL", s_mibs, baseline_s);
    }

    #[cfg(feature = "parallel")]
    {
        let p_start = Instant::now();
        for _ in 0..iters {
            black_box(r.clean_parallel(black_box(&payload_8mib)));
        }
        let p_elapsed = p_start.elapsed();
        let p_secs = p_elapsed.as_secs_f64();
        let p_mibs = (payload_8mib.len() as f64 * iters as f64) / 1048576.0 / p_secs;
        println!(
            "{:<32} input={:>8}B iters={:>6} {:>10.1} ns/iter {:>9.1} MiB/s",
            "8 MiB clean / parallel",
            payload_8mib.len(),
            iters,
            p_elapsed.as_nanos() as f64 / iters as f64,
            p_mibs
        );

        let baseline_p = 316.5;
        if p_mibs >= baseline_p {
            println!("  parallel {:.1} MiB/s >= {:.1}  PASS", p_mibs, baseline_p);
        } else {
            println!("  parallel {:.1} MiB/s < {:.1}  FAIL", p_mibs, baseline_p);
        }
    }
}
