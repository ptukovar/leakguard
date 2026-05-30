//! Run with: `cargo run --example redact_logs`
//!
//! Demonstrates the library API on a few realistic log lines.

use leakguard::{Kind, Mask, Redactor};

fn main() {
    let logs = [
        "2026-05-30T10:00:01Z user=alice@example.com ip=203.0.113.42 action=login",
        "payment ok card=4111 1111 1111 1111 amount=42.00",
        "git clone https://deploy:s3cr3t@github.com/acme/app.git",
        "auth header: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123",
        "device 00:1A:2B:3C:4D:5E reported ssn 123-45-6789",
        "aws creds AKIAIOSFODNN7EXAMPLE rotated",
        "ci token ghp_1234567890abcdefghijklmnopqrstuvwxyz used",
        "charge stripe sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH ok",
        "payout iban DE89370400440532013000 confirmed",
        "support call +1 (415) 555-0132 logged",
    ];

    println!("=== default (label) mask ===");
    let s = Redactor::new();
    for line in &logs {
        println!("{}", s.clean(line));
    }

    println!("\n=== partial mask (keep last 4) ===");
    let s = Redactor::new().mask(Mask::Partial {
        keep_last: 4,
        ch: '*',
    });
    for line in &logs {
        println!("{}", s.clean(line));
    }

    println!("\n=== only emails + IPs, hashed ===");
    let s = Redactor::only(&[Kind::Email, Kind::IpV4]).mask(Mask::Hash);
    for line in &logs {
        println!("{}", s.clean(line));
    }
}
