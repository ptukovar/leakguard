#![cfg(feature = "parallel")]

use leakguard::{Mask, Redactor};

fn large_input() -> String {
    let unit = concat!(
        "user=alice@example.com ip=203.0.113.42 ",
        "card=4111 1111 1111 1111 token=AKIAIOSFODNN7EXAMPLE\n",
    );
    unit.repeat(4_096)
}

#[test]
fn parallel_find_matches_serial_results() {
    let input = large_input();
    let redactor = Redactor::new();

    assert_eq!(redactor.find_parallel(&input), redactor.find(&input));
}

#[test]
fn parallel_clean_matches_serial_for_every_mask() {
    let input = large_input();
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

    for redactor in redactors {
        assert_eq!(redactor.clean_parallel(&input), redactor.clean(&input));
    }
}

#[test]
fn parallel_api_handles_small_and_empty_inputs() {
    let redactor = Redactor::new();

    assert_eq!(redactor.clean_parallel(""), "");
    assert_eq!(
        redactor.clean_parallel("alice@example.com"),
        redactor.clean("alice@example.com")
    );
}
