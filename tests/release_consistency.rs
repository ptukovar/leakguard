const README: &str = include_str!("../README.md");

#[test]
fn package_version_matches_readme_install_snippet() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "1.0.0");
    assert!(
        README
            .lines()
            .any(|line| line.trim() == "leakguard = \"1.0.0\""),
        "README library install snippet must match the package version"
    );
}
