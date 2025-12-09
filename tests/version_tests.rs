use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn kevi_version_reports_build_metadata() {
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.arg("--version");
    // Clap prints the long_version when --version is used; ensure key fields exist
    cmd.assert().success().stdout(
        predicate::str::contains("version:")
            .and(predicate::str::contains("git sha:"))
            .and(predicate::str::contains("build time (UTC):"))
            .and(predicate::str::contains("target:"))
            .and(predicate::str::contains("features:")),
    );
}
