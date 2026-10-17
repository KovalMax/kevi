#[test]
fn release_workflow_validates_stable_exact_tag_and_merges_before_signing() {
    let workflow = include_str!("../.github/workflows/release.yml").replace("\r\n", "\n");
    let third_party_uses = workflow
        .lines()
        .filter_map(|line| line.trim().strip_prefix("uses: "))
        .collect::<Vec<_>>();
    assert!(!third_party_uses.is_empty());
    for action in third_party_uses {
        let (reference, comment) = action.split_once(" # ").unwrap_or((action, ""));
        let (_, sha) = reference.rsplit_once('@').expect("action reference has @");
        assert_eq!(sha.len(), 40, "action must use a full commit SHA: {action}");
        assert!(sha.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(
            !comment.is_empty(),
            "action pin should retain a readable ref: {action}"
        );
    }
    let tag_check = workflow
        .find("^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")
        .unwrap();
    let package_match = workflow.find("[[ \"$tag\" == \"v$version\" ]]").unwrap();
    let assembly = workflow.find("Assemble final checksums").unwrap();
    let signing = workflow
        .find("Sign final checksum manifest when configured")
        .unwrap();
    let publish = workflow.find("Publish release assets").unwrap();
    let key_detection = workflow.find("Detect configured signing key").unwrap();
    let install = workflow.find("Install minisign").unwrap();
    assert!(
        tag_check < package_match
            && package_match < assembly
            && assembly < signing
            && signing < publish
    );
    assert!(assembly < key_detection && key_detection < install && install < signing);
    assert!(workflow.contains("sha256sum \"${files[@]}\" > SHA256SUMS.txt"));
    assert!(workflow
        .contains("minisign -S -s \"$keyfile\" -m SHA256SUMS.txt -x SHA256SUMS.txt.minisig"));
    assert!(workflow.contains("UNSIGNED: no signing key was configured"));
    assert!(workflow.contains("echo 'configured=false' >> \"$GITHUB_OUTPUT\""));
    assert!(workflow.contains("echo 'configured=true' >> \"$GITHUB_OUTPUT\""));
    assert!(workflow.contains(
        "if: steps.signing-key.outputs.configured == 'true'\n        uses: taiki-e/install-action"
    ));
    assert!(workflow
        .contains("if: steps.signing-key.outputs.configured == 'true'\n        shell: bash"));
    assert!(workflow.contains("if [[ -n \"$MINISIGN_SECRET_KEY\" ]]; then"));
    assert!(workflow.contains("SIGNING CONFIGURED: signature asset accompanies SHA256SUMS.txt."));
    assert!(workflow.contains("test -s SHA256SUMS.txt.minisig"));
    assert!(workflow.contains("dist/SHA256SUMS.txt*"));
    assert!(workflow.contains("shopt -s nullglob"));
    assert!(workflow.contains("set -euo pipefail"));
    assert!(workflow.contains("sbom.json"));
    assert!(!workflow.contains("dist/SHA256SUMS.txt.minisig"));
    assert!(workflow.contains("kevi-windows-${{ runner.arch }}.zip"));
    assert!(workflow.contains("kevi-macos-${{ runner.arch }}.tar.gz"));
    assert!(workflow.contains("kevi-linux-${{ runner.arch }}.tar.gz"));
    assert!(workflow.contains("needs: build-release"));
    assert!(workflow.contains("RELEASE-SIGNATURE-STATUS.txt"));
    assert!(workflow.contains("chmod 600 \"$keyfile\""));
    assert!(workflow.contains("trap 'rm -f \"$keyfile\"' EXIT"));
}

#[test]
fn dependency_audit_is_blocking_and_does_not_publish_with_a_github_token() {
    let workflow = include_str!("../.github/workflows/audit.yml").replace("\r\n", "\n");

    assert!(workflow.contains("pull_request:\n    paths:"));
    assert!(workflow.contains("- '.github/workflows/audit.yml'"));
    assert!(workflow.contains("permissions:\n  contents: read"));
    assert!(!workflow.contains("contents: write"));
    assert!(!workflow.contains("permissions: write-all"));
    assert!(workflow.contains("cargo install cargo-audit --version 0.22.0 --locked"));
    assert!(workflow.contains("cargo audit\n"));
    assert!(!workflow.contains("rustsec/audit-check"));
    assert!(!workflow.contains("secrets.GITHUB_TOKEN"));
}
