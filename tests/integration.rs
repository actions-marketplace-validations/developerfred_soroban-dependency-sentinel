use assert_cmd::Command;

#[test]
fn scan_help_runs() {
    Command::cargo_bin("sentinel")
        .unwrap()
        .args(["scan", "--help"])
        .assert()
        .success();
}

#[test]
fn scan_json_on_empty_dir() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("sentinel")
        .unwrap()
        .args(["scan", "--path"])
        .arg(dir.path())
        .args(["--format", "json"])
        .assert()
        .success();
}

#[test]
fn detects_known_cve_in_vulnerable_fixture() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/vulnerable-project");
    if !fixture.join("Cargo.lock").exists() {
        eprintln!("skipping: fixture Cargo.lock not present");
        return;
    }

    let out = Command::cargo_bin("sentinel")
        .unwrap()
        .args(["scan", "--path"])
        .arg(&fixture)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "scan should succeed");

    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = json.as_array().expect("expected array");
    let vuln_count: usize = arr
        .iter()
        .map(|r| {
            r.get("vulnerabilities")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        })
        .sum();
    assert!(
        vuln_count > 0,
        "expected at least one CVE, got {vuln_count}"
    );
}

#[test]
fn fail_on_watch_exits_nonzero_when_cve_present() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/vulnerable-project");
    if !fixture.join("Cargo.lock").exists() {
        return;
    }

    Command::cargo_bin("sentinel")
        .unwrap()
        .args(["scan", "--path"])
        .arg(&fixture)
        .args(["--format", "text", "--fail-on", "watch"])
        .assert()
        .failure();
}
