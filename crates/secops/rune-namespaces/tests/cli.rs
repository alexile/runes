//! Tests for the `rune-namespaces` CLI, built only with the `cli` feature.

#![cfg(feature = "cli")]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_rune-namespaces");

#[test]
fn print_args_shows_the_plan_in_order() {
    let output = Command::new(BIN)
        .args([
            "--ro",
            "/usr",
            "--rw",
            "/work",
            "--print-args",
            "--",
            "ls",
            "-l",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let args = String::from_utf8(output.stdout).unwrap();
    let tmpfs_root = args.find("--tmpfs / ").unwrap();
    let proc = args.find("--proc /proc").unwrap();
    let bind = args.find("--bind /work /work").unwrap();
    assert!(tmpfs_root < proc && proc < bind, "{args}");
    assert!(args.contains("--unshare-net"));
    assert!(args.trim_end().ends_with("-- ls -l"), "{args}");
}

#[test]
fn share_net_keeps_the_network() {
    let output = Command::new(BIN)
        .args(["--share-net", "--print-args", "--", "true"])
        .output()
        .unwrap();
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("--unshare-net")
    );
}

#[test]
fn invalid_options_exit_125() {
    let output = Command::new(BIN)
        .args(["--backend", "unshare", "--ro", "/usr", "--", "true"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
}

#[test]
fn probe_answers() {
    let output = Command::new(BIN).arg("--probe").output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("namespaces: "), "{stdout}");
}
