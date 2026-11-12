//! Real, bwrap-backed end-to-end tests for the core enforcement claims.
//!
//! Everything in `src/sandbox.rs`'s unit tests only checks the argument
//! *vector* `build_bwrap_args` produces — never that bwrap, given those
//! arguments, actually enforces anything. These tests run a real
//! sandboxed process and assert on its real, observed behavior. Skipped
//! (not failed) on a host without bwrap or without working unprivileged
//! user namespaces, since both are legitimate CI/container states — see
//! `skip_if_unavailable`.

// Test helpers outside `#[test]` fns are not covered by clippy.toml's
// allow-*-in-tests; a failed setup step should abort the test loudly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::process::Output;

use rune_secops_warden::{
    CommandRef, CommandsSection, EnvSection, FilesystemSection, Network, PathEntry, Policy,
    SandboxSection, audit_log_path, build_command, preflight, summarize_audit_log,
};

/// Returns `true` (and prints why) if this host can't run real sandboxes,
/// so tests can skip instead of failing on environments where that's
/// expected (containers without user namespaces, CI without bwrap, ...).
fn skip_if_unavailable() -> bool {
    if let Err(err) = preflight() {
        eprintln!("skipping: sandbox preflight failed on this host: {err}");
        return true;
    }
    false
}

fn run(policy: &Policy, program: &str, args: &[&str]) -> Output {
    let args: Vec<String> = args.iter().map(std::string::ToString::to_string).collect();
    let mut command = build_command(policy, program, &args).expect("policy should build");
    command.output().expect("sandboxed process should spawn")
}

fn scratch_dir(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "rune-secops-warden-e2e-{name}-{}-{nanos}",
        std::process::id(),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn base_policy(project_dir: &std::path::Path) -> Policy {
    Policy {
        sandbox: SandboxSection {
            cwd: Some(project_dir.to_path_buf()),
            // `sandbox.landlock`'s stub protocol requires the calling
            // process to call `run_stub_if_invoked()` at the top of its
            // own `main()` (see that function's docs) — true for a real
            // CLI built on this crate, not true for `cargo test`'s own
            // generated harness binary, which is what's actually calling
            // `build_command` in every other test in this file. Landlock
            // itself is already covered by its own dedicated tests in
            // `landlock_layer.rs` and — through a real bwrap sandbox, via
            // a binary that *does* implement the protocol — by
            // `landlock_stub_runs_the_real_program_through_a_real_sandbox`
            // below; every other test here exists to check bwrap's own
            // mechanisms and shouldn't also need to stand up that
            // protocol just to run at all.
            landlock: false,
            ..SandboxSection::default()
        },
        filesystem: FilesystemSection {
            read_write: vec![PathEntry {
                path: project_dir.to_path_buf(),
                mount_as: None,
                create: None,
                create_content: None,
                acknowledge_executable_content: false,
            }],
            ..FilesystemSection::default()
        },
        env: EnvSection {
            allow: vec![],
            set: std::iter::once(("PATH".to_string(), "/usr/bin:/bin".to_string())).collect(),
        },
        commands: CommandsSection {
            allow: vec![
                CommandRef::Name("sh".to_string()),
                CommandRef::Name("cat".to_string()),
            ],
        },
        ..Policy::default()
    }
}

#[test]
fn unbound_host_file_is_unreachable() {
    if skip_if_unavailable() {
        return;
    }
    let project = scratch_dir("unbound-file");
    let policy = base_policy(&project);

    // /etc/hostname exists on essentially every real Linux host and is
    // never bound by this policy — it must not be readable.
    let output = run(&policy, "cat", &["/etc/hostname"]);
    assert!(
        !output.status.success(),
        "reading an unbound host file should fail, got: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No such file") || stderr.contains("not found"),
        "expected an ENOENT-shaped error, got: {stderr}"
    );
}

#[test]
fn audit_log_reports_a_real_blocked_access() {
    if skip_if_unavailable() {
        return;
    }
    if Command::new("strace").arg("-V").output().is_err() {
        eprintln!("skipping: strace not available on this host");
        return;
    }
    let project = scratch_dir("audit");
    let mut policy = base_policy(&project);
    policy.audit.enabled = true;

    // Same unbound-file scenario as `unbound_host_file_is_unreachable` —
    // the point here isn't that it's blocked (already covered there),
    // it's that the audit log says so in a readable way.
    let output = run(&policy, "cat", &["/etc/hostname"]);
    assert!(!output.status.success());

    let summary = summarize_audit_log(&audit_log_path());
    assert!(
        summary
            .iter()
            .any(|line| line.contains("/etc/hostname") && line.contains("ENOENT")),
        "expected the audit summary to name the blocked path and errno, got: {summary:?}"
    );
}

#[test]
fn bound_read_write_directory_is_readable_and_writable() {
    if skip_if_unavailable() {
        return;
    }
    let project = scratch_dir("bound-rw");
    std::fs::write(project.join("hello.txt"), "hi from the host").unwrap();
    let policy = base_policy(&project);

    let read = run(
        &policy,
        "cat",
        &[project.join("hello.txt").to_str().unwrap()],
    );
    assert!(read.status.success(), "expected read to succeed: {read:?}");
    assert_eq!(
        String::from_utf8_lossy(&read.stdout).trim(),
        "hi from the host"
    );

    let write_target = project.join("written-from-sandbox.txt");
    let write = run(
        &policy,
        "sh",
        &[
            "-c",
            &format!("echo written > {}", write_target.to_str().unwrap()),
        ],
    );
    assert!(
        write.status.success(),
        "expected write to succeed: {write:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&write_target).unwrap().trim(),
        "written"
    );
}

#[test]
fn command_outside_the_whitelist_is_unreachable_even_by_absolute_path() {
    if skip_if_unavailable() {
        return;
    }
    let project = scratch_dir("unlisted-command");
    let policy = base_policy(&project); // commands.allow = [sh, cat] only

    // `id` is essentially always present at one of these paths but was
    // never added to commands.allow — it must not be executable, whether
    // bare or by the absolute path it lives at on the host.
    for candidate in ["/usr/bin/id", "/bin/id"] {
        if !std::path::Path::new(candidate).is_file() {
            continue;
        }
        let output = run(&policy, "sh", &["-c", candidate]);
        assert!(
            !output.status.success(),
            "expected {candidate} to be unreachable, got: {output:?}"
        );
        return;
    }
}

#[test]
fn deny_entry_masks_a_path_within_an_otherwise_bound_directory() {
    if skip_if_unavailable() {
        return;
    }
    let project = scratch_dir("deny-entry");
    std::fs::write(project.join("secret.env"), "API_KEY=shh").unwrap();
    let mut policy = base_policy(&project);
    policy.filesystem.deny.push(rune_secops_warden::DenyEntry {
        path: project.join("secret.env"),
    });

    let output = run(
        &policy,
        "cat",
        &[project.join("secret.env").to_str().unwrap()],
    );
    assert!(
        !output.status.success(),
        "denied file should be unreadable even though its parent dir is bound, got: {output:?}"
    );
}

#[test]
fn read_only_override_survives_a_writable_parent_directory() {
    if skip_if_unavailable() {
        return;
    }
    let project = scratch_dir("read-only-override");
    let control_file = project.join("settings.json");
    std::fs::write(&control_file, r#"{"hooks":[]}"#).unwrap();

    let mut policy = base_policy(&project);
    policy.filesystem.read_only_override.push(PathEntry {
        path: control_file.clone(),
        mount_as: None,
        create: None,
        create_content: None,
        acknowledge_executable_content: false,
    });

    // Regression test for the exact shape of a real, disclosed
    // vulnerability class (Claude Code sandbox escape, CVE-2026-25725):
    // a sandboxed process must not be able to rewrite a control file a
    // *future, possibly unsandboxed* process will trust, even though the
    // file lives inside an otherwise-writable directory.
    let write = run(
        &policy,
        "sh",
        &[
            "-c",
            &format!(
                "echo '{{\"hooks\":[\"evil\"]}}' > {}",
                control_file.to_str().unwrap()
            ),
        ],
    );
    assert!(
        !write.status.success(),
        "writing to a read_only_override path must fail even though its parent is read-write, got: {write:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&control_file).unwrap(),
        r#"{"hooks":[]}"#,
        "the control file's real content must be unchanged"
    );

    // The rest of the writable parent directory must still work normally
    // — this isn't a blanket lockdown of `.claude`, just the one file.
    let sibling = project.join("session-transcript.txt");
    let sibling_write = run(
        &policy,
        "sh",
        &["-c", &format!("echo ok > {}", sibling.to_str().unwrap())],
    );
    assert!(
        sibling_write.status.success(),
        "writes elsewhere in the same read-write directory must still succeed, got: {sibling_write:?}"
    );
}

#[test]
fn network_none_blocks_dns_resolution() {
    if skip_if_unavailable() {
        return;
    }
    let project = scratch_dir("network-none");
    let mut policy = base_policy(&project);
    policy.sandbox.network = Network::None;
    policy
        .commands
        .allow
        .push(CommandRef::Name("getent".to_string()));

    if Command::new("getent").arg("--version").output().is_err() {
        eprintln!("skipping: getent not available on this host");
        return;
    }

    let output = run(&policy, "getent", &["hosts", "localhost"]);
    // With the network namespace fully unshared there's no loopback
    // route configured, so even resolving "localhost" fails — this is
    // the strongest single signal that networking is actually cut off,
    // not just firewalled.
    assert!(
        !output.status.success(),
        "expected DNS/hosts resolution to fail with network=none, got: {output:?}"
    );
}

/// Tests that drive the `landlock-e2e-helper` binary, which is built only
/// with the `e2e-helper` feature (CI tests with `--all-features`).
#[cfg(feature = "e2e-helper")]
mod helper_binary {
    use super::*;

    /// The one test in this file exercising `sandbox.landlock = true` — see
    /// `base_policy`'s doc comment for why every other test here disables it,
    /// and `landlock_layer.rs`'s own unit tests for the sharper
    /// defense-in-depth proof (Landlock alone, no mount namespace at all).
    /// This test's job is narrower and different: confirm the *whole real
    /// pipeline* — binding the stub binary and its shared-library closure
    /// into the sandbox, bwrap constructing the sandbox normally, the stub
    /// applying Landlock from inside it, and finally exec'ing the real
    /// program — actually works end to end through a genuine `bwrap`
    /// process, not just that its individual pieces work in isolation.
    ///
    /// Runs `landlock-e2e-helper` (see its own module docs) as a real
    /// *subprocess* rather than calling `build_command` in this test process
    /// directly, unlike every other test in this file — deliberately: this
    /// is the one case where that distinction matters.
    /// `std::env::current_exe()` (see `run_stub_if_invoked`'s docs) resolves
    /// to whichever process *calls* `build_command`, and `cargo test`'s own
    /// harness binary — what every other test's in-process `run()` call
    /// leaves as that caller — doesn't implement the stub protocol. The
    /// helper binary does, so it has to be the one making the call.
    #[test]
    fn landlock_stub_runs_the_real_program_through_a_real_sandbox() {
        if skip_if_unavailable() {
            return;
        }
        let project = scratch_dir("landlock-stub");
        let helper = env!("CARGO_BIN_EXE_landlock-e2e-helper");
        let visible = project.join("visible.txt");
        std::fs::write(&visible, "landlock stub reached the real program").unwrap();

        let output = Command::new(helper)
            .arg("supervise")
            .arg(&project)
            .arg(&visible)
            .output()
            .expect("supervisor helper should spawn");
        assert!(
            output.status.success(),
            "the real program should run to completion inside the sandbox with landlock enabled, got: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "landlock stub reached the real program",
            "stdout should be exactly the file's content, proving the stub actually exec'd the real \
             program (rather than, say, silently swallowing it and exiting 0 on its own)"
        );
    }

    /// `network.allowed_domains` end to end: a real sandboxed process, with
    /// no network namespace access of any kind, reaching an allowed
    /// destination through the whole real pipeline (host-side CONNECT proxy
    /// on a Unix socket, that socket bind-mounted in, the in-sandbox relay
    /// forked from the stub, `HTTP_PROXY` pointed at it automatically) and
    /// getting refused for a disallowed one — using the exact same helper
    /// process/subprocess pattern and rationale as
    /// `landlock_stub_runs_the_real_program_through_a_real_sandbox` above.
    #[test]
    fn network_allowed_domains_permits_allowed_and_blocks_disallowed() {
        if skip_if_unavailable() {
            return;
        }
        let helper = env!("CARGO_BIN_EXE_landlock-e2e-helper");

        // Stands in for "the allowed destination": a real TCP listener that
        // echoes back whatever it receives, reachable only through the
        // proxy once the sandbox's real network namespace is unshared.
        let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut stream in echo.incoming().flatten() {
                use std::io::{Read, Write};
                let mut buf = [0u8; 4];
                if stream.read_exact(&mut buf).is_ok() {
                    let _ = stream.write_all(&buf);
                }
            }
        });
        let target = format!("127.0.0.1:{echo_port}");

        let allowed = Command::new(helper)
            .args(["supervise-network", "127.0.0.1", &target])
            .output()
            .expect("supervisor helper should spawn");
        assert!(
            allowed.status.success(),
            "allowed-domain run should succeed, got: {allowed:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&allowed.stdout).trim(),
            "ALLOWED ping",
            "an allowed domain should reach the real destination and echo back the real payload, \
             proving actual bytes flowed through the whole proxy/relay chain, not just that the \
             CONNECT was accepted"
        );

        let denied = Command::new(helper)
            .args(["supervise-network", "totally-different.example", &target])
            .output()
            .expect("supervisor helper should spawn");
        assert!(
            String::from_utf8_lossy(&denied.stdout)
                .trim()
                .starts_with("DENIED"),
            "a domain not in allowed_domains must be refused by the proxy, got: {denied:?}"
        );
    }

    /// `network.allowed_ips` end to end, through the same real pipeline as
    /// the domain test above: a CIDR range (not just an exact address)
    /// permits a real sandboxed process to reach a target by bare IP, and a
    /// bare IP outside every configured range is refused — proving the
    /// bare-IP branch in `network_proxy::handle_connect` actually runs inside
    /// a real sandbox, not just in the unit tests that exercise its matching
    /// logic in isolation.
    #[test]
    fn network_allowed_ips_permits_a_cidr_range_and_blocks_outside_it() {
        if skip_if_unavailable() {
            return;
        }
        let helper = env!("CARGO_BIN_EXE_landlock-e2e-helper");

        let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut stream in echo.incoming().flatten() {
                use std::io::{Read, Write};
                let mut buf = [0u8; 4];
                if stream.read_exact(&mut buf).is_ok() {
                    let _ = stream.write_all(&buf);
                }
            }
        });
        let target = format!("127.0.0.1:{echo_port}");

        // A /8 CIDR range, not the exact address — proving prefix matching,
        // not just exact-string comparison, is what's actually enforced.
        let allowed = Command::new(helper)
            .args(["supervise-network", "127.0.0.0/8", &target])
            .output()
            .expect("supervisor helper should spawn");
        assert!(
            allowed.status.success(),
            "a target covered by an allowed_ips CIDR range should succeed, got: {allowed:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&allowed.stdout).trim(),
            "ALLOWED ping",
            "should reach the real destination and echo back the real payload through the whole \
             proxy/relay chain"
        );

        // A disjoint /32 that doesn't cover 127.0.0.1 at all.
        let denied = Command::new(helper)
            .args(["supervise-network", "10.0.0.5/32", &target])
            .output()
            .expect("supervisor helper should spawn");
        assert!(
            String::from_utf8_lossy(&denied.stdout)
                .trim()
                .starts_with("DENIED"),
            "a bare-IP target outside every allowed_ips range must be refused, got: {denied:?}"
        );
    }

    /// The DNS-rebinding-protection path specifically: a real hostname
    /// ("localhost") allowed via `allowed_domains`, resolved through the
    /// actual host resolver (not a synthetic address, unlike the
    /// `pick_allowed_addr` unit tests) to a loopback address. Refused by
    /// default even though the domain itself is allowed, and permitted once
    /// `allowed_ips` explicitly covers the resolved address — proving
    /// `network_proxy::resolve_allowed_addr`'s real `to_socket_addrs()` call
    /// and the selection rule built on it actually run end to end inside a
    /// real sandbox, not just against synthetic `SocketAddr`s in isolation.
    #[test]
    fn network_allowed_domain_resolving_to_loopback_requires_explicit_allowed_ips() {
        if skip_if_unavailable() {
            return;
        }
        let helper = env!("CARGO_BIN_EXE_landlock-e2e-helper");

        let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut stream in echo.incoming().flatten() {
                use std::io::{Read, Write};
                let mut buf = [0u8; 4];
                if stream.read_exact(&mut buf).is_ok() {
                    let _ = stream.write_all(&buf);
                }
            }
        });
        let target = format!("localhost:{echo_port}");

        // "localhost" is allowed, but nothing in allowed_ips covers where it
        // actually resolves to — must be refused, not silently permitted just
        // because the domain matched.
        let denied = Command::new(helper)
            .args(["supervise-network", "localhost", &target])
            .output()
            .expect("supervisor helper should spawn");
        assert!(
            String::from_utf8_lossy(&denied.stdout)
                .trim()
                .starts_with("DENIED"),
            "an allowed domain resolving only to a private/loopback address must be refused without \
             an explicit allowed_ips override, got: {denied:?}"
        );

        // Same allowed domain, now with the resolved address's range covered
        // by allowed_ips too — the explicit opt-in this protection exists to
        // require. Both loopback ranges are listed since which address
        // family "localhost" resolves to first isn't guaranteed.
        let allowed = Command::new(helper)
            .args([
                "supervise-network",
                "localhost",
                &target,
                "127.0.0.0/8",
                "::1/128",
            ])
            .output()
            .expect("supervisor helper should spawn");
        assert!(
            allowed.status.success(),
            "the same target should succeed once allowed_ips explicitly covers the resolved \
             loopback address, got: {allowed:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&allowed.stdout).trim(),
            "ALLOWED ping"
        );
    }
}
