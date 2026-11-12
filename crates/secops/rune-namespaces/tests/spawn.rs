//! End-to-end tests: spawn real programs in real namespaces and check what
//! they can and cannot see. Each test skips (passing) when the backend
//! cannot create namespaces on this host — no `bwrap`, or unprivileged
//! user namespaces restricted.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers: a failed spawn or a bad fixture fails the test"
)]

use std::path::{Path, PathBuf};
use std::process::Output;

use rune_namespaces::{
    Backend, EnvPolicy, MaskKind, MountPlan, Namespace, NamespaceSet, Options, SeccompProgram,
    probe,
};

fn available(backend: &Backend) -> bool {
    match probe(backend) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping: {err}");
            false
        }
    }
}

fn program(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file())
}

/// Runs `name` with `args` under `options`; `None` (skip) if the program
/// is not installed.
fn run(options: &Options, name: &str, args: &[&str]) -> Option<Output> {
    let Some(path) = program(name) else {
        eprintln!("skipping: no {name}");
        return None;
    };
    Some(options.command(&path, args).unwrap().output().unwrap())
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn system() -> Options {
    Options::default().with_mounts(MountPlan::isolated().with_system_read_only())
}

/// Interface names listed in `/proc/net/dev`.
fn interfaces(text: &str) -> Vec<String> {
    text.lines()
        .skip(2)
        .filter_map(|line| line.split(':').next())
        .map(|name| name.trim().to_owned())
        .collect()
}

#[test]
fn bwrap_hides_everything_not_bound() {
    if !available(&Backend::Bwrap) {
        return;
    }
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(allowed.path().join("ok.txt"), "visible").unwrap();
    std::fs::write(outside.path().join("secret.txt"), "hidden").unwrap();
    let options = system().with_mounts(
        MountPlan::isolated()
            .with_system_read_only()
            .with_read_only(allowed.path()),
    );

    let ok = allowed.path().join("ok.txt");
    let Some(output) = run(&options, "cat", &[ok.to_str().unwrap()]) else {
        return;
    };
    assert!(output.status.success(), "{output:?}");
    assert_eq!(stdout(&output), "visible");

    let secret = outside.path().join("secret.txt");
    let output = run(&options, "cat", &[secret.to_str().unwrap()]).unwrap();
    assert!(
        !output.status.success(),
        "a path outside the plan must not exist"
    );

    // Host directories that were never bound are absent.
    let output = run(&options, "ls", &["/home", "/root", "/var"]).unwrap();
    assert!(!output.status.success());
}

#[test]
fn bwrap_read_only_binds_and_masks() {
    if !available(&Backend::Bwrap) {
        return;
    }
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    std::fs::write(root.join(".env"), "TOKEN=s3cr3t").unwrap();
    std::fs::create_dir(root.join(".ssh")).unwrap();
    std::fs::write(root.join(".ssh/id"), "key").unwrap();
    std::fs::write(root.join("ro.txt"), "ro").unwrap();
    let options = system().with_mounts(
        MountPlan::isolated()
            .with_system_read_only()
            .with_read_write(root)
            .with_read_only(root.join("ro.txt"))
            .with_mask(root.join(".env"), MaskKind::File)
            .with_mask(root.join(".ssh"), MaskKind::Dir),
    );
    let path = |p: &str| root.join(p).to_str().unwrap().to_owned();

    let Some(output) = run(&options, "cat", &[&path(".env")]) else {
        return;
    };
    // `/dev/null` bound over it: unreadable (bwrap binds are `nodev`) or
    // empty, never the secret.
    assert!(!stdout(&output).contains("s3cr3t"));

    let output = run(&options, "ls", &["-A", &path(".ssh")]).unwrap();
    assert!(output.status.success());
    assert_eq!(stdout(&output), "", "a masked directory is empty");

    let output = run(&options, "touch", &[&path(".ssh/new")]).unwrap();
    assert!(!output.status.success(), "a masked directory is read-only");

    let output = run(&options, "touch", &[&path("ro.txt")]).unwrap();
    assert!(!output.status.success(), "a read-only override must win");

    let output = run(&options, "touch", &[&path("written")]).unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        root.join("written").exists(),
        "read-write binds reach the host"
    );
    assert_eq!(
        std::fs::read_to_string(root.join(".env")).unwrap(),
        "TOKEN=s3cr3t"
    );
}

#[test]
fn bwrap_isolates_the_network() {
    if !available(&Backend::Bwrap) {
        return;
    }
    let Some(output) = run(&system(), "cat", &["/proc/net/dev"]) else {
        return;
    };
    assert!(output.status.success(), "{output:?}");
    assert_eq!(interfaces(&stdout(&output)), ["lo"]);
}

#[test]
fn bwrap_pid_namespace_and_hostname() {
    if !available(&Backend::Bwrap) {
        return;
    }
    let options = system().with_hostname("sandbox");
    let Some(output) = run(&options, "cat", &["/proc/sys/kernel/hostname"]) else {
        return;
    };
    assert_eq!(stdout(&output).trim(), "sandbox");
    // Only bwrap's init and the program itself are visible.
    let output = run(&options, "ls", &["/proc"]).unwrap();
    let pids = stdout(&output)
        .split_whitespace()
        .filter(|entry| entry.parse::<u32>().is_ok())
        .count();
    assert!(pids <= 2, "expected at most 2 processes, saw {pids}");
}

#[test]
fn bwrap_scrubs_the_environment() {
    if !available(&Backend::Bwrap) {
        return;
    }
    let options = system().with_env(EnvPolicy::default().with_set("ONLY", "this"));
    let host: Vec<(String, String)> = vec![
        ("PATH".into(), "/usr/bin".into()),
        ("SECRET".into(), "x".into()),
    ];
    let Some(env) = program("env") else {
        return;
    };
    let output = options
        .command_with_env::<&str>(&env, &[], options.env.resolve(host))
        .unwrap()
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    // bwrap itself adds PWD.
    let vars: Vec<_> = stdout(&output)
        .lines()
        .filter(|line| !line.starts_with("PWD="))
        .map(str::to_owned)
        .collect();
    assert_eq!(vars, ["ONLY=this"]);
}

/// A filter that fails `mkdir`/`mkdirat` with `EPERM` and allows the rest.
fn deny_mkdir() -> SeccompProgram {
    const LD_NR: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JEQ: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const RET: u16 = 0x06; // BPF_RET | BPF_K
    let insn = |code: u16, jt: u8, jf: u8, k: u32| {
        let mut b = code.to_ne_bytes().to_vec();
        b.extend([jt, jf]);
        b.extend(k.to_ne_bytes());
        b
    };
    let mkdirat = u32::try_from(libc::SYS_mkdirat).unwrap();
    #[cfg(target_arch = "x86_64")]
    let mkdir = u32::try_from(libc::SYS_mkdir).unwrap();
    #[cfg(not(target_arch = "x86_64"))]
    let mkdir = mkdirat;
    let bytes = [
        insn(LD_NR, 0, 0, 0),
        insn(JEQ, 2, 0, mkdirat),
        insn(JEQ, 1, 0, mkdir),
        insn(RET, 0, 0, 0x7fff_0000),     // SECCOMP_RET_ALLOW
        insn(RET, 0, 0, 0x0005_0000 | 1), // SECCOMP_RET_ERRNO | EPERM
    ]
    .concat();
    SeccompProgram::from_bytes(bytes).unwrap()
}

#[test]
fn bwrap_applies_a_seccomp_filter() {
    if !available(&Backend::Bwrap) {
        return;
    }
    let options = system().with_seccomp(deny_mkdir());
    let Some(output) = run(&options, "mkdir", &["/tmp/blocked"]) else {
        return;
    };
    assert!(!output.status.success(), "the filter must block mkdir");
    // Without the filter it works.
    let output = run(&system(), "mkdir", &["/tmp/blocked"]).unwrap();
    assert!(output.status.success(), "{output:?}");
}

fn unshare() -> Options {
    Options::default()
        .with_backend(Backend::Unshare)
        .with_mounts(MountPlan::new())
        .with_namespaces(NamespaceSet::ALL.without(Namespace::Pid))
}

#[test]
fn unshare_isolates_network_and_hostname() {
    if !available(&Backend::Unshare) {
        return;
    }
    let options = unshare().with_hostname("sandbox");
    let Some(output) = run(&options, "cat", &["/proc/net/dev"]) else {
        return;
    };
    assert!(output.status.success(), "{output:?}");
    assert_eq!(interfaces(&stdout(&output)), ["lo"]);
    let output = run(&options, "cat", &["/proc/sys/kernel/hostname"]).unwrap();
    assert_eq!(stdout(&output).trim(), "sandbox");
}

#[test]
fn unshare_applies_a_seccomp_filter() {
    if !available(&Backend::Unshare) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("blocked");
    let options = unshare().with_seccomp(deny_mkdir());
    let Some(output) = run(&options, "mkdir", &[target.to_str().unwrap()]) else {
        return;
    };
    assert!(!output.status.success());
    assert!(!target.exists());
}

#[test]
fn probe_reports_a_missing_bwrap() {
    let err = probe(&Backend::BwrapAt("/nonexistent/bwrap".into())).unwrap_err();
    assert!(
        matches!(err, rune_namespaces::Error::BwrapNotFound { .. }),
        "{err:?}"
    );
}
