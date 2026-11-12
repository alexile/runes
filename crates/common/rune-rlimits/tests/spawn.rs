//! End-to-end tests: apply limits to real child processes and read them
//! back. Tests that need `/proc/self/limits` or a particular program skip
//! (passing) when it is missing.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers: a failed spawn or a bad fixture fails the test"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use rune_rlimits::{LimitSet, Limits, Resource, Rlimit, Value, get, parse_proc_limits, set};

fn program(name: &str) -> Option<PathBuf> {
    let found = ["/usr/bin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file());
    if found.is_none() {
        eprintln!("skipping: no {name}");
    }
    found
}

/// The limits a child spawned under `set` reports in `/proc/self/limits`,
/// or `None` (skip) where that file or `cat` does not exist.
fn child_limits(set: &LimitSet) -> Option<Vec<(Resource, Rlimit)>> {
    if !Path::new("/proc/self/limits").exists() {
        eprintln!("skipping: no /proc/self/limits");
        return None;
    }
    let mut command = Command::new(program("cat")?);
    command.arg("/proc/self/limits");
    set.apply_to(&mut command);
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    Some(parse_proc_limits(&String::from_utf8(output.stdout).unwrap()).unwrap())
}

fn lookup(limits: &[(Resource, Rlimit)], resource: Resource) -> Option<Rlimit> {
    limits.iter().find(|(r, _)| *r == resource).map(|(_, l)| *l)
}

#[test]
fn child_sees_every_requested_limit() {
    // Lower than any sane default, and within the current hard limits.
    let requested = LimitSet::new()
        .with_cpu_seconds(100)
        .with_address_space_bytes(4 << 30)
        .with_file_size_bytes(1 << 30)
        .with(Resource::NoFile, Rlimit::new(64, 128).unwrap())
        .with_processes(4096)
        .without_core_dumps()
        .clamped_to_current()
        .unwrap();
    let Some(seen) = child_limits(&requested) else {
        return;
    };
    for (resource, limit) in requested.iter() {
        assert_eq!(lookup(&seen, resource), Some(limit), "{resource}");
    }
}

#[test]
fn flat_limits_reach_the_child() {
    let limits = Limits {
        max_open_files: Some(100),
        max_file_size_mb: Some(1),
        ..Limits::default()
    };
    let set = LimitSet::from(&limits).clamped_to_current().unwrap();
    let Some(seen) = child_limits(&set) else {
        return;
    };
    assert_eq!(lookup(&seen, Resource::NoFile), set.get(Resource::NoFile));
    assert_eq!(
        lookup(&seen, Resource::FileSize),
        set.get(Resource::FileSize)
    );
}

#[test]
fn proc_table_agrees_with_getrlimit() {
    let Ok(text) = std::fs::read_to_string("/proc/self/limits") else {
        eprintln!("skipping: no /proc/self/limits");
        return;
    };
    // Resources no test in this binary changes.
    for (resource, limit) in parse_proc_limits(&text).unwrap() {
        if matches!(
            resource,
            Resource::Stack | Resource::Data | Resource::NoFile
        ) {
            assert_eq!(get(resource).unwrap(), limit, "{resource}");
        }
    }
}

#[test]
fn empty_set_spawns_normally() {
    let Some(path) = program("true") else {
        return;
    };
    let mut command = Command::new(path);
    LimitSet::new().apply_to(&mut command);
    assert!(command.status().unwrap().success());
}

#[test]
fn cpu_limit_kills_a_spinning_child() {
    let Some(sh) = program("sh") else {
        return;
    };
    let mut command = Command::new(sh);
    command.args(["-c", "while :; do :; done"]);
    LimitSet::new().with_cpu_seconds(1).apply_to(&mut command);
    let status = command.status().unwrap();
    assert!(
        !status.success(),
        "a process exceeding RLIMIT_CPU should be killed"
    );
}

#[test]
fn file_size_limit_stops_a_large_write() {
    let (Some(sh), Some(_)) = (program("sh"), program("head")) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("big");
    let mut command = Command::new(sh);
    command.args([
        "-c",
        &format!("head -c 65536 /dev/zero > '{}'", file.display()),
    ]);
    LimitSet::new()
        .with_file_size_bytes(4096)
        .apply_to(&mut command);
    let status = command.status().unwrap();
    assert!(!status.success());
    let written = std::fs::metadata(&file).map_or(0, |m| m.len());
    assert!(written <= 4096, "wrote {written} bytes past RLIMIT_FSIZE");
}

#[test]
fn raising_a_hard_limit_fails_the_spawn() {
    let Some(path) = program("true") else {
        return;
    };
    let hard = get(Resource::NoFile).unwrap().hard();
    let Value::Limited(n) = hard else {
        eprintln!("skipping: RLIMIT_NOFILE hard limit is unlimited");
        return;
    };
    let mut command = Command::new(path);
    LimitSet::new()
        .with_fixed(Resource::NoFile, n.saturating_add(1))
        .apply_to(&mut command);
    match command.status() {
        Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}"),
        // Root (CAP_SYS_RESOURCE) may raise it, up to fs.nr_open.
        Ok(_) => eprintln!("skipping: allowed to raise RLIMIT_NOFILE (privileged?)"),
    }
}

#[test]
fn set_and_get_round_trip_in_process() {
    // RLIMIT_CORE is harmless to change in a test process: lower the soft
    // limit, read it back, restore it (raising a soft limit up to the hard
    // one needs no privilege).
    let original = get(Resource::Core).unwrap();
    let lowered = Rlimit::new(0, original.hard()).unwrap();
    set(Resource::Core, lowered).unwrap();
    assert_eq!(get(Resource::Core).unwrap(), lowered);
    set(Resource::Core, original).unwrap();
    assert_eq!(get(Resource::Core).unwrap(), original);
}
