//! A real, separate binary purely so `tests/e2e.rs` can exercise the
//! stub protocol (`sandbox.landlock = true` and/or
//! `network.allowed_domains`) through an actual `bwrap`-backed sandbox
//! end to end. This genuinely needs a standalone binary, not just a
//! helper function called from the test: the whole point of the stub
//! mechanism is that `std::env::current_exe()` (see
//! `rune_secops_warden::run_stub_if_invoked`'s docs) resolves to
//! *whichever process calls `build_command`* — for `cargo test`'s own
//! generated harness binary, that's the harness itself, which doesn't
//! (and can't reasonably be made to) call `run_stub_if_invoked()` at the
//! top of its own `main()`. This binary plays both roles a real CLI built on
//! this crate plays in one: the supervisor that calls `build_command`
//! *and*, since it becomes `self_exe` inside that sandbox, the stub that
//! restricts/relays and execs the real program — here, itself again, a
//! third time, now just behaving like `cat` or a minimal proxy-aware
//! HTTP CONNECT client.
//!
//! Modes, disambiguated in order:
//! 1. Stub (`run_stub_if_invoked`, auto-detected via env var —
//!    transparent, see that function).
//! 2. `landlock-e2e-helper supervise <project-dir> <visible-file>`: the
//!    Landlock scenario — builds a sandboxed-`cat`-of-`visible-file`
//!    policy with `sandbox.landlock = true` and itself as the allowed
//!    command, runs it, forwards the exit code.
//! 3. `landlock-e2e-helper supervise-network <allowed-domain-or-ip-or-cidr> <target-host:port>`:
//!    the network-egress scenario — builds a policy with either
//!    `network.allowed_domains` (a hostname) or `network.allowed_ips` (an
//!    IP literal or CIDR range, disambiguated by whether the argument
//!    parses as one) set to the first argument, and itself as the
//!    allowed command, running mode 5 against `target-host:port` inside
//!    the sandbox.
//! 4. `landlock-e2e-helper <path>`: read `path` and print its content —
//!    the "real program" mode 2's sandboxed run ends up exec'ing.
//! 5. `landlock-e2e-helper network-client <host:port>`: connect to
//!    `$HTTP_PROXY`, issue a real `CONNECT host:port` and, if allowed,
//!    round-trip a fixed payload — the "real program" mode 3's sandboxed
//!    run ends up exec'ing. Prints `ALLOWED` and the echoed payload, or
//!    `DENIED <status line>`, to stdout.

// This binary's whole job is to report results on stdout for tests/e2e.rs.
#![allow(clippy::print_stdout)]

use rune_secops_warden::{CommandRef, CommandsSection, FilesystemSection, PathEntry, Policy};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() {
    rune_secops_warden::run_stub_if_invoked();

    let mut args = std::env::args().skip(1);
    let outcome = match args.next() {
        Some(marker) if marker == "supervise" => supervise(args),
        Some(marker) if marker == "supervise-network" => supervise_network(args),
        Some(marker) if marker == "network-client" => network_client(args),
        Some(path) => Ok(cat(&path)),
        None => {
            eprintln!("usage: landlock-e2e-helper supervise <project-dir> <visible-file>");
            eprintln!(
                "       landlock-e2e-helper supervise-network <allowed-domain> <target-host:port>"
            );
            eprintln!("       landlock-e2e-helper network-client <host:port>");
            eprintln!("       landlock-e2e-helper <path>");
            Ok(2)
        }
    };
    let code = outcome.unwrap_or_else(|err| {
        eprintln!("landlock-e2e-helper: {err}");
        1
    });
    std::process::exit(code);
}

/// The next positional argument, or an error naming the missing `what`.
fn next_arg(args: &mut impl Iterator<Item = String>, what: &str) -> Result<String> {
    args.next().ok_or_else(|| format!("missing {what}").into())
}

fn self_exe_string() -> Result<String> {
    Ok(std::env::current_exe()
        .map_err(|err| format!("resolving this binary's own path: {err}"))?
        .to_string_lossy()
        .into_owned())
}

fn supervise(mut args: impl Iterator<Item = String>) -> Result<i32> {
    let project_dir = next_arg(&mut args, "<project-dir>")?;
    let visible_file = next_arg(&mut args, "<visible-file>")?;
    let self_exe = self_exe_string()?;

    let policy = Policy {
        sandbox: rune_secops_warden::SandboxSection {
            cwd: Some(project_dir.clone().into()),
            landlock: true,
            ..Default::default()
        },
        filesystem: FilesystemSection {
            read_write: vec![PathEntry::from(std::path::PathBuf::from(project_dir))],
            ..Default::default()
        },
        commands: CommandsSection {
            allow: vec![CommandRef::Entry {
                name: "landlock-e2e-helper".to_string(),
                path: Some(self_exe.clone().into()),
            }],
        },
        ..Default::default()
    };

    let mut command = rune_secops_warden::build_command(&policy, &self_exe, &[visible_file])?;
    let status = command.status()?;
    Ok(status.code().unwrap_or(1))
}

fn supervise_network(mut args: impl Iterator<Item = String>) -> Result<i32> {
    let allowed = next_arg(&mut args, "<allowed-domain-or-ip-or-cidr>")?;
    let target = next_arg(&mut args, "<target-host:port>")?;
    // Optional: any number of extra `allowed_ips` entries alongside
    // whatever `allowed` resolved to below — needed to exercise the
    // hostname-resolves-to-a-private-address-covered-by-allowed_ips path
    // (see
    // `network_allowed_domain_resolving_to_loopback_requires_explicit_allowed_ips`
    // in tests/e2e.rs), which needs *both* an allowed domain and an
    // allowed_ips override active at once — and, since a resolver can
    // return either address family for "localhost" first, may need more
    // than one entry to cover it regardless of which came back.
    let extra_allowed_ips: Vec<String> = args.collect();
    let self_exe = self_exe_string()?;

    // A bare IP or CIDR range goes in `allowed_ips`; a hostname goes in
    // `allowed_domains` — see `network_proxy::handle_connect`'s bare-IP
    // branch for why a literal never goes through `allowed_domains` at
    // all. Letting the caller pass either through this one positional
    // argument keeps the existing invocations (an exact IP, a bare
    // domain) working unchanged while also covering CIDR ranges.
    let looks_like_ip_or_cidr = allowed
        .split('/')
        .next()
        .is_some_and(|addr| addr.parse::<std::net::IpAddr>().is_ok());
    let (allowed_domains, mut allowed_ips) = if looks_like_ip_or_cidr {
        (vec![], vec![allowed])
    } else {
        (vec![allowed], vec![])
    };
    allowed_ips.extend(extra_allowed_ips);

    let policy = Policy {
        sandbox: rune_secops_warden::SandboxSection {
            // No filesystem paths are bound at all in this policy (it's
            // purely testing network egress) — fall back to the tmpfs
            // root bwrap always creates rather than the ambient cwd,
            // which isn't visible inside the sandbox at all here.
            cwd: Some("/".into()),
            ..Default::default()
        },
        network: rune_secops_warden::NetworkSection {
            allowed_domains,
            allowed_ips,
        },
        commands: CommandsSection {
            allow: vec![CommandRef::Entry {
                name: "landlock-e2e-helper".to_string(),
                path: Some(self_exe.clone().into()),
            }],
        },
        ..Default::default()
    };

    let mut command =
        rune_secops_warden::build_command(&policy, &self_exe, &["network-client".into(), target])?;
    let output = command.output()?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    Ok(output.status.code().unwrap_or(1))
}

fn cat(path: &str) -> i32 {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            print!("{content}");
            0
        }
        Err(err) => {
            eprintln!("read failed: {err}");
            1
        }
    }
}

fn network_client(mut args: impl Iterator<Item = String>) -> Result<i32> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;

    let target = next_arg(&mut args, "<host:port>")?;
    let Ok(proxy_url) = std::env::var("HTTP_PROXY") else {
        eprintln!("HTTP_PROXY not set");
        return Ok(2);
    };
    let proxy_addr = proxy_url
        .trim_start_matches("http://")
        .trim_end_matches('/');

    let mut stream =
        TcpStream::connect(proxy_addr).map_err(|err| format!("connecting to HTTP_PROXY: {err}"))?;
    stream.write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes())?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;

    if !status_line.contains("200") {
        println!("DENIED {}", status_line.trim());
        return Ok(0);
    }
    // Consume the blank line terminating the CONNECT response.
    let mut blank = String::new();
    reader.read_line(&mut blank)?;

    stream.write_all(b"ping")?;
    let mut echoed = [0u8; 4];
    reader.read_exact(&mut echoed)?;
    println!("ALLOWED {}", String::from_utf8_lossy(&echoed));
    Ok(0)
}
