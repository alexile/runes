//! Domain- and IP/CIDR-scoped network egress — opt-in via
//! `network.allowed_domains`/`network.allowed_ips` in the policy TOML
//! (see [`crate::policy::NetworkSection`]).
//!
//! # Why this needs more than a shared network namespace
//!
//! The obvious-looking approach — leave the network namespace shared
//! with the host, run a filtering proxy on `127.0.0.1:<port>`, set
//! `HTTP_PROXY`/`HTTPS_PROXY` — has a real gap: it only constrains
//! processes that actually *use* those env vars. Anything that opens a
//! raw socket directly (ignoring the proxy, by design or by not
//! supporting one at all) reaches the real network completely
//! unfiltered, because the namespace itself was never actually
//! restricted. That's a soft control dressed as a hard one — the
//! specific trap this project's own docs elsewhere insist on not
//! stepping into.
//!
//! # The design used instead
//!
//! 1. The sandboxed process gets a **fully isolated** network namespace
//!    (`--unshare-net`, forced regardless of `sandbox.network` — see
//!    `sandbox::build_bwrap_args`) — no raw socket to anywhere
//!    succeeds, proxy-aware or not.
//! 2. A host-side CONNECT-only proxy ([`spawn_proxy`]) listens on a Unix
//!    domain socket, not a TCP port — deliberately, since `AF_UNIX`
//!    sockets are filesystem objects and work across the isolated
//!    network namespace via an ordinary bind mount, whereas no TCP
//!    port on the isolated namespace's own private loopback can reach
//!    anything outside it.
//! 3. That socket is bind-mounted into the sandbox (`sandbox.rs`) at a
//!    fixed path. The *only* thing reachable from inside the sandbox,
//!    network-wise, is that one socket — not "everything, filtered by
//!    convention," but "nothing, except this."
//! 4. Since most HTTP-speaking programs (`HTTP_PROXY`/`HTTPS_PROXY`)
//!    don't know how to dial a Unix socket as a proxy target, a small
//!    relay ([`serve_relay`]) runs *inside* the sandbox — forked from the
//!    Landlock/network stub in `landlock_layer.rs` before it execs the
//!    real program — bridging <code>127.0.0.1:[RELAY_PORT]</code> (the sandbox's
//!    own, otherwise-empty private loopback) to that same bind-mounted
//!    socket. `HTTP_PROXY`/`HTTPS_PROXY` point there.
//!
//! # IP/CIDR targets and DNS-rebinding protection
//!
//! The host-side proxy is [`rune_egress_proxy::Proxy`]; this module only
//! turns a [`NetworkSection`] into its [`rune_egress_proxy::Policy`] (see
//! [`egress_policy`]) and wires it to the sandbox. `network.allowed_ips`
//! (bare addresses or CIDR ranges) covers two distinct cases:
//!
//! - A `CONNECT` target that is itself an IP literal (no hostname at
//!   all) is checked directly against `allowed_ips` — there is no
//!   "publicly routable, so allow it" fallback for a literal, since a
//!   literal never went through `allowed_domains` at all.
//! - A `CONNECT` target that is a hostname allowed via `allowed_domains`
//!   is resolved **once**, and the resulting address is connected to
//!   directly (not re-resolved) — the standard defense against a
//!   TOCTOU-style DNS-rebinding race. If every address that hostname
//!   resolved to is non-global (private, loopback, link-local, reserved,
//!   including their v4-mapped and NAT64 forms) and none of them are
//!   separately covered by `allowed_ips`, the connection is refused.
//!   This is what stops an allowed domain whose DNS answer (whether by
//!   attacker control or plain misconfiguration) points at
//!   `169.254.169.254` or an internal service from being a usable path
//!   past the allowlist.
//!
//! # What this honestly does and doesn't guarantee
//!
//! A program that speaks HTTP(S) through a configured proxy: fully
//! filtered to `allowed_domains`/`allowed_ips`, with a hard backstop
//! (full namespace isolation) if it doesn't. A program that opens raw
//! sockets without any proxy awareness at all: no network access
//! whatsoever, allowed domain or not — this is a CONNECT tunnel, not a
//! transparent firewall, so there's no path for traffic that was never
//! routed through it in the first place. That is a real, deliberate
//! limitation, not something this module tries to paper over.

use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::thread;

use rune_egress_proxy::{Event, Proxy};

use crate::policy::NetworkSection;

/// Fixed loopback port the in-sandbox relay ([`serve_relay`]) listens on.
/// Safe as a fixed, hardcoded number specifically because it's inside
/// the sandbox's own private, `--unshare-net`-isolated network
/// namespace — nothing else exists there to collide with.
pub const RELAY_PORT: u16 = 47601;

/// Where the proxy socket is bind-mounted *inside* the sandbox — the
/// only name the relay (running inside, past `bwrap`'s `pivot_root`) ever
/// resolves it by. `/run` is always a fresh, bwrap-managed tmpfs
/// regardless of policy (see `sandbox::build_bwrap_args`), so binding a
/// single file into it doesn't depend on anything policy-specific.
pub const IN_SANDBOX_PROXY_SOCKET: &str = "/run/rune-warden-network-proxy.sock";

/// Environment variable the stub (`landlock_layer::run_stub_if_invoked`)
/// checks to know whether to fork the in-sandbox relay before exec'ing
/// the real program — its value is always [`IN_SANDBOX_PROXY_SOCKET`].
pub const NETWORK_UDS_ENV: &str = "RUNE_WARDEN_NETWORK_UDS";

/// The egress policy `network` describes: `allowed_domains` as host
/// patterns (exact names, or `*.`-prefixed subdomain wildcards that never
/// match the apex) and `allowed_ips` as addresses or CIDR ranges, on any
/// port.
///
/// # Errors
///
/// The first malformed `allowed_domains` or `allowed_ips` entry.
pub fn egress_policy(
    network: &NetworkSection,
) -> Result<rune_egress_proxy::Policy, rune_egress_proxy::Error> {
    rune_egress_proxy::Policy::new()
        .allow_hosts(network.allowed_domains.iter().map(String::as_str))?
        .allow_ips(network.allowed_ips.iter().map(String::as_str))
}

/// Deterministic per-process path for the host-side proxy's Unix domain
/// socket — keyed on this process's own pid so concurrent, unrelated
/// `network.allowed_domains` runs don't collide.
pub fn proxy_socket_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "rune-secops-warden-network-{}.sock",
        std::process::id()
    ))
}

/// Logs refused requests to stderr, the way the sandboxed agent's user
/// sees them.
fn log_denials(event: &Event<'_>) {
    match event {
        Event::Denied { .. } | Event::Rejected { .. } => {
            eprintln!("rune-secops-warden: network: {event}");
        }
        _ => {}
    }
}

/// Start the host-side domain/IP-filtering CONNECT proxy on a background
/// thread, listening on [`proxy_socket_path`]. Returns once the socket
/// is bound and ready to accept — the proxy itself keeps running on its
/// own thread for the life of this process.
pub fn spawn_proxy(policy: rune_egress_proxy::Policy) -> std::io::Result<PathBuf> {
    let path = proxy_socket_path();
    let _ = std::fs::remove_file(&path);
    spawn_proxy_at(&path, policy)
}

fn spawn_proxy_at(path: &Path, policy: rune_egress_proxy::Policy) -> std::io::Result<PathBuf> {
    let listener = UnixListener::bind(path)?;
    let proxy = Proxy::new(policy).with_observer(log_denials);
    thread::Builder::new()
        .name("warden-egress-proxy".into())
        .spawn(move || proxy.serve_unix(&listener))?;
    Ok(path.to_path_buf())
}

/// Bind the in-sandbox relay's listener on <code>127.0.0.1:[RELAY_PORT]</code>
/// without serving it yet.
///
/// The stub binds *before* it forks, so the port is already accepting
/// connections by the time the real program is exec'd. Binding after the
/// fork, on the relay's own thread, races the program: a client that
/// connects to `HTTP_PROXY` straight away can get `ECONNREFUSED`.
/// Connections that arrive before [`serve_relay`] starts wait in the
/// listen backlog. The socket is close-on-exec, so the exec'd program
/// does not inherit it.
pub fn bind_relay() -> std::io::Result<TcpListener> {
    TcpListener::bind(("127.0.0.1", RELAY_PORT))
}

/// Run inside the sandbox, forked from the stub before it execs the real
/// program (see `landlock_layer::run_stub_if_invoked`): serves a listener
/// from [`bind_relay`], bridging each connection to the bind-mounted
/// proxy socket at `uds_path`. Blocks forever — the caller runs this in
/// the parent half of a `fork()`, never expecting it to return normally.
/// The actual TCP-to-UDS bridging is [`rune_relay`]'s job, extracted as
/// a generic crate — there's nothing sandbox-specific about relaying
/// bytes between a TCP port and a Unix socket.
pub fn serve_relay(listener: &TcpListener, uds_path: &Path) -> std::io::Result<()> {
    rune_relay::serve_tcp_to_uds(listener, uds_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_egress_proxy::{Decision, Denial, Target};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::net::UnixStream;

    fn policy(domains: &[&str], ips: &[&str]) -> rune_egress_proxy::Policy {
        egress_policy(&NetworkSection {
            allowed_domains: domains.iter().map(ToString::to_string).collect(),
            allowed_ips: ips.iter().map(ToString::to_string).collect(),
        })
        .unwrap()
    }

    fn domain_allowed(host: &str, domains: &[&str]) -> bool {
        let target: Target = format!("{host}:443").parse().unwrap();
        matches!(
            policy(domains, &[]).decide(&target),
            Decision::Resolve { .. }
        )
    }

    fn socket_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rune-secops-warden-network-proxy-{name}-{}-{:?}.sock",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn connect_status(path: &Path, target: &str) -> (String, BufReader<UnixStream>, UnixStream) {
        let mut client = UnixStream::connect(path).unwrap();
        client
            .write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes())
            .unwrap();
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut status_line = String::new();
        reader.read_line(&mut status_line).unwrap();
        (status_line, reader, client)
    }

    fn echo_server(len: usize) -> u16 {
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = echo.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = echo.accept() {
                let mut buf = vec![0u8; len];
                if stream.read_exact(&mut buf).is_ok() {
                    let _ = stream.write_all(&buf);
                }
            }
        });
        port
    }

    #[test]
    fn exact_domain_matches() {
        assert!(domain_allowed("api.anthropic.com", &["api.anthropic.com"]));
        assert!(!domain_allowed("evil.com", &["api.anthropic.com"]));
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        let allowed = ["*.anthropic.com"];
        assert!(domain_allowed("api.anthropic.com", &allowed));
        assert!(domain_allowed("deep.sub.anthropic.com", &allowed));
        assert!(
            !domain_allowed("anthropic.com", &allowed),
            "a wildcard shouldn't match the bare apex domain"
        );
        assert!(
            !domain_allowed("evilanthropic.com", &allowed),
            "suffix matching must respect the label boundary, not just string suffix"
        );
    }

    #[test]
    fn no_patterns_means_nothing_allowed() {
        assert!(!domain_allowed("api.anthropic.com", &[]));
    }

    #[test]
    fn malformed_entries_are_rejected() {
        let bad_ip = NetworkSection {
            allowed_ips: vec!["not-an-ip".to_string()],
            ..NetworkSection::default()
        };
        assert!(egress_policy(&bad_ip).is_err());
        let bad_domain = NetworkSection {
            allowed_domains: vec!["exa mple.com".to_string()],
            ..NetworkSection::default()
        };
        assert!(egress_policy(&bad_domain).is_err());
    }

    /// Real end-to-end proof: spin up the actual proxy (Unix socket,
    /// background thread, real upstream connect) and drive a genuine
    /// CONNECT handshake through it against a real local TCP listener
    /// standing in for "the allowed destination" — not just testing the
    /// domain-matching logic in isolation.
    #[test]
    fn proxy_allows_a_permitted_connect_and_relays_bytes() {
        let echo_port = echo_server(5);
        let socket = socket_path("allow");
        // "127.0.0.1" is a bare IP literal, not a hostname — it's checked
        // against `allowed_ips`, never `allowed_domains`.
        let path = spawn_proxy_at(&socket, policy(&[], &["127.0.0.1"])).unwrap();

        let (status_line, mut reader, mut client) =
            connect_status(&path, &format!("127.0.0.1:{echo_port}"));
        assert!(status_line.contains("200"), "got: {status_line}");
        let mut blank_line = String::new();
        reader.read_line(&mut blank_line).unwrap(); // the response's terminating blank line

        client.write_all(b"hello").unwrap();
        let mut echoed = [0u8; 5];
        reader.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"hello");

        std::fs::remove_file(&socket).ok();
    }

    #[test]
    fn proxy_rejects_a_domain_not_in_the_allowlist() {
        let socket = socket_path("deny");
        let path = spawn_proxy_at(&socket, policy(&["allowed.example"], &[])).unwrap();
        let (status_line, _, _) = connect_status(&path, "not-allowed.example:443");
        assert!(status_line.contains("403"), "got: {status_line}");
        std::fs::remove_file(&socket).ok();
    }

    /// Real end-to-end proof for `allowed_ips`: a CIDR range, not just an
    /// exact address, permits a real CONNECT+relay through the actual
    /// proxy.
    #[test]
    fn proxy_allows_a_bare_ip_covered_by_a_cidr_range() {
        let echo_port = echo_server(3);
        let socket = socket_path("cidr");
        let path = spawn_proxy_at(&socket, policy(&[], &["127.0.0.0/8"])).unwrap();
        let (status_line, _, _) = connect_status(&path, &format!("127.0.0.1:{echo_port}"));
        assert!(status_line.contains("200"), "got: {status_line}");
        std::fs::remove_file(&socket).ok();
    }

    #[test]
    fn proxy_rejects_a_bare_ip_not_in_allowed_ips() {
        let socket = socket_path("ip-deny");
        // 8.8.8.8 is a real, public, globally-routable address — the
        // point is that a bare-IP target gets no "it's public" fallback
        // at all, only `allowed_ips` grants it.
        let path = spawn_proxy_at(&socket, policy(&[], &["10.0.0.0/8"])).unwrap();
        let (status_line, _, _) = connect_status(&path, "8.8.8.8:443");
        assert!(status_line.contains("403"), "got: {status_line}");
        std::fs::remove_file(&socket).ok();
    }

    #[test]
    fn pinning_skips_private_addresses_by_default() {
        let addrs = [
            "127.0.0.1:443".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
        ];
        assert_eq!(
            policy(&[], &[]).pin(addrs),
            Ok("93.184.216.34:443".parse().unwrap())
        );
    }

    #[test]
    fn pinning_refuses_when_every_candidate_is_private_and_unallowlisted() {
        let addrs = ["169.254.169.254:80".parse().unwrap()];
        assert_eq!(policy(&[], &[]).pin(addrs), Err(Denial::NoAllowedAddress));
    }

    #[test]
    fn pinning_accepts_a_private_candidate_explicitly_allowlisted() {
        // The opt-in override: a domain that legitimately resolves inside
        // a private range (an internal registry behind split-horizon DNS,
        // say) still works if the operator explicitly allowlisted that
        // address via `allowed_ips`.
        let addrs = ["10.0.0.5:443".parse().unwrap()];
        assert_eq!(
            policy(&[], &["10.0.0.0/24"]).pin(addrs),
            Ok("10.0.0.5:443".parse().unwrap())
        );
    }

    #[test]
    fn non_global_ranges_are_refused_for_resolved_names() {
        let policy = policy(&[], &[]);
        for ip in [
            "127.0.0.1",
            "169.254.169.254", // cloud metadata endpoint
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1", // CGNAT
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::ffff:10.0.0.1", // v4-mapped private address
        ] {
            assert!(
                !policy.resolved_ip_allowed(ip.parse().unwrap()),
                "{ip} should be blocked by default"
            );
        }
        for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "::ffff:8.8.8.8"] {
            assert!(
                policy.resolved_ip_allowed(ip.parse().unwrap()),
                "{ip} is a real public address and should not be blocked by default"
            );
        }
    }
}
