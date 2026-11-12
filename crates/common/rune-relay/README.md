# rune-relay

> Bidirectional byte relay between two stream halves, plus a ready-made TCP-listener-to-Unix-domain-socket bridge built on it — generic stream plumbing, no protocol awareness.

[![crates.io](https://img.shields.io/crates/v/rune-relay)](https://crates.io/crates/rune-relay)
[![docs.rs](https://img.shields.io/docsrs/rune-relay)](https://docs.rs/rune-relay)
[![license](https://img.shields.io/crates/l/rune-relay)](LICENSE)

Blocking, thread-per-direction relaying for Unix platforms, with no
dependencies beyond `std`:

- `relay(a, b)` joins two full-duplex sockets (`TcpStream`, `UnixStream`, or
  your own type via the `DuplexStream` trait). Half-closes are propagated end
  to end, and a failure in one direction tears down the other. It returns the
  number of bytes copied each way.
- `pipe_both_directions` relays between any `Read`/`Write` halves (in-memory
  buffers, pipes, wrappers) and returns once both readers reach end-of-file.
- `relay_tcp_to_uds` / `serve_tcp_to_uds` bridge a TCP port to a Unix domain
  socket. The accept loop skips per-connection failures and backs off
  (5 ms → 1 s) when the process runs out of file descriptors instead of
  spinning.

## Installation

```bash
cargo add rune-relay
```

## Usage

Relay between two sockets; the client half-closes after its request and the
server answers once it sees end-of-file:

```rust
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::thread;

let (mut client, client_side) = UnixStream::pair()?;
let (server_side, mut server) = UnixStream::pair()?;

let relay = thread::spawn(move || rune_relay::relay(client_side, server_side));
let server = thread::spawn(move || -> std::io::Result<()> {
    let mut request = String::new();
    server.read_to_string(&mut request)?; // ends at the client's half-close
    server.write_all(request.to_uppercase().as_bytes())
});

client.write_all(b"ping")?;
client.shutdown(Shutdown::Write)?;
let mut response = String::new();
client.read_to_string(&mut response)?;
assert_eq!(response, "PING");
drop(client);

server.join().expect("server thread")?;
let transferred = relay.join().expect("relay thread")?;
assert_eq!((transferred.a_to_b, transferred.b_to_a), (4, 4));
```

Bridge a TCP port to a Unix domain socket, one thread per connection:

```rust,no_run
use std::net::TcpListener;
use std::path::Path;

let listener = TcpListener::bind("127.0.0.1:8080")?;
rune_relay::serve_tcp_to_uds(&listener, Path::new("/run/some.sock"))?;
```

## Semantics

| Event | `relay` reaction |
| ----- | ---------------- |
| Peer A shuts down its write side (EOF) | shut down the write side towards B; B → A keeps flowing |
| Read or write error in either direction | shut down both sockets completely, so both directions end |
| Both directions ended | return `Transferred { a_to_b, b_to_a }` |

`pipe_both_directions` cannot half-close a generic writer; it flushes each
writer when its direction ends and drops it on return. Use `relay` for socket
halves obtained with `try_clone`, where dropping one handle does not close the
socket.

## License

MIT
