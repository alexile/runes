"""Regenerate the fixtures: real ClientHello/ServerHello bytes from OpenSSL
(s_client, s_server) and GnuTLS (wget), captured over loopback only.

    python3 capture.py <output dir>

Captured with OpenSSL 3.5.5 and GNU Wget 1.25.0 (GnuTLS). The server uses a
throwaway self-signed P-256 certificate for example.com.
"""
import os, socket, subprocess, sys, tempfile, time

OUT = sys.argv[1]
TMP = tempfile.mkdtemp()
CERT, KEY = os.path.join(TMP, "cert.pem"), os.path.join(TMP, "key.pem")
subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-keyout", KEY, "-out", CERT, "-days", "3650", "-subj", "/CN=example.com"],
               check=True, capture_output=True)

def read_hello(conn):
    """Read records until one complete handshake message is assembled."""
    data = b""
    conn.settimeout(5)
    while True:
        hs = b""; off = 0
        while off + 5 <= len(data):
            n = int.from_bytes(data[off+3:off+5], "big")
            if off + 5 + n > len(data): break
            hs += data[off+5:off+5+n]; off += 5 + n
        if len(hs) >= 4 and len(hs) >= 4 + int.from_bytes(hs[1:4], "big"):
            return data[:off]
        chunk = conn.recv(65536)
        if not chunk: raise RuntimeError("closed")
        data += chunk

def capture_client(name, argv_fn):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    proc = subprocess.Popen(argv_fn(port), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    conn, _ = srv.accept()
    hello = read_hello(conn)
    conn.close(); srv.close(); proc.kill(); proc.wait()
    open(os.path.join(OUT, name), "wb").write(hello)
    print(name, len(hello))
    return hello

def capture_server(name, server_args, client_hello, wait=0.7):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    proc = subprocess.Popen(["openssl", "s_server", "-accept", str(port), "-cert", CERT, "-key", KEY, "-quiet"] + server_args,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            c = socket.create_connection(("127.0.0.1", port)); break
        except OSError: time.sleep(0.1)
    c.sendall(client_hello)
    c.settimeout(wait); data = b""
    try:
        while True:
            chunk = c.recv(65536)
            if not chunk: break
            data += chunk
    except socket.timeout: pass
    c.close(); proc.kill(); proc.wait()
    open(os.path.join(OUT, name), "wb").write(data)
    print(name, len(data))

S0 = "DEFAULT@SECLEVEL=0"
def s_client(*extra):
    return lambda p: ["openssl", "s_client", "-connect", f"127.0.0.1:{p}", "-servername", "example.com",
                      "-alpn", "h2,http/1.1", *extra]

ch = {}
ch["tls10"] = capture_client("openssl-client-hello-tls1_0.bin", s_client("-tls1", "-cipher", S0))
ch["tls11"] = capture_client("openssl-client-hello-tls1_1.bin", s_client("-tls1_1", "-cipher", S0))
ch["tls12"] = capture_client("openssl-client-hello-tls1_2.bin", s_client("-tls1_2"))
ch["tls13"] = capture_client("openssl-client-hello-tls1_3.bin", s_client())
capture_client("gnutls-client-hello-tls1_3.bin",
               lambda p: ["wget", "-q", "-O", "/dev/null", "--tries=1", "--timeout=3",
                          "--no-check-certificate", f"https://localhost:{p}/"])

capture_server("openssl-server-flight-tls1_0.bin", ["-tls1", "-cipher", S0], ch["tls10"])
capture_server("openssl-server-flight-tls1_1.bin", ["-tls1_1", "-cipher", S0], ch["tls11"])
capture_server("openssl-server-flight-tls1_2.bin", ["-tls1_2", "-alpn", "h2"], ch["tls12"])
capture_server("openssl-server-flight-tls1_3.bin", ["-alpn", "h2"], ch["tls13"])
capture_server("openssl-server-hrr-tls1_3.bin", ["-groups", "secp384r1"], ch["tls13"])
capture_server("openssl-server-alert-protocol_version.bin", ["-tls1_3"], ch["tls10"])
capture_server("openssl-server-downgrade-tls1_2.bin", [], ch["tls12"])
fb = capture_client("openssl-client-hello-fallback-scsv.bin", s_client("-tls1_2", "-fallback_scsv"))
capture_server("openssl-server-alert-inappropriate_fallback.bin", [], fb)
