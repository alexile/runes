//! `SSH_MSG_KEXINIT`: the algorithm lists a server offers.

use crate::Error;
use crate::wire::{MSG_KEXINIT, Reader, put_name_list, put_u32};

/// An `SSH_MSG_KEXINIT` payload
/// ([RFC 4253 §7.1](https://www.rfc-editor.org/rfc/rfc4253#section-7.1)).
///
/// Each list is in the sender's order of preference.
///
/// ```
/// use rune_probe_ssh::KexInit;
///
/// let mut offer = KexInit::default();
/// offer.kex_algorithms = vec!["curve25519-sha256".into(), "diffie-hellman-group1-sha1".into()];
/// offer.server_host_key_algorithms = vec!["ssh-ed25519".into()];
/// let payload = offer.encode();
/// assert_eq!(payload[0], 20); // SSH_MSG_KEXINIT
/// assert_eq!(KexInit::parse(&payload)?, offer);
/// # Ok::<(), rune_probe_ssh::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct KexInit {
    /// The 16 random bytes that make each exchange unique.
    pub cookie: [u8; 16],
    /// Key-exchange methods, e.g. `curve25519-sha256`. Pseudo-algorithms
    /// that signal extensions (`ext-info-s`, `kex-strict-s-v00@openssh.com`)
    /// appear here too.
    pub kex_algorithms: Vec<String>,
    /// Host-key (signature) algorithms, e.g. `ssh-ed25519`, `rsa-sha2-512`.
    pub server_host_key_algorithms: Vec<String>,
    /// Ciphers, client to server.
    pub encryption_client_to_server: Vec<String>,
    /// Ciphers, server to client.
    pub encryption_server_to_client: Vec<String>,
    /// MACs, client to server.
    pub mac_client_to_server: Vec<String>,
    /// MACs, server to client.
    pub mac_server_to_client: Vec<String>,
    /// Compression methods, client to server.
    pub compression_client_to_server: Vec<String>,
    /// Compression methods, server to client.
    pub compression_server_to_client: Vec<String>,
    /// Language tags, client to server. Usually empty.
    pub languages_client_to_server: Vec<String>,
    /// Language tags, server to client. Usually empty.
    pub languages_server_to_client: Vec<String>,
    /// Whether a guessed key-exchange packet follows.
    pub first_kex_packet_follows: bool,
    /// Reserved for future extension; zero.
    pub reserved: u32,
}

impl KexInit {
    /// Parse a KEXINIT payload, starting at the message number. Bytes after
    /// the reserved field are ignored.
    ///
    /// # Errors
    ///
    /// [`Error::UnexpectedMessage`] when the payload is not a KEXINIT,
    /// [`Error::Truncated`] when it ends early, and [`Error::Malformed`]
    /// when a name-list holds an empty name or a byte outside printable
    /// ASCII.
    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(payload);
        let msg = r.u8("message number")?;
        if msg != MSG_KEXINIT {
            return Err(Error::UnexpectedMessage {
                expected: MSG_KEXINIT,
                actual: msg,
            });
        }
        let mut cookie = [0u8; 16];
        cookie.copy_from_slice(r.bytes(16, "KEXINIT cookie")?);
        Ok(Self {
            cookie,
            kex_algorithms: r.name_list("kex_algorithms")?,
            server_host_key_algorithms: r.name_list("server_host_key_algorithms")?,
            encryption_client_to_server: r.name_list("encryption_algorithms_client_to_server")?,
            encryption_server_to_client: r.name_list("encryption_algorithms_server_to_client")?,
            mac_client_to_server: r.name_list("mac_algorithms_client_to_server")?,
            mac_server_to_client: r.name_list("mac_algorithms_server_to_client")?,
            compression_client_to_server: r.name_list("compression_algorithms_client_to_server")?,
            compression_server_to_client: r.name_list("compression_algorithms_server_to_client")?,
            languages_client_to_server: r.name_list("languages_client_to_server")?,
            languages_server_to_client: r.name_list("languages_server_to_client")?,
            first_kex_packet_follows: r.boolean("first_kex_packet_follows")?,
            reserved: r.u32("KEXINIT reserved field")?,
        })
    }

    /// Encode as a KEXINIT payload, message number first.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.push(MSG_KEXINIT);
        out.extend_from_slice(&self.cookie);
        for list in [
            &self.kex_algorithms,
            &self.server_host_key_algorithms,
            &self.encryption_client_to_server,
            &self.encryption_server_to_client,
            &self.mac_client_to_server,
            &self.mac_server_to_client,
            &self.compression_client_to_server,
            &self.compression_server_to_client,
            &self.languages_client_to_server,
            &self.languages_server_to_client,
        ] {
            put_name_list(&mut out, list);
        }
        out.push(u8::from(self.first_kex_packet_follows));
        put_u32(&mut out, self.reserved);
        out
    }

    /// Every cipher offered in either direction, without duplicates, in
    /// order of first appearance.
    #[must_use]
    pub fn ciphers(&self) -> Vec<&str> {
        union(
            &self.encryption_client_to_server,
            &self.encryption_server_to_client,
        )
    }

    /// Every MAC offered in either direction, without duplicates.
    #[must_use]
    pub fn macs(&self) -> Vec<&str> {
        union(&self.mac_client_to_server, &self.mac_server_to_client)
    }

    /// Every compression method offered in either direction, without
    /// duplicates.
    #[must_use]
    pub fn compression(&self) -> Vec<&str> {
        union(
            &self.compression_client_to_server,
            &self.compression_server_to_client,
        )
    }

    /// True when the server signals strict key exchange
    /// (`kex-strict-s-v00@openssh.com`), the Terrapin countermeasure.
    #[must_use]
    pub fn strict_kex(&self) -> bool {
        self.kex_algorithms
            .iter()
            .any(|k| k == "kex-strict-s-v00@openssh.com")
    }
}

fn union<'a>(a: &'a [String], b: &'a [String]) -> Vec<&'a str> {
    // A hash set keeps this linear: a hostile KEXINIT can carry thousands
    // of distinct names.
    let mut seen = std::collections::HashSet::with_capacity(a.len().max(b.len()));
    a.iter()
        .chain(b)
        .map(String::as_str)
        .filter(|name| seen.insert(*name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_other_messages_and_truncation() {
        assert_eq!(
            KexInit::parse(&[21]),
            Err(Error::UnexpectedMessage {
                expected: 20,
                actual: 21
            })
        );
        let full = KexInit::default().encode();
        for cut in 0..full.len() {
            assert!(KexInit::parse(&full[..cut]).is_err(), "cut at {cut}");
        }
        assert_eq!(KexInit::parse(&full).unwrap(), KexInit::default());
    }

    #[test]
    fn unions_keep_first_order() {
        let mut k = KexInit {
            encryption_client_to_server: vec!["a".into(), "b".into()],
            encryption_server_to_client: vec!["b".into(), "c".into()],
            ..KexInit::default()
        };
        assert_eq!(k.ciphers(), ["a", "b", "c"]);
        assert!(!k.strict_kex());
        k.kex_algorithms.push("kex-strict-s-v00@openssh.com".into());
        assert!(k.strict_kex());
    }
}
