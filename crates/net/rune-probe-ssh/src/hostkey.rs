//! Public host keys (`K_S`) and their fingerprints.

use crate::Error;
use crate::wire::{MSG_KEX_REPLY, Reader};

/// A server's public host key, as sent in the key-exchange reply
/// ([RFC 4253 §6.6](https://www.rfc-editor.org/rfc/rfc4253#section-6.6)).
///
/// ```
/// use rune_probe_ssh::HostKey;
///
/// // `ssh-keygen -t ed25519`, public half.
/// let blob = rune_base64::decode(
///     "AAAAC3NzaC1lZDI1NTE5AAAAIOJv+0BnO5Sq9IS18Q8eLfxJL3GuLtonL4clXHHkg4EX",
/// ).unwrap();
/// let key = HostKey::parse(&blob)?;
/// assert_eq!(key.key_type, "ssh-ed25519");
/// assert_eq!(key.bits, Some(256));
/// // Matches `ssh-keygen -lf`.
/// assert_eq!(key.fingerprint_sha256(), "SHA256:sy6hgZYNW2YfQFZt6xYCu+D96SlMGrevKRhp8XYPN74");
/// # Ok::<(), rune_probe_ssh::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct HostKey {
    /// The key type from the blob, e.g. `ssh-ed25519`, `ssh-rsa`,
    /// `ecdsa-sha2-nistp256` or `ssh-ed25519-cert-v01@openssh.com`.
    pub key_type: String,
    /// Key size in bits, as `ssh-keygen -l` reports it, for the key types
    /// this crate understands.
    pub bits: Option<u32>,
    /// The raw public-key blob, as fingerprinted.
    pub blob: Vec<u8>,
}

impl HostKey {
    /// Parse a public-key blob.
    ///
    /// RSA, DSA, ECDSA and Ed25519 keys (and OpenSSH certificates for them)
    /// are sized; other key types keep `bits` empty.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] or [`Error::Malformed`] when the blob does not
    /// hold a key of the type it names.
    pub fn parse(blob: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(blob);
        let key_type = r.string("host key type")?;
        if key_type.is_empty() || !key_type.iter().all(|&b| (0x21..=0x7e).contains(&b)) {
            return Err(Error::Malformed("host key type"));
        }
        let key_type: String = key_type.iter().map(|&b| char::from(b)).collect();
        let base = match key_type.strip_suffix("-cert-v01@openssh.com") {
            Some(base) => {
                r.string("certificate nonce")?;
                base
            }
            None => key_type.as_str(),
        };
        let bits = match base {
            "ssh-rsa" => {
                r.string("RSA exponent")?;
                Some(mpint_bits(r.string("RSA modulus")?))
            }
            "ssh-dss" => Some(mpint_bits(r.string("DSA prime")?)),
            "ssh-ed25519" => {
                if r.string("Ed25519 key")?.len() != 32 {
                    return Err(Error::Malformed("Ed25519 key"));
                }
                Some(256)
            }
            _ => match base.strip_prefix("ecdsa-sha2-") {
                Some(curve) => {
                    let named = r.string("ECDSA curve")?;
                    if named != curve.as_bytes() {
                        return Err(Error::Malformed("ECDSA curve"));
                    }
                    r.string("ECDSA point")?;
                    match curve {
                        "nistp256" => Some(256),
                        "nistp384" => Some(384),
                        "nistp521" => Some(521),
                        _ => None,
                    }
                }
                None => None,
            },
        };
        Ok(Self {
            key_type,
            bits,
            blob: blob.to_vec(),
        })
    }

    /// The OpenSSH SHA-256 fingerprint: `SHA256:` and the unpadded base64
    /// of the blob's digest, as `ssh-keygen -l` and `ssh` print it.
    #[must_use]
    pub fn fingerprint_sha256(&self) -> String {
        format!(
            "SHA256:{}",
            rune_base64::encode_no_pad(&rune_sha256::hash_raw(&self.blob))
        )
    }

    /// The key in `authorized_keys` / `known_hosts` form: type, a space and
    /// the base64 blob.
    #[must_use]
    pub fn to_openssh(&self) -> String {
        format!("{} {}", self.key_type, rune_base64::encode(&self.blob))
    }
}

/// Bit length of a non-negative RFC 4251 `mpint`.
fn mpint_bits(value: &[u8]) -> u32 {
    let start = value.iter().position(|&b| b != 0).unwrap_or(value.len());
    let digits = value.get(start..).unwrap_or_default();
    match digits.first() {
        None => 0,
        Some(&top) => {
            let len = u32::try_from(digits.len()).unwrap_or(u32::MAX / 8);
            (len - 1).saturating_mul(8) + (8 - top.leading_zeros())
        }
    }
}

/// Extract `K_S` from a `SSH_MSG_KEXDH_REPLY` / `SSH_MSG_KEX_ECDH_REPLY`
/// payload.
///
/// The payload starts at the message number. The rest of the reply (the server's
/// ephemeral key and signature) is not checked: the probe never completes
/// the exchange.
///
/// # Errors
///
/// [`Error::UnexpectedMessage`] for another message, [`Error::Truncated`]
/// when the key is cut short.
pub fn parse_kex_reply_host_key(payload: &[u8]) -> Result<&[u8], Error> {
    let mut r = Reader::new(payload);
    let msg = r.u8("message number")?;
    if msg != MSG_KEX_REPLY {
        return Err(Error::UnexpectedMessage {
            expected: MSG_KEX_REPLY,
            actual: msg,
        });
    }
    r.string("host key")
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_1024: &str = "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDLwSlEGUNEBIVQSwfSPQOHPacwU27hKFDUCYvzRNix6RK4/Nv/fEvnyCxgEkWT8AMDj0YV60Jk0wA0bhVjzBG8kZkvjOYuz7CbSVwU6ReXjheIK2Ggp8DQUJmNOy5qFCcPenwFiAs+2Ex45Pj+oUoxYZiUhHAEkxvV+64MArJCSw==";
    const ECDSA_P256: &str = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDL6VoCxS7ElxPexgCG/fYmj5+QLN4yVNzCv3M6z5VnTnMtQS4XStdjDwB6VqZIo4paWFW0n8ayO5byOgoeyh7k=";

    #[test]
    fn ssh_keygen_known_answers() {
        let rsa = HostKey::parse(&rune_base64::decode(RSA_1024).unwrap()).unwrap();
        assert_eq!(rsa.key_type, "ssh-rsa");
        assert_eq!(rsa.bits, Some(1024));
        assert_eq!(
            rsa.fingerprint_sha256(),
            "SHA256:8D8GBIFYgHY22Io7k9Y90vtTR4JEV0xijzyuXEDchos"
        );
        assert_eq!(rsa.to_openssh(), format!("ssh-rsa {RSA_1024}"));

        let ec = HostKey::parse(&rune_base64::decode(ECDSA_P256).unwrap()).unwrap();
        assert_eq!(ec.key_type, "ecdsa-sha2-nistp256");
        assert_eq!(ec.bits, Some(256));
        assert_eq!(
            ec.fingerprint_sha256(),
            "SHA256:Pa19XJiAEHZi2fYLmGF116YTViV92HJGAAWfn3/12xU"
        );
    }

    #[test]
    fn truncated_and_unknown_keys() {
        let blob = rune_base64::decode(RSA_1024).unwrap();
        for cut in 0..blob.len() {
            assert!(HostKey::parse(&blob[..cut]).is_err(), "cut at {cut}");
        }
        let mut unknown = Vec::new();
        crate::wire::put_string(&mut unknown, b"ssh-ed448");
        crate::wire::put_string(&mut unknown, &[0; 57]);
        let key = HostKey::parse(&unknown).unwrap();
        assert_eq!((key.key_type.as_str(), key.bits), ("ssh-ed448", None));
    }

    #[test]
    fn mpint_sizes() {
        assert_eq!(mpint_bits(&[]), 0);
        assert_eq!(mpint_bits(&[0, 0x80]), 8);
        assert_eq!(mpint_bits(&[0x01, 0]), 9);
    }

    #[test]
    fn kex_reply() {
        let mut payload = vec![MSG_KEX_REPLY];
        crate::wire::put_string(&mut payload, b"key");
        assert_eq!(parse_kex_reply_host_key(&payload).unwrap(), b"key");
        assert!(parse_kex_reply_host_key(&[20]).is_err());
    }
}
