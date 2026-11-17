//! Two-step sign-in: time-based one-time codes (RFC 6238, the kind authenticator apps
//! such as Google Authenticator, Microsoft Authenticator or 2FAS show). Six digits,
//! 30-second steps, HMAC-SHA1.

use hmac::{Hmac, Mac};
use sha1::Sha1;

const STEP: u64 = 30;
const DIGITS: u32 = 6;

/// A new random 160-bit secret.
pub fn new_secret() -> Vec<u8> {
    let mut b = vec![0u8; 20];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b
}

/// The code for time step `step`.
fn code_at(secret: &[u8], step: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("any key length");
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(DIGITS)
}

/// The time step a `code` belongs to, if it's valid now (one step of clock drift is
/// allowed either way) and newer than `last_used` (a code works only once).
pub fn check(secret: &[u8], code: &str, unix_now: u64, last_used: u64) -> Option<u64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let now = unix_now / STEP;
    [now.saturating_sub(1), now, now + 1]
        .into_iter()
        .filter(|s| *s > last_used)
        .find(|s| code_at(secret, *s) == want)
}

/// RFC 4648 base32 without padding (what authenticator apps expect).
pub fn base32(data: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0);
    for b in data {
        buf = (buf << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// `otpauth://` link for a QR code: issuer "RD Remote Desktop", account `user@host`.
pub fn uri(secret: &[u8], user: &str, host: &str) -> String {
    let enc = |s: &str| -> String {
        s.bytes()
            .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
            .collect()
    };
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP}",
        enc("RD Remote Desktop"),
        enc(&format!("{user}@{host}")),
        base32(secret),
        enc("RD Remote Desktop")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vectors() {
        // RFC 6238 appendix B, SHA-1 key "12345678901234567890", last 6 digits.
        let key = b"12345678901234567890";
        for (t, want) in [(59u64, 287082u32), (1111111109, 81804), (1234567890, 5924), (2000000000, 279037)] {
            assert_eq!(code_at(key, t / STEP), want, "t={t}");
        }
        assert_eq!(check(key, "287082", 59, 0), Some(1));
        assert_eq!(check(key, "287 082", 59 + 30, 0), Some(1), "one step of drift");
        assert_eq!(check(key, "287082", 59, 1), None, "already used");
        assert_eq!(check(key, "287083", 59, 0), None);
        assert_eq!(check(key, "12345", 59, 0), None);
    }

    #[test]
    fn base32_reference() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"f"), "MY");
        assert!(uri(b"12345", "me", "Office PC").starts_with("otpauth://totp/RD%20Remote%20Desktop:me%40Office%20PC?secret=GEZDGNBV&"));
    }
}
