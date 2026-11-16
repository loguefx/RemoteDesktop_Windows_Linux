//! A very small HTTPS GET client, for the few web requests the app and host make:
//! dynamic DNS updates and the "new version available" check. HTTP/1.1, one request
//! per connection, certificates checked against the built-in web root store.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Largest response body read.
const MAX_BODY: usize = 1024 * 1024;

pub struct Response {
    pub status: u16,
    pub body: String,
}

/// `GET url` (https only). `extra_headers` are `Name: value` lines.
pub async fn get(url: &str, extra_headers: &[(&str, &str)]) -> Result<Response> {
    tokio::time::timeout(Duration::from_secs(15), get_inner(url, extra_headers))
        .await
        .map_err(|_| anyhow!("timed out"))?
}

async fn get_inner(url: &str, extra_headers: &[(&str, &str)]) -> Result<Response> {
    let rest = url.strip_prefix("https://").ok_or_else(|| anyhow!("only https:// addresses are supported"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h, p.parse::<u16>().unwrap()),
        _ => (authority, 443),
    };
    if host.is_empty() || host.contains(['@', ' ']) {
        bail!("bad address");
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| anyhow!("{e}"))?;
    let tcp = TcpStream::connect((host, port)).await.with_context(|| format!("connect to {host}"))?;
    let mut tls = connector.connect(name, tcp).await.context("TLS")?;

    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rd-remote-desktop/{}\r\nAccept: */*\r\nConnection: close\r\n",
        env!("CARGO_PKG_VERSION")
    );
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes()).await?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        // Some servers close without a TLS close_notify; treat that as the end.
        let n = match tls.read(&mut buf).await {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > MAX_BODY + 64 * 1024 {
            bail!("response too large");
        }
    }
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Result<Response> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| anyhow!("bad HTTP response"))?;
    let head = String::from_utf8_lossy(&raw[..end]);
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("bad HTTP status line"))?;
    let chunked = lines.any(|l| {
        l.split_once(':').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
        })
    });
    let body = &raw[end + 4..];
    let body = if chunked { dechunk(body)? } else { body.to_vec() };
    Ok(Response { status, body: String::from_utf8_lossy(&body[..body.len().min(MAX_BODY)]).into_owned() })
}

fn dechunk(mut b: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = b.windows(2).position(|w| w == b"\r\n").ok_or_else(|| anyhow!("bad chunk"))?;
        let size_str = String::from_utf8_lossy(&b[..line_end]);
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16).context("bad chunk size")?;
        b = &b[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if b.len() < size {
            bail!("truncated chunk");
        }
        out.extend_from_slice(&b[..size]);
        b = b.get(size + 2..).unwrap_or(&[]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_chunked() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK").unwrap();
        assert_eq!((r.status, r.body.as_str()), (200, "OK"));
        let r = parse_response(b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").unwrap();
        assert_eq!((r.status, r.body.as_str()), (404, "abcde"));
        assert!(parse_response(b"garbage").is_err());
    }
}
