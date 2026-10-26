use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const MAX_PENDING_DNS_LOOKUPS: usize = 8;
static PENDING_DNS_LOOKUPS: AtomicUsize = AtomicUsize::new(0);

pub fn authority(host: &str, port: u16) -> String {
    if host
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_ipv6())
    {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub struct TcpResponse {
    pub bytes: Vec<u8>,
    pub peer: SocketAddr,
}

pub struct UdpResponse {
    pub bytes: Vec<u8>,
    pub peer: SocketAddr,
}

pub struct HttpResponse {
    pub bytes: Vec<u8>,
    pub status: u16,
    pub peer: Option<SocketAddr>,
    pub url: String,
    pub headers: Vec<(String, String)>,
}

pub fn http_url(raw: &str) -> Result<(reqwest::Url, String), String> {
    if raw.len() > 4096 {
        return Err("HTTP URL exceeds 4096 bytes".into());
    }
    let url = reqwest::Url::parse(raw).map_err(|e| format!("invalid HTTP URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("HTTP URL must use http or https".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("HTTP URL credentials are not allowed".into());
    }
    if url.fragment().is_some() {
        return Err("HTTP URL fragments are not allowed".into());
    }
    let host = url.host_str().ok_or("HTTP URL has no host")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = url.port_or_known_default().ok_or("HTTP URL has no port")?;
    let allowed_authority = authority(host, port);
    Ok((url, allowed_authority))
}

pub fn fetch(
    url: reqwest::Url,
    max_bytes: usize,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    request(url, "GET", &[], &[], max_bytes, timeout)
}

pub fn request(
    url: reqwest::Url,
    method: &str,
    headers: &[String],
    body: &[u8],
    max_bytes: usize,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    if !matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    ) {
        return Err("HTTP method must be GET, HEAD, POST, PUT, PATCH, DELETE, or OPTIONS".into());
    }
    if matches!(method, "GET" | "HEAD") && !body.is_empty() {
        return Err("GET and HEAD requests must have an empty body".into());
    }
    let head = method == "HEAD";
    if headers.len() > 32 || headers.iter().map(String::len).sum::<usize>() > 8192 {
        return Err("HTTP request headers exceed 32 fields or 8192 bytes".into());
    }
    let method =
        reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| "invalid HTTP method")?;
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .http1_max_headers(64)
        .timeout(timeout)
        .build()
        .map_err(|e| format!("HTTP client setup failed: {e}"))?;
    let mut builder = client
        .request(method, url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity");
    for field in headers {
        let (name, value) = field
            .split_once(':')
            .ok_or("HTTP header needs name: value")?;
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| "invalid HTTP header name")?;
        if matches!(
            name.as_str(),
            "host" | "content-length" | "transfer-encoding" | "connection" | "accept-encoding"
        ) {
            return Err(format!(
                "HTTP header {} is managed by the runtime",
                name.as_str()
            ));
        }
        let value = reqwest::header::HeaderValue::from_str(value.trim())
            .map_err(|_| "invalid HTTP header value")?;
        builder = builder.header(name, value);
    }
    if !body.is_empty() {
        builder = builder.body(body.to_vec());
    }
    let response = builder
        .send()
        .map_err(|e| format!("HTTP request failed: {e}"))?;
    let status = response.status();
    if status.is_redirection() {
        return Err(format!("HTTP redirect refused: {status}"));
    }
    if !head
        && response
            .content_length()
            .is_some_and(|size| size > max_bytes as u64)
    {
        return Err(format!(
            "LimitExceeded: HTTP response exceeds {max_bytes} bytes"
        ));
    }
    let peer = response.remote_addr();
    let url = response.url().to_string();
    let mut response_headers = Vec::new();
    let mut header_bytes = 0usize;
    for (name, value) in response.headers() {
        let value = value
            .to_str()
            .map_err(|_| "HTTP response header is not text")?;
        header_bytes = header_bytes.saturating_add(name.as_str().len() + value.len());
        if response_headers.len() >= 64 || header_bytes > 32 * 1024 {
            return Err("HTTP response headers exceed 64 fields or 32768 bytes".into());
        }
        response_headers.push((name.as_str().to_owned(), value.to_owned()));
    }
    let mut bytes = Vec::new();
    response
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| {
            let timed_out = e.kind() == io::ErrorKind::TimedOut
                || e.get_ref()
                    .and_then(|source| source.downcast_ref::<reqwest::Error>())
                    .is_some_and(reqwest::Error::is_timeout);
            if timed_out {
                "HTTP body read timed out".to_string()
            } else {
                format!("HTTP body read failed: {e}")
            }
        })?;
    if bytes.len() > max_bytes {
        return Err(format!(
            "LimitExceeded: HTTP response exceeds {max_bytes} bytes"
        ));
    }
    Ok(HttpResponse {
        bytes,
        status: status.as_u16(),
        peer,
        url,
        headers: response_headers,
    })
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() {
        Err("TCP exchange timed out".into())
    } else {
        Ok(duration.max(Duration::from_millis(1)))
    }
}

fn io_error(action: &str, error: io::Error) -> String {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        "TCP exchange timed out".into()
    } else {
        format!("TCP {action} failed: {error}")
    }
}

fn resolve_with_deadline<F>(
    address: String,
    deadline: Instant,
    timeout_message: &'static str,
    resolver: F,
) -> Result<Vec<SocketAddr>, String>
where
    F: FnOnce(String) -> io::Result<Vec<SocketAddr>> + Send + 'static,
{
    if Instant::now() >= deadline {
        return Err(timeout_message.into());
    }
    if let Ok(socket) = address.parse::<SocketAddr>() {
        return Ok(vec![socket]);
    }
    PENDING_DNS_LOOKUPS
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |pending| {
            (pending < MAX_PENDING_DNS_LOOKUPS).then_some(pending + 1)
        })
        .map_err(|_| "too many pending DNS lookups")?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker_address = address.clone();
    let worker = thread::Builder::new()
        .name("galeikan-dns".into())
        .spawn(move || {
            struct PendingLookup;
            impl Drop for PendingLookup {
                fn drop(&mut self) {
                    PENDING_DNS_LOOKUPS.fetch_sub(1, Ordering::AcqRel);
                }
            }
            let _pending = PendingLookup;
            let _ = sender.send(resolver(worker_address));
        });
    if let Err(error) = worker {
        PENDING_DNS_LOOKUPS.fetch_sub(1, Ordering::AcqRel);
        return Err(format!("cannot start DNS lookup: {error}"));
    }
    let resolution = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => timeout_message.to_string(),
            mpsc::RecvTimeoutError::Disconnected => "DNS lookup worker failed".into(),
        })?;
    if Instant::now() >= deadline {
        return Err(timeout_message.into());
    }
    resolution.map_err(|error| format!("cannot resolve {address}: {error}"))
}

fn resolve_address(
    address: String,
    deadline: Instant,
    timeout_message: &'static str,
) -> Result<Vec<SocketAddr>, String> {
    resolve_with_deadline(address, deadline, timeout_message, |address| {
        address
            .to_socket_addrs()
            .map(|addresses| addresses.take(32).collect())
    })
}

pub fn exchange(
    host: &str,
    port: u16,
    request: &[u8],
    max_bytes: usize,
    timeout: Duration,
) -> Result<TcpResponse, String> {
    let address = authority(host, port);
    let deadline = Instant::now() + timeout;
    let addrs = resolve_address(address.clone(), deadline, "TCP exchange timed out")?;
    let mut stream = None;
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, remaining(deadline)?) {
            Ok(socket) => {
                stream = Some(socket);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let mut stream = stream.ok_or_else(|| match last_error {
        Some(error) => format!("TCP connect failed: {error}"),
        None => format!("no address resolved for {address}"),
    })?;
    let peer = stream
        .peer_addr()
        .map_err(|e| format!("TCP peer address unavailable: {e}"))?;
    let mut pending = request;
    while !pending.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|e| io_error("write timeout setup", e))?;
        let written = stream.write(pending).map_err(|e| io_error("write", e))?;
        if written == 0 {
            return Err("TCP connection closed while writing".into());
        }
        pending = &pending[written..];
    }
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| io_error("write shutdown", e))?;
    let mut response = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|e| io_error("read timeout setup", e))?;
        let available = max_bytes + 1 - response.len();
        let read_len = available.min(chunk.len());
        let count = stream
            .read(&mut chunk[..read_len])
            .map_err(|e| io_error("read", e))?;
        if count == 0 {
            return Ok(TcpResponse {
                bytes: response,
                peer,
            });
        }
        response.extend_from_slice(&chunk[..count]);
        if response.len() > max_bytes {
            return Err(format!(
                "LimitExceeded: TCP response exceeds {max_bytes} bytes"
            ));
        }
    }
}

pub fn datagram(
    host: &str,
    port: u16,
    request: &[u8],
    max_bytes: usize,
    timeout: Duration,
) -> Result<UdpResponse, String> {
    let address = authority(host, port);
    let deadline = Instant::now() + timeout;
    let addrs = resolve_address(address.clone(), deadline, "UDP exchange timed out")?;
    let mut connected = None;
    let mut last_error = None;
    for addr in addrs {
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        match UdpSocket::bind(bind_addr).and_then(|socket| {
            socket.connect(addr)?;
            Ok(socket)
        }) {
            Ok(socket) => {
                connected = Some(socket);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let socket = connected.ok_or_else(|| match last_error {
        Some(error) => format!("UDP connect failed: {error}"),
        None => format!("no address resolved for {address}"),
    })?;
    let peer = socket
        .peer_addr()
        .map_err(|e| format!("UDP peer address unavailable: {e}"))?;
    let remaining = || {
        let duration = deadline.saturating_duration_since(Instant::now());
        if duration.is_zero() {
            Err("UDP exchange timed out".to_string())
        } else {
            Ok(duration.max(Duration::from_millis(1)))
        }
    };
    let io_error = |action: &str, error: io::Error| {
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            "UDP exchange timed out".to_string()
        } else {
            format!("UDP {action} failed: {error}")
        }
    };
    socket
        .set_write_timeout(Some(remaining()?))
        .map_err(|e| io_error("write timeout setup", e))?;
    let sent = socket.send(request).map_err(|e| io_error("write", e))?;
    if sent != request.len() {
        return Err(format!("UDP wrote only {sent} of {} bytes", request.len()));
    }
    let mut bytes = vec![0; max_bytes + 1];
    socket
        .set_read_timeout(Some(remaining()?))
        .map_err(|e| io_error("read timeout setup", e))?;
    let received = socket.recv(&mut bytes).map_err(|e| io_error("read", e))?;
    if received > max_bytes {
        return Err(format!(
            "LimitExceeded: UDP datagram exceeds {max_bytes} bytes"
        ));
    }
    bytes.truncate(received);
    Ok(UdpResponse { bytes, peer })
}

#[cfg(test)]
mod tests {
    use super::{http_url, resolve_address, resolve_with_deadline};
    use std::net::SocketAddr;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[test]
    fn http_url_authority_is_canonical_and_rejects_unsafe_forms() {
        assert_eq!(
            http_url("https://EXAMPLE.com/sample").unwrap().1,
            "example.com:443"
        );
        assert_eq!(http_url("http://[::1]/").unwrap().1, "[::1]:80");
        assert_eq!(
            http_url("https://example.com:8443/").unwrap().1,
            "example.com:8443"
        );
        assert!(http_url("file:///etc/passwd").is_err());
        assert!(http_url("http://u:p@example.com/").is_err());
        assert!(http_url("http://example.com/#secret").is_err());
    }

    #[test]
    fn dns_lookup_respects_deadline_without_waiting_for_blocked_resolver() {
        let (release, blocked) = mpsc::channel::<()>();
        let start = Instant::now();
        let result = resolve_with_deadline(
            "fixture.test:80".into(),
            start + Duration::from_millis(50),
            "lookup timed out",
            move |_| {
                blocked.recv().unwrap();
                Ok(Vec::new())
            },
        );
        assert_eq!(result.unwrap_err(), "lookup timed out");
        assert!(start.elapsed() < Duration::from_secs(2));
        drop(release);
    }

    #[test]
    fn literal_addresses_skip_dns_and_named_addresses_return_bounded_results() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let literal =
            resolve_with_deadline("127.0.0.1:80".into(), deadline, "lookup timed out", |_| {
                panic!("literal address must not start a DNS lookup")
            })
            .unwrap();
        assert_eq!(literal, vec!["127.0.0.1:80".parse::<SocketAddr>().unwrap()]);

        let named = resolve_with_deadline(
            "fixture.test:80".into(),
            deadline,
            "lookup timed out",
            |_| Ok(vec!["127.0.0.1:80".parse().unwrap()]),
        )
        .unwrap();
        assert_eq!(named, literal);
    }

    #[test]
    fn localhost_resolves_within_the_request_deadline() {
        let addresses = resolve_address(
            "localhost:80".into(),
            Instant::now() + Duration::from_secs(2),
            "lookup timed out",
        )
        .unwrap();
        assert!(!addresses.is_empty());
        assert!(addresses.len() <= 32);
        assert!(addresses.iter().all(|address| address.port() == 80));
    }
}
