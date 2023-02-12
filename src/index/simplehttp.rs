use {
  anyhow::{anyhow, Context, Result},
  bitcoin::consensus::Decodable,
  std::{
    io::{BufRead, BufReader, Read, Write},
    net::{
      self, TcpStream, {SocketAddr, ToSocketAddrs},
    },
    str,
  },
};

const DEFAULT_PORT: u16 = 8332;

pub struct SimpleHttpTransport {
  addr: net::SocketAddr,
  stream: TcpStream,
}

impl SimpleHttpTransport {
  pub fn new(url: &str) -> Result<Self> {
    let url = check_url(url)?;
    let stream = TcpStream::connect(url.0)?;
    Ok(SimpleHttpTransport {
      addr: url.0,
      stream,
    })
  }

  pub fn request<R>(&mut self, path: &str) -> Result<R>
  where
    R: Decodable,
  {
    let req = format!("GET {} HTTP/1.1\r\nhost: {}\r\n\r\n", path, self.addr);

    self.stream.write_all(req.as_bytes())?;
    let mut sock = BufReader::new(&mut self.stream);
    // Parse first HTTP response header line
    let mut header_buf = String::new();
    sock.read_line(&mut header_buf)?;
    if header_buf.len() < 12 {
      return Err(anyhow!("REST error"));
    }
    if !header_buf.as_bytes()[..12].is_ascii() {
      return Err(anyhow!("REST error"));
    }
    if !header_buf.starts_with("HTTP/1.1 ") {
      return Err(anyhow!("REST error"));
    }
    let response_code = match header_buf[9..12].parse::<u16>() {
      Ok(n) => n,
      Err(_) => return Err(anyhow!("REST error")),
    };

    // Parse response header fields
    let mut content_length = None;
    loop {
      header_buf.clear();
      sock.read_line(&mut header_buf)?;
      if header_buf == "\r\n" {
        break;
      }
      header_buf.make_ascii_lowercase();

      const CONTENT_LENGTH: &str = "content-length: ";
      if header_buf.starts_with(CONTENT_LENGTH) {
        content_length = Some(
          header_buf[CONTENT_LENGTH.len()..]
            .trim()
            .parse::<u64>()
            .map_err(|_| anyhow!("REST error"))?,
        );
      }
    }

    if response_code == 401 {
      // There is no body in a 401 response, so don't try to read it
      return Err(anyhow!("REST error"));
    }

    const FINAL_RESP_ALLOC: u64 = 1024 * 1024 * 1024;
    // Read up to `content_length` bytes. Note that if there is no content-length
    // header, we will assume an effectively infinite content length, i.e. we will
    // just keep reading from the socket until it is closed.
    let mut reader = match content_length {
      None => sock.take(FINAL_RESP_ALLOC),
      Some(n) if n > FINAL_RESP_ALLOC => return Err(anyhow!("REST error")),
      Some(n) => sock.take(n),
    };

    let r = R::consensus_decode_from_finite_reader(&mut reader)
      .with_context(|| anyhow!("Invalid REST response"))?;
    Ok(r)
  }
}

/// Does some very basic manual URL parsing because the uri/url crates
/// all have unicode-normalization as a dependency and that's broken.
fn check_url(url: &str) -> Result<(SocketAddr, String)> {
  // The fallback port in case no port was provided.
  // This changes when the http or https scheme was provided.
  let mut fallback_port = DEFAULT_PORT;

  // We need to get the hostname and the port.
  // (1) Split scheme
  let after_scheme = {
    let mut split = url.splitn(2, "://");
    let s = split.next().unwrap();
    match split.next() {
      None => s, // no scheme present
      Some(after) => {
        // Check if the scheme is http or https.
        if s == "http" {
          fallback_port = 80;
        } else if s == "https" {
          fallback_port = 443;
        } else {
          return Err(anyhow!("url scheme should be http or https"));
        }
        after
      }
    }
  };
  // (2) split off path
  let (before_path, path) = {
    if let Some(slash) = after_scheme.find('/') {
      (&after_scheme[0..slash], &after_scheme[slash..])
    } else {
      (after_scheme, "/")
    }
  };
  // (3) split off auth part
  let after_auth = {
    let mut split = before_path.splitn(2, '@');
    let s = split.next().unwrap();
    split.next().unwrap_or(s)
  };

  // (4) Parse into socket address.
  // At this point we either have <host_name> or <host_name_>:<port>
  // `std::net::ToSocketAddrs` requires `&str` to have <host_name_>:<port> format.
  let mut addr = match after_auth.to_socket_addrs() {
    Ok(addr) => addr,
    Err(_) => {
      // Invalid socket address. Try to add port.
      format!("{after_auth}:{fallback_port}").to_socket_addrs()?
    }
  };

  match addr.next() {
    Some(a) => Ok((a, path.to_owned())),
    None => Err(anyhow!("invalid hostname: error extracting socket address")),
  }
}
