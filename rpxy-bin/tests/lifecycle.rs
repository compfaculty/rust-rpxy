use std::{
  fs::{self, File},
  io::{BufRead, BufReader, Write},
  net::{SocketAddr, TcpListener, TcpStream},
  path::{Path, PathBuf},
  process::{Child, Command, ExitStatus, Stdio},
  thread,
  time::{Duration, Instant},
};

#[path = "lifecycle/tls.rs"]
mod tls;

struct ProxyProcess {
  child: Child,
  log: PathBuf,
}

impl ProxyProcess {
  fn start(config: &Path) -> Self {
    Self::start_with_args(config, &[])
  }

  fn start_with_args(config: &Path, args: &[&str]) -> Self {
    let log = config.with_extension("log");
    let output = File::create(&log).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_rpxy"))
      .arg("--config")
      .arg(config)
      .args(args)
      .current_dir(config.parent().unwrap())
      .env("RUST_LOG", "debug")
      .stdout(Stdio::from(output.try_clone().unwrap()))
      .stderr(Stdio::from(output))
      .spawn()
      .unwrap();
    Self { child, log }
  }

  fn output(&self) -> String {
    fs::read_to_string(&self.log).unwrap()
  }

  fn wait_for_exit(&mut self) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
      if let Some(status) = self.child.try_wait().unwrap() {
        return status;
      }
      assert!(Instant::now() < deadline, "proxy did not exit:\n{}", self.output());
      thread::sleep(Duration::from_millis(20));
    }
  }

  fn wait_for_log(&mut self, predicate: impl Fn(&str) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
      let output = self.output();
      assert!(self.child.try_wait().unwrap().is_none(), "proxy exited:\n{output}");
      if predicate(&output) {
        return;
      }
      assert!(Instant::now() < deadline, "proxy log did not reach expected state:\n{output}");
      thread::sleep(Duration::from_millis(20));
    }
  }
}

impl Drop for ProxyProcess {
  fn drop(&mut self) {
    let _ = self.child.kill();
    let _ = self.child.wait();
  }
}

#[test]
fn missing_or_malformed_startup_config_exits_with_an_error() {
  let dir = tempfile::tempdir().unwrap();
  let missing = dir.path().join("missing.toml");
  let malformed = dir.path().join("malformed.toml");
  fs::write(&malformed, "listen_port = [").unwrap();

  for (config, diagnostic) in [(missing, "Failed to read"), (malformed, "Failed to parse")] {
    let mut proxy = ProxyProcess::start(&config);
    assert_eq!(proxy.wait_for_exit().code(), Some(1));
    let output = proxy.output();
    assert!(output.contains("Cannot load configuration"), "{output}");
    assert!(output.contains(diagnostic), "{output}");
  }
}

fn cert_fixture(name: &str) -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR")).join("../example-certs").join(name)
}

fn tls_config(port: u16) -> String {
  format!(
    "
listen_address_v4 = '127.0.0.1'
listen_port_tls = {port}
[apps.local]
server_name = 'localhost'
reverse_proxy = [{{ upstream = [{{ location = '127.0.0.1:1' }}] }}]
[apps.local.tls]
tls_cert_path = '{}'
tls_cert_key_path = '{}'
",
    cert_fixture("server.crt").display(),
    cert_fixture("server.key").display()
  )
}

#[test]
fn occupied_tls_port_exits_with_a_bind_error() {
  let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
  let port = occupied.local_addr().unwrap().port();
  let dir = tempfile::tempdir().unwrap();
  let config = dir.path().join("rpxy.toml");
  fs::write(&config, tls_config(port)).unwrap();

  let mut proxy = ProxyProcess::start(&config);
  assert_eq!(proxy.wait_for_exit().code(), Some(1));
  let output = proxy.output();
  assert!(output.contains("Failed to bind TCP socket"), "{output}");
}

#[cfg(any(feature = "http3-quinn", feature = "http3-s2n"))]
#[test]
fn occupied_quic_port_exits_with_a_bind_error() {
  let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
  let port = occupied.local_addr().unwrap().port();
  let dir = tempfile::tempdir().unwrap();
  let config = dir.path().join("rpxy.toml");
  fs::write(&config, tls_config(port) + "\n[experimental.h3]\n").unwrap();

  let mut proxy = ProxyProcess::start(&config);
  assert_eq!(proxy.wait_for_exit().code(), Some(1));
  let output = proxy.output();
  assert!(output.contains("Start UDP proxy serving with HTTP/3"), "{output}");
  assert!(output.contains("Address already in use"), "{output}");
}

fn response_status(addr: SocketAddr, host: &str) -> u16 {
  let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
  stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
  write!(stream, "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").unwrap();
  let mut line = String::new();
  BufReader::new(stream).read_line(&mut line).unwrap();
  line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

fn write_http_config(path: &Path, addr: SocketAddr, host: &str) {
  fs::write(
    path,
    format!(
      "
listen_address_v4 = '127.0.0.1'
listen_port = {}
[apps.local]
server_name = '{host}'
reverse_proxy = [{{ path = '/service', upstream = [{{ location = '127.0.0.1:1' }}] }}]
",
      addr.port()
    ),
  )
  .unwrap();
}

const HTTP_LISTENER_STARTED: &str = "Start TCP proxy serving with HTTP request";

#[test]
fn rejected_reload_keeps_listening_and_the_next_valid_update_applies() {
  let addr = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
  let dir = tempfile::tempdir().unwrap();
  let config = dir.path().join("rpxy.toml");
  write_http_config(&config, addr, "old.example");
  let mut proxy = ProxyProcess::start(&config);
  proxy.wait_for_log(|out| out.contains(HTTP_LISTENER_STARTED) && out.contains("Realtime watching established"));
  assert_eq!(response_status(addr, "old.example"), 404);

  fs::write(&config, format!("listen_port = {}", addr.port())).unwrap();
  proxy.wait_for_log(|out| out.contains("Configuration update rejected"));
  assert_eq!(response_status(addr, "old.example"), 404);

  write_http_config(&config, addr, "new.example");
  proxy.wait_for_log(|out| out.matches(HTTP_LISTENER_STARTED).count() >= 2);
  assert_eq!(response_status(addr, "old.example"), 503);
  assert_eq!(response_status(addr, "new.example"), 404);
  let output = proxy.output();
  assert_eq!(output.matches(HTTP_LISTENER_STARTED).count(), 2, "{output}");
}

#[cfg(unix)]
#[test]
fn reload_rechecks_config_without_a_notification() {
  use std::os::unix::fs::symlink;

  let addr = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
  let dir = tempfile::tempdir().unwrap();
  let targets = dir.path().join("configs");
  fs::create_dir(&targets).unwrap();
  let config = dir.path().join("rpxy.toml");
  let old = targets.join("old.toml");
  let new = targets.join("new.toml");
  write_http_config(&old, addr, "old.example");
  write_http_config(&new, addr, "new.example");
  symlink(old, &config).unwrap();

  let mut proxy = ProxyProcess::start(&config);
  proxy.wait_for_log(|out| out.contains(HTTP_LISTENER_STARTED) && out.contains("Realtime watching established"));
  assert_eq!(response_status(addr, "old.example"), 404);

  // The watcher tracks the canonical target's directory. Replace only the symlink.
  let replacement = dir.path().join("next.toml");
  symlink(new, &replacement).unwrap();
  fs::rename(replacement, &config).unwrap();
  proxy.wait_for_log(|out| out.matches(HTTP_LISTENER_STARTED).count() >= 2);
  assert_eq!(response_status(addr, "new.example"), 404);
}

fn run_config_check(config: &Path, input: &str) -> (ExitStatus, String) {
  fs::write(config, input).unwrap();
  let mut proxy = ProxyProcess::start_with_args(config, &["--check-config"]);
  (proxy.wait_for_exit(), proxy.output())
}

#[test]
fn check_config_validates_tls_on_an_occupied_port() {
  let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
  let dir = tempfile::tempdir().unwrap();
  let config = dir.path().join("check.toml");
  let input = tls_config(occupied.local_addr().unwrap().port())
    + &format!("client_ca_cert_path = '{}'\n", cert_fixture("client.ca.crt").display());

  let (status, output) = run_config_check(&config, &input);
  assert!(status.success(), "{output}");
  assert!(output.contains("Configuration is valid"), "{output}");
}

#[test]
fn check_config_rejects_tls_files_that_cannot_serve_the_domain() {
  let dir = tempfile::tempdir().unwrap();
  let config = dir.path().join("check.toml");
  let valid = tls_config(8443);
  let empty_ca = dir.path().join("empty-ca.crt");
  fs::write(&empty_ca, "").unwrap();

  let cases = [
    (valid.replace("server.crt", "missing.crt"), "Unable to load the certificates"),
    (
      valid.replace("server.key", "client.key"),
      "Cannot match the server certificate to its private key",
    ),
    (
      valid.replace("server_name = 'localhost'", "server_name = 'other.example'"),
      "Cannot use the server certificate for the configured hostname",
    ),
    (
      valid.clone() + &format!("client_ca_cert_path = '{}'\n", empty_ca.display()),
      "no usable trust anchors",
    ),
  ];
  for (input, diagnostic) in cases {
    let (status, output) = run_config_check(&config, &input);
    assert_eq!(status.code(), Some(1), "{output}");
    assert!(output.contains("Invalid TLS files"), "{output}");
    assert!(output.contains(diagnostic), "{output}");
  }
}

#[test]
fn check_config_rejects_misconfigured_routes_and_redacts_toml_source() {
  let dir = tempfile::tempdir().unwrap();
  let config = dir.path().join("check.toml");
  let base = "
listen_port = 8080
[apps.local]
server_name = 'localhost'
[[apps.local.reverse_proxy]]
upstream = [{ location = '127.0.0.1:8081' }]
";
  let cases = [
    (format!("{base}upstrean_options = []"), "upstrean_options"),
    (format!("{base}load_balance = 'weightedd'"), "load_balance"),
    (format!("{base}replace_path = '/example?query'"), "replace_path"),
    (
      format!("{base}upstream_options = ['force_http11_upstream', 'force_http2_upstream']"),
      "Invalid routes",
    ),
    (
      format!("{base}[[apps.local.reverse_proxy]]\npath = '/'\nupstream = [{{ location = '127.0.0.1:8082' }}]"),
      "duplicate path",
    ),
    (
      format!(
        "{base}[apps.second]\nserver_name = 'LOCALHOST'\nreverse_proxy = [{{ upstream = [{{ location = '127.0.0.1:8082' }}] }}]"
      ),
      "Duplicate server_name",
    ),
    (
      base.replace("listen_port = 8080", "listen_port = 'private-test-value'"),
      "Invalid TOML or wrong field type",
    ),
  ];
  for (input, diagnostic) in cases {
    let (status, output) = run_config_check(&config, &input);
    assert_eq!(status.code(), Some(1), "{output}");
    assert!(output.contains(diagnostic), "{output}");
    assert!(!output.contains("private-test-value"), "{output}");
  }
}

#[cfg(not(any(feature = "http3-quinn", feature = "http3-s2n")))]
#[test]
fn check_config_reports_http3_unavailable_in_this_binary() {
  let dir = tempfile::tempdir().unwrap();
  let config = dir.path().join("check.toml");
  let (status, output) = run_config_check(&config, &(tls_config(8443) + "\n[experimental.h3]\n"));
  assert_eq!(status.code(), Some(1), "{output}");
  assert!(output.contains("experimental.h3 requires an HTTP/3 feature"), "{output}");
}

#[cfg(feature = "acme")]
#[test]
fn check_config_checks_acme_settings_without_creating_the_registry() {
  let dir = tempfile::tempdir().unwrap();
  let config = dir.path().join("check.toml");
  let input = "
listen_port_tls = 8443
[apps.local]
server_name = 'localhost'
reverse_proxy = [{ upstream = [{ location = '127.0.0.1:8081' }] }]
[apps.local.tls]
acme = true
[experimental.acme]
email = 'operator@example.test'
dir_url = 'https://acme.example.test/directory'
registry_path = 'acme-registry'
";
  let (status, output) = run_config_check(&config, input);
  assert!(status.success(), "{output}");
  assert!(!dir.path().join("acme-registry").exists());

  let invalid = input.replace("https://acme.example.test/directory", "file:///tmp");
  let (status, output) = run_config_check(&config, &invalid);
  assert_eq!(status.code(), Some(1), "{output}");
  assert!(output.contains("ACME directory URL must use HTTP or HTTPS"), "{output}");
  assert!(!dir.path().join("acme-registry").exists());
}
