use super::ProxyProcess;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Bytes, client::conn, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use std::{convert::Infallible, fs, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{
  net::{TcpListener, TcpStream},
  time::timeout,
};
use tokio_rustls::{
  TlsConnector,
  rustls::{
    self, ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
  },
};

const PUBLIC_HOST: &str = "public.example.test";
const PRIVATE_HOST: &str = "private.example.test";
const IO_TIMEOUT: Duration = Duration::from_secs(5);

async fn upstream(body: &'static str) -> SocketAddr {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  tokio::spawn(async move {
    while let Ok((socket, _)) = listener.accept().await {
      tokio::spawn(async move {
        http1::Builder::new()
          .serve_connection(
            TokioIo::new(socket),
            service_fn(
              move |_| async move { Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(body.as_bytes())))) },
            ),
          )
          .await
          .unwrap();
      });
    }
  });
  addr
}

fn server_identity(dir: &Path, host: &str) -> CertificateDer<'static> {
  let identity = rcgen::generate_simple_self_signed(vec![host.to_owned()]).unwrap();
  fs::write(dir.join(format!("{host}.crt")), identity.cert.pem()).unwrap();
  fs::write(dir.join(format!("{host}.key")), identity.signing_key.serialize_pem()).unwrap();
  identity.cert.der().clone()
}

fn client_identity(dir: &Path) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
  let mut ca = CertificateParams::default();
  ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
  let ca_key = KeyPair::generate().unwrap();
  fs::write(dir.join("client-ca.crt"), ca.self_signed(&ca_key).unwrap().pem()).unwrap();

  let mut client = CertificateParams::default();
  client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
  let client_key = KeyPair::generate().unwrap();
  let cert = client.signed_by(&client_key, &Issuer::from_params(&ca, &ca_key)).unwrap();
  (cert.der().clone(), client_key.into())
}

async fn tcp_request(
  addr: SocketAddr,
  host: &str,
  cert: &CertificateDer<'_>,
  config: ClientConfig,
  alpn: &[u8],
) -> anyhow::Result<Bytes> {
  let stream = TlsConnector::from(Arc::new(config))
    .connect(host.to_owned().try_into()?, TcpStream::connect(addr).await?)
    .await?;
  let tls = stream.get_ref().1;
  assert_eq!(tls.alpn_protocol(), Some(alpn));
  assert_eq!(tls.peer_certificates().unwrap(), std::slice::from_ref(cert));

  let uri = if alpn == b"h2" {
    format!("https://{host}/service/probe").parse::<hyper::Uri>()?
  } else {
    hyper::Uri::from_static("/service/probe")
  };
  let request = Request::get(uri)
    .header(hyper::header::HOST, host)
    .body(Full::<Bytes>::default())?;
  let response = if alpn == b"h2" {
    let (mut sender, connection) = conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await?;
    tokio::spawn(connection);
    sender.send_request(request).await?
  } else {
    let (mut sender, connection) = conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(connection);
    sender.send_request(request).await?
  };
  assert_eq!(response.status(), StatusCode::OK);
  Ok(response.into_body().collect().await?.to_bytes())
}

#[tokio::test]
async fn multi_domain_tls_routes_to_distinct_upstreams() {
  let dir = tempfile::tempdir().unwrap();
  let config_path = dir.path().join("rpxy.toml");
  let public_cert = server_identity(dir.path(), PUBLIC_HOST);
  let private_cert = server_identity(dir.path(), PRIVATE_HOST);
  let (client_cert, client_key) = client_identity(dir.path());
  let public_upstream = upstream("public upstream").await;
  let private_upstream = upstream("private upstream").await;
  let port_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
  let addr = port_reservation.local_addr().unwrap();
  #[cfg(any(feature = "http3-quinn", feature = "http3-s2n"))]
  let udp_reservation = std::net::UdpSocket::bind(addr).unwrap();

  let mut config = format!(
    "
listen_address_v4 = '127.0.0.1'
listen_port_tls = {}
[apps.public]
server_name = '{PUBLIC_HOST}'
reverse_proxy = [{{ path = '/service', upstream = [{{ location = '{public_upstream}' }}] }}]
tls = {{ tls_cert_path = '{PUBLIC_HOST}.crt', tls_cert_key_path = '{PUBLIC_HOST}.key' }}
[apps.private]
server_name = '{PRIVATE_HOST}'
reverse_proxy = [{{ path = '/service', upstream = [{{ location = '{private_upstream}' }}] }}]
tls = {{ tls_cert_path = '{PRIVATE_HOST}.crt', tls_cert_key_path = '{PRIVATE_HOST}.key', client_ca_cert_path = 'client-ca.crt' }}
",
    addr.port()
  );
  if cfg!(any(feature = "http3-quinn", feature = "http3-s2n")) {
    config.push_str("\n[experimental.h3]\n");
  }
  fs::write(&config_path, config).unwrap();
  drop(port_reservation);
  #[cfg(any(feature = "http3-quinn", feature = "http3-s2n"))]
  drop(udp_reservation);

  let mut proxy = ProxyProcess::start(&config_path);
  proxy.wait_for_log(|log| log.contains("TLS certificates updated successfully"));

  let mut roots = RootCertStore::empty();
  roots.add(public_cert.clone()).unwrap();
  roots.add(private_cert.clone()).unwrap();
  let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
  for alpn in [b"http/1.1".as_slice(), b"h2"] {
    let mut anonymous = ClientConfig::builder_with_provider(provider.clone())
      .with_safe_default_protocol_versions()
      .unwrap()
      .with_root_certificates(roots.clone())
      .with_no_client_auth();
    anonymous.alpn_protocols = vec![alpn.to_vec()];
    let mut authenticated = ClientConfig::builder_with_provider(provider.clone())
      .with_safe_default_protocol_versions()
      .unwrap()
      .with_root_certificates(roots.clone())
      .with_client_auth_cert(vec![client_cert.clone()], client_key.clone_key())
      .unwrap();
    authenticated.alpn_protocols = vec![alpn.to_vec()];
    for (host, cert, client, expected) in [
      (PUBLIC_HOST, &public_cert, anonymous, "public upstream"),
      (PRIVATE_HOST, &private_cert, authenticated, "private upstream"),
    ] {
      let response = timeout(IO_TIMEOUT, tcp_request(addr, host, cert, client, alpn))
        .await
        .unwrap_or_else(|_| panic!("timed out requesting {host}: {}", proxy.output()))
        .unwrap_or_else(|e| panic!("request to {host} failed: {e:#}\n{}", proxy.output()));
      assert_eq!(response.as_ref(), expected.as_bytes(), "{host} via {alpn:?}");
    }
  }

  // TLS 1.2 reports the missing client identity during the handshake itself.
  let anonymous_tls12 = ClientConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(&[&rustls::version::TLS12])
    .unwrap()
    .with_root_certificates(roots.clone())
    .with_no_client_auth();
  let failure = timeout(
    IO_TIMEOUT,
    TlsConnector::from(Arc::new(anonymous_tls12))
      .connect(PRIVATE_HOST.try_into().unwrap(), TcpStream::connect(addr).await.unwrap()),
  )
  .await
  .unwrap()
  .expect_err("mTLS host accepted a client without a certificate");
  assert!(
    matches!(
      failure.get_ref().and_then(|error| error.downcast_ref::<rustls::Error>()),
      Some(rustls::Error::AlertReceived(
        rustls::AlertDescription::CertificateRequired | rustls::AlertDescription::HandshakeFailure
      )),
    ),
    "{failure}"
  );

  #[cfg(any(feature = "http3-quinn", feature = "http3-s2n"))]
  check_http3(addr, roots, &public_cert, &proxy).await;
}

#[cfg(any(feature = "http3-quinn", feature = "http3-s2n"))]
async fn check_http3(addr: SocketAddr, roots: RootCertStore, public_cert: &CertificateDer<'_>, proxy: &ProxyProcess) {
  use hyper::body::Buf;
  use quinn::{ConnectionError, Endpoint, TransportConfig, crypto::rustls::QuicClientConfig};

  let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
  config.alpn_protocols = vec![b"h3".to_vec()];
  let crypto = Arc::new(QuicClientConfig::try_from(config).unwrap());
  let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
  endpoint.set_default_client_config(quinn::ClientConfig::new(crypto.clone()));

  // The UDP listener installs certificates independently of the TCP listener.
  let connection = timeout(IO_TIMEOUT, async {
    loop {
      let connecting = endpoint.connect(addr, PUBLIC_HOST).unwrap();
      if let Ok(Ok(connection)) = timeout(Duration::from_millis(250), connecting).await {
        break connection;
      }
      tokio::time::sleep(Duration::from_millis(20)).await;
    }
  })
  .await
  .unwrap_or_else(|_| panic!("HTTP/3 endpoint did not become ready:\n{}", proxy.output()));
  let chain = connection
    .peer_identity()
    .unwrap()
    .downcast::<Vec<CertificateDer<'static>>>()
    .unwrap();
  assert_eq!(&*chain, std::slice::from_ref(public_cert));

  let body = timeout(IO_TIMEOUT, async {
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection)).await?;
    let driver = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let mut stream = sender
      .send_request(Request::get(format!("https://{PUBLIC_HOST}/service/probe")).body(())?)
      .await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = Vec::new();
    while let Some(mut data) = stream.recv_data().await? {
      let size = data.remaining();
      body.extend_from_slice(&data.copy_to_bytes(size));
    }
    driver.abort();
    Ok::<_, anyhow::Error>(body)
  })
  .await
  .unwrap()
  .unwrap();
  assert_eq!(body, b"public upstream");

  // The listener can discard an unroutable handshake without sending an alert.
  // Bound the client's idle time and confirm that the public hostname still works.
  let mut transport = TransportConfig::default();
  transport.max_idle_timeout(Some(Duration::from_secs(2).try_into().unwrap()));
  let mut client = quinn::ClientConfig::new(crypto);
  client.transport_config(Arc::new(transport));
  let failure = timeout(IO_TIMEOUT, endpoint.connect_with(client, addr, PRIVATE_HOST).unwrap())
    .await
    .unwrap_or_else(|_| panic!("HTTP/3 client did not finish the handshake attempt:\n{}", proxy.output()))
    .expect_err("HTTP/3 accepted a hostname configured for mTLS");
  assert!(
    matches!(
      failure,
      ConnectionError::ConnectionClosed(_) | ConnectionError::TransportError(_) | ConnectionError::TimedOut
    ),
    "{failure}"
  );
  timeout(IO_TIMEOUT, endpoint.connect(addr, PUBLIC_HOST).unwrap())
    .await
    .expect("public HTTP/3 hostname timed out after the denied handshake")
    .expect("public HTTP/3 hostname failed after the denied handshake");
}
