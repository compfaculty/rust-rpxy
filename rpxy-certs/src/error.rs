use thiserror::Error;

/// Describes things that can go wrong in the Rpxy certificate
#[derive(Debug, Error)]
pub enum RpxyCertError {
  /// Error when reading certificates and keys
  #[error("Failed to read certificates from file: {0}")]
  IoError(#[from] std::io::Error),
  /// Error when parsing certificates and keys to generate a rustls CertifiedKey
  #[error("Unable to find a valid certificate and key")]
  InvalidCertificateAndKey,
  #[error("Cannot match the server certificate to its private key")]
  InvalidServerCertificateKey(#[source] rustls::Error),
  #[error("Cannot use the server certificate for the configured hostname")]
  InvalidServerCertificateName(#[source] rustls::Error),
  #[error("Server certificate {position} is not valid X.509")]
  InvalidServerCertificate { position: usize },
  #[error("Server certificate {position} is expired or not yet valid")]
  InvalidServerCertificateValidity { position: usize },
  #[error("Client CA file contains no usable trust anchors with a subject key identifier")]
  NoUsableClientCaCertificates,
  /// Error when parsing client CA certificates: No client certificate found
  #[error("No client certificate found")]
  NoClientCert,
  /// Error for hot reload certificate reloader
  #[error("Certificate reload error: {0}")]
  CertificateReloadError(#[from] hot_reload::ReloaderError<crate::server_crypto::ServerCryptoBase>),
  /// Error when converting server name bytes to string
  #[error("Failed to convert server name bytes to string: {0}")]
  ServerNameBytesToString(#[from] std::string::FromUtf8Error),
  /// Rustls error
  #[error("Rustls error: {0}")]
  RustlsError(#[from] rustls::Error),
  /// Rustls CryptoProvider error
  #[error("Rustls No default CryptoProvider error")]
  NoDefaultCryptoProvider,
}
