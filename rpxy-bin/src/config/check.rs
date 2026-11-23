#[cfg(feature = "sticky-cookie")]
use super::build_sticky_cookie_secret;
use super::{build_settings, parse::tls_file_source, toml::ConfigToml};
use anyhow::{Context, anyhow, ensure};
use std::path::Path;

pub fn check_config(path: &Path) -> anyhow::Result<()> {
  let input = std::fs::read_to_string(path).context("Cannot read TOML file")?;
  let (config, unsupported_fields) = ConfigToml::deserialize_with_unsupported_fields(&input).map_err(|error| {
    // TOML errors can quote the source line, including secrets in malformed values.
    if let Some(span) = error.span() {
      let line = input
        .as_bytes()
        .iter()
        .take(span.start)
        .filter(|&&byte| byte == b'\n')
        .count()
        + 1;
      anyhow!("Invalid TOML or wrong field type at line {line}")
    } else {
      anyhow!("Invalid TOML or wrong field type")
    }
  })?;
  ensure!(
    unsupported_fields.is_empty(),
    "Configuration contains fields that are unknown, misplaced, or unavailable in this build:\n{}",
    unsupported_fields.join("\n")
  );
  let (_, apps) = build_settings(&config)?;
  #[cfg(feature = "sticky-cookie")]
  build_sticky_cookie_secret(&config)?;
  apps.validate_routes()?;

  if config.experimental.as_ref().is_some_and(|options| options.h3.is_some()) {
    ensure!(
      cfg!(any(feature = "http3-quinn", feature = "http3-s2n")),
      "experimental.h3 requires an HTTP/3 feature (http3-quinn or http3-s2n)"
    );
    ensure!(config.listen_port_tls.is_some(), "experimental.h3 requires listen_port_tls");
  }

  #[cfg(feature = "acme")]
  let acme = config.experimental.as_ref().and_then(|options| options.acme.as_ref());
  #[cfg(feature = "acme")]
  if let Some(acme) = acme {
    rpxy_acme::AcmeManager::check_config(acme.dir_url.as_deref(), acme.registry_path.as_deref())
      .context("Invalid experimental.acme settings")?;
  }

  let raw_apps = &config.apps.as_ref().expect("validated application settings").0;
  ensure!(
    config.listen_port_tls.is_some() == raw_apps.values().any(|app| app.tls.is_some()),
    "listen_port_tls and at least one app's TLS settings must be configured together"
  );
  for (name, app) in raw_apps {
    let Some(tls) = &app.tls else { continue };
    #[cfg(feature = "acme")]
    if tls.acme == Some(true) {
      ensure!(acme.is_some(), "apps.{name}.tls.acme requires experimental.acme");
      if let Some(path) = tls.client_ca_cert_path.as_deref() {
        rpxy_certs::CryptoFileSource::validate_client_ca(Path::new(path))
          .with_context(|| format!("Invalid client CA for apps.{name}.tls"))?;
      }
      continue;
    }

    let server_name = app.server_name.as_deref().expect("validated server_name");
    tls_file_source(tls)?
      .validate(server_name)
      .with_context(|| format!("Invalid TLS files for apps.{name} ({server_name})"))?;
  }
  Ok(())
}
