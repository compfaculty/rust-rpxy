use crate::{
  AppConfig, AppConfigList,
  error::*,
  log::*,
  name_exp::{ByteName, ServerName},
};
use ahash::{HashMap, HashSet};
use anyhow::{Context, ensure};
use derive_builder::Builder;
use http::uri::PathAndQuery;
use std::borrow::Cow;

use super::{UpstreamOption, load_balance::load_balance_options, upstream::PathManager};

impl AppConfigList {
  /// Check that configured routes can be built and that every entry takes effect.
  /// This is used by the CLI's strict configuration check before starting services.
  pub fn validate_routes(&self) -> anyhow::Result<()> {
    let mut app_names = HashSet::default();
    let mut server_names = HashSet::default();
    for app in &self.inner {
      ensure!(
        app_names.insert(app.app_name.to_ascii_lowercase()),
        "Duplicate app name {:?}",
        app.app_name
      );
      ensure!(
        server_names.insert(app.server_name.as_str().to_server_name()),
        "Duplicate server_name {:?}",
        app.server_name
      );
      ensure!(
        !app.reverse_proxy.is_empty(),
        "App {:?} has no reverse_proxy routes",
        app.app_name
      );
      let mut paths = HashSet::default();
      for (index, route) in app.reverse_proxy.iter().enumerate() {
        let path = route.path.as_deref().unwrap_or("/");
        let entry = format!("apps.{}.reverse_proxy[{index}]", app.app_name);
        ensure!(paths.insert(path), "{entry}: duplicate path {path:?}");
        for (field, value) in [("path", Some(path)), ("replace_path", route.replace_path.as_deref())] {
          if let Some(value) = value {
            ensure!(
              value.starts_with('/')
                && value
                  .parse::<PathAndQuery>()
                  .is_ok_and(|path| path.query().is_none() && path.as_str() == value),
              "{entry}.{field} must be an absolute URL path without a query or fragment"
            );
          }
        }
        if let Some(mode) = route.load_balance.as_deref() {
          match mode {
            load_balance_options::FIX_TO_FIRST | load_balance_options::RANDOM | load_balance_options::ROUND_ROBIN => {}
            #[cfg(feature = "sticky-cookie")]
            load_balance_options::STICKY_ROUND_ROBIN => {}
            #[cfg(feature = "health-check")]
            load_balance_options::PRIMARY_BACKUP => {}
            _ => anyhow::bail!("{entry}.load_balance {mode:?} is unknown or unavailable in this build"),
          }
        }
        for option in route.upstream_options.iter().flatten() {
          UpstreamOption::try_from(option.as_str())
            .with_context(|| format!("{entry}.upstream_options contains unknown option {option:?}"))?;
        }
        #[cfg(not(any(feature = "rustls-backend", feature = "native-tls-backend")))]
        ensure!(
          route
            .upstream
            .iter()
            .all(|upstream| upstream.inner.scheme_str() != Some("https")),
          "{entry} requires HTTPS upstream support (rustls-backend or native-tls-backend)"
        );
      }
      PathManager::try_from(app).with_context(|| format!("Invalid routes for app {:?}", app.app_name))?;
    }
    if let Some(default_app) = &self.default_app {
      ensure!(
        app_names.contains(&default_app.to_ascii_lowercase()),
        "default_app {default_app:?} does not name a configured app"
      );
    }
    Ok(())
  }
}

/// Struct serving information to route incoming connections, like server name to be handled and tls certs/keys settings.
#[derive(Builder)]
pub struct BackendApp {
  #[builder(setter(into))]
  /// backend application name, e.g., app1
  pub app_name: String,
  #[builder(setter(custom))]
  /// server name, e.g., example.com, in [[ServerName]] object
  pub server_name: ServerName,
  /// struct of reverse proxy serving incoming request
  pub path_manager: PathManager,
  /// tls settings: https redirection with 30x
  #[builder(default)]
  pub https_redirection: Option<bool>,
  /// tls settings: mutual TLS is enabled
  #[builder(default)]
  pub mutual_tls: Option<bool>,
}
impl<'a> BackendAppBuilder {
  pub fn server_name(&mut self, server_name: impl Into<Cow<'a, str>>) -> &mut Self {
    self.server_name = Some(server_name.to_server_name());
    self
  }
}

#[derive(Default)]
/// HashMap and some meta information for multiple Backend structs.
pub struct BackendAppManager {
  /// HashMap of Backend structs, key is server name
  pub apps: HashMap<ServerName, BackendApp>,
  /// for plaintext http
  pub default_server_name: Option<ServerName>,
}

impl TryFrom<&AppConfig> for BackendApp {
  type Error = RpxyError;

  fn try_from(app_config: &AppConfig) -> Result<Self, Self::Error> {
    let mut backend_builder = BackendAppBuilder::default();
    let path_manager = PathManager::try_from(app_config)?;
    backend_builder
      .app_name(app_config.app_name.clone())
      .server_name(app_config.server_name.clone())
      .path_manager(path_manager);
    // TLS settings and build backend instance
    let backend = if let Some(tls) = app_config.tls.as_ref() {
      backend_builder
        .https_redirection(Some(tls.https_redirection))
        .mutual_tls(Some(tls.mutual_tls))
        .build()?
    } else {
      backend_builder.build()?
    };
    Ok(backend)
  }
}

impl TryFrom<&AppConfigList> for BackendAppManager {
  type Error = RpxyError;

  fn try_from(config_list: &AppConfigList) -> Result<Self, Self::Error> {
    let mut manager = Self::default();
    for app_config in config_list.inner.iter() {
      let backend: BackendApp = BackendApp::try_from(app_config)?;
      manager.apps.insert(app_config.server_name.clone().to_server_name(), backend);

      info!(
        "Registering application {} ({})",
        &app_config.server_name, &app_config.app_name
      );
    }

    // default backend application for plaintext http requests
    let Some(default_app_name) = &config_list.default_app else {
      return Ok(manager);
    };

    let default_server_name = manager
      .apps
      .iter()
      .filter(|(_k, v)| &v.app_name == default_app_name)
      .map(|(_, v)| v.server_name.clone())
      .collect::<Vec<_>>();

    if !default_server_name.is_empty() {
      info!(
        "Serving plaintext http for requests to unconfigured server_name by app {} (server_name: {}).",
        &default_app_name,
        (&default_server_name[0]).try_into().unwrap_or_else(|_| "".to_string())
      );

      manager.default_server_name = Some(default_server_name[0].clone());
    }

    Ok(manager)
  }
}
