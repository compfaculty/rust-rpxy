// Global allocator selection.
// - `dhat-heap` (developer-only profiling): use dhat's allocator on every OS.
// - otherwise: mimalloc, except on illumos where the implicit system allocator is used.
// The cfgs are mutually exclusive, so at most one `#[global_allocator]` is defined
// (none in the non-`dhat-heap` illumos case, which falls back to the system allocator).
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[cfg(all(not(feature = "dhat-heap"), not(target_os = "illumos")))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

// With `dhat-heap`, dhat's allocator replaces mimalloc, which is then compiled but never
// referenced. Mark it as intentionally unused for cargo's `unused_dependencies` lint.
#[cfg(all(feature = "dhat-heap", not(target_os = "illumos")))]
use mimalloc as _;

mod config;
mod constants;
mod error;
mod log;

#[cfg(feature = "acme")]
use crate::config::build_acme_manager;
#[cfg(feature = "sticky-cookie")]
use crate::config::build_sticky_cookie_secret;
use crate::{
  config::{ConfigToml, ConfigTomlReloader, build_cert_manager, build_settings, check_config, parse_opts},
  constants::CONFIG_WATCH_DELAY_SECS,
  error::*,
  log::*,
};
use hot_reload::{AsyncFileLoad, ReloaderConfig, ReloaderReceiver, ReloaderService};
#[cfg(feature = "sticky-cookie")]
use rpxy_lib::StickyCookieSecret;
use rpxy_lib::{RpxyOptions, RpxyOptionsBuilder, entrypoint};
use std::{sync::Arc, time::Duration};
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tokio_util::sync::CancellationToken;

fn main() {
  let parsed_opts = parse_opts();
  if parsed_opts.check_config {
    init_logger(None);
    let path = std::path::Path::new(&parsed_opts.config_file_path);
    match check_config(path) {
      Ok(()) => println!("Configuration is valid."),
      Err(error) => {
        eprintln!("Configuration check failed for {}: {error:#}", path.display());
        std::process::exit(1);
      }
    }
    return;
  }

  // Keep the heap profiler alive for the whole process. On drop it writes
  // `dhat-heap.json`; because `std::process::exit` skips destructors, the exit
  // call below is moved out of the async block and the profiler is dropped first.
  #[cfg(feature = "dhat-heap")]
  let dhat_profiler = dhat::Profiler::new_heap();

  let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
  runtime_builder.enable_all();
  runtime_builder.thread_name("rpxy");
  let runtime = runtime_builder.build().unwrap();

  let exit_code: i32 = runtime.block_on(async {
    init_logger(parsed_opts.log_dir_path.as_deref());

    // Read the unsafe debug-header logging opt-out once at startup.
    // Not hot-reloaded; threaded into rpxy-lib via RpxyOptions.
    let unsafe_debug_headers = unsafe_debug_headers_enabled();

    // Whether the logger installed above will emit access-log lines; threaded
    // into rpxy-lib so the per-request log record is skipped when no line can
    // be emitted. Not hot-reloaded, like the logger itself.
    let access_log_enabled = access_log_enabled(parsed_opts.log_dir_path.as_deref());

    let config_path = &parsed_opts.config_file_path;
    let initial_config = match ConfigToml::async_load_from(config_path).await {
      Ok(config) => config,
      Err(e) => {
        error!("Cannot load configuration from {config_path}: {e}");
        return 1;
      }
    };
    let reloader_config = ReloaderConfig::hybrid(CONFIG_WATCH_DELAY_SECS);

    let (config_service, config_rx) =
      match ReloaderService::<ConfigTomlReloader, ConfigToml, String>::new(config_path, reloader_config).await {
        Ok(reloader) => reloader,
        Err(e) => {
          error!("Cannot watch configuration at {config_path}: {e}");
          return 1;
        }
      };

    // When profiling, allow Ctrl-C to return gracefully so the dhat profiler is
    // dropped and `dhat-heap.json` is flushed. In normal builds this future never
    // resolves, so the select arm is inert and process behavior is unchanged.
    let shutdown_signal = async {
      #[cfg(feature = "dhat-heap")]
      {
        let _ = tokio::signal::ctrl_c().await;
      }
      #[cfg(not(feature = "dhat-heap"))]
      {
        std::future::pending::<()>().await;
      }
    };

    tokio::select! {
      config_res = config_service.start_with_realtime() => {
        if let Err(e) = config_res {
          error!("config reloader service exited: {e}");
          return 1;
        }
      }
      rpxy_res = rpxy_service(config_path, initial_config, config_rx, runtime.handle().clone(), unsafe_debug_headers, access_log_enabled) => {
        if let Err(e) = rpxy_res {
          error!("rpxy service exited: {e}");
          return 1;
        }
      }
      _ = shutdown_signal => {
        info!("SIGINT received; shutting down to flush the dhat heap profile");
      }
    }
    0
  });

  // Quiesce the runtime before flushing the heap profile: stop the worker threads
  // (giving in-flight tasks a brief grace period) so they are not still allocating
  // while the profiler is dropped and `dhat-heap.json` is written. Then drop the
  // profiler explicitly, since the exit below skips destructors.
  #[cfg(feature = "dhat-heap")]
  {
    runtime.shutdown_timeout(std::time::Duration::from_millis(200));
    drop(dhat_profiler);
  }

  std::process::exit(exit_code);
}

/// rpxy service definition
struct RpxyService {
  runtime_handle: tokio::runtime::Handle,
  proxy_conf: rpxy_lib::ProxyConfig,
  app_conf: rpxy_lib::AppConfigList,
  cert_service: Option<Arc<ReloaderService<rpxy_certs::CryptoReloader, rpxy_certs::ServerCryptoBase>>>,
  cert_rx: Option<ReloaderReceiver<rpxy_certs::ServerCryptoBase>>,
  /// Operator opt-out for credential-header redaction in DEBUG logs,
  /// read once at startup from `RPXY_UNSAFE_DEBUG_HEADERS`.
  unsafe_debug_headers: bool,
  /// Whether the installed logger emits access-log lines, determined once at
  /// startup from the log mode and `RUST_LOG` (see `log::access_log_enabled`).
  access_log_enabled: bool,
  #[cfg(feature = "sticky-cookie")]
  sticky_cookie_secret: Option<Arc<StickyCookieSecret>>,
  #[cfg(feature = "acme")]
  acme_manager: Option<rpxy_acme::AcmeManager>,
}

impl RpxyService {
  /// Create a new RpxyService from config and runtime handle.
  async fn new(
    config_toml: &ConfigToml,
    runtime_handle: tokio::runtime::Handle,
    unsafe_debug_headers: bool,
    access_log_enabled: bool,
  ) -> Result<Self, anyhow::Error> {
    let (proxy_conf, app_conf) = build_settings(config_toml).map_err(|e| anyhow!("Invalid configuration: {e}"))?;
    #[cfg(feature = "sticky-cookie")]
    let sticky_cookie_secret =
      build_sticky_cookie_secret(config_toml).map_err(|e| anyhow!("Invalid sticky-cookie configuration: {e}"))?;

    let (cert_service, cert_rx) = build_cert_manager(config_toml)
      .await
      .map_err(|e| anyhow!("Invalid cert configuration: {e}"))?
      .map(|(s, r)| (Some(Arc::new(s)), Some(r)))
      .unwrap_or((None, None));

    Ok(Self {
      runtime_handle: runtime_handle.clone(),
      proxy_conf,
      app_conf,
      cert_service,
      cert_rx,
      unsafe_debug_headers,
      access_log_enabled,
      #[cfg(feature = "sticky-cookie")]
      sticky_cookie_secret,
      #[cfg(feature = "acme")]
      acme_manager: build_acme_manager(config_toml, runtime_handle.clone()).await?,
    })
  }

  async fn start(&self, cancel_token: CancellationToken) -> Result<(), anyhow::Error> {
    let RpxyService {
      runtime_handle,
      proxy_conf,
      app_conf,
      cert_service: _,
      cert_rx,
      unsafe_debug_headers,
      access_log_enabled,
      #[cfg(feature = "sticky-cookie")]
      sticky_cookie_secret,
      #[cfg(feature = "acme")]
      acme_manager,
    } = self;

    #[cfg(feature = "acme")]
    {
      let (acme_join_handles, server_config_acme_challenge) = acme_manager
        .as_ref()
        .map(|m| m.spawn_manager_tasks(cancel_token.child_token()))
        .unwrap_or((vec![], Default::default()));
      let mut builder = RpxyOptionsBuilder::default();
      builder
        .proxy_config(proxy_conf.clone())
        .app_config_list(app_conf.clone())
        .cert_rx(cert_rx.clone())
        .runtime_handle(runtime_handle.clone())
        .unsafe_debug_headers(*unsafe_debug_headers)
        .access_log_enabled(*access_log_enabled)
        .server_configs_acme_challenge(Arc::new(server_config_acme_challenge));
      #[cfg(feature = "sticky-cookie")]
      builder.sticky_cookie_secret(sticky_cookie_secret.clone());
      let rpxy_opts = builder.build()?;
      self
        .start_inner(rpxy_opts, cancel_token, acme_join_handles)
        .await
        .map_err(|e| anyhow!(e))
    }

    #[cfg(not(feature = "acme"))]
    {
      let mut builder = RpxyOptionsBuilder::default();
      builder
        .proxy_config(proxy_conf.clone())
        .app_config_list(app_conf.clone())
        .cert_rx(cert_rx.clone())
        .runtime_handle(runtime_handle.clone())
        .unsafe_debug_headers(*unsafe_debug_headers)
        .access_log_enabled(*access_log_enabled);
      #[cfg(feature = "sticky-cookie")]
      builder.sticky_cookie_secret(sticky_cookie_secret.clone());
      let rpxy_opts = builder.build()?;
      self.start_inner(rpxy_opts, cancel_token).await.map_err(|e| anyhow!(e))
    }
  }

  /// Wrapper of entry point for rpxy service with certificate management service
  async fn start_inner(
    &self,
    rpxy_opts: RpxyOptions,
    cancel_token: CancellationToken,
    #[cfg(feature = "acme")] acme_task_handles: Vec<tokio::task::JoinHandle<()>>,
  ) -> Result<(), anyhow::Error> {
    let cancel_token = cancel_token.clone();
    let runtime_handle = rpxy_opts.runtime_handle.clone();

    // spawn rpxy entrypoint, where cancellation token is possibly contained inside the service
    let cancel_token_clone = cancel_token.clone();
    let child_cancel_token = cancel_token.child_token();
    let rpxy_handle = runtime_handle.spawn(async move {
      if let Err(e) = entrypoint(&rpxy_opts, child_cancel_token).await {
        error!("rpxy entrypoint exited on error: {e}");
        cancel_token_clone.cancel();
        return Err(anyhow!(e));
      }
      Ok(())
    });

    if self.cert_service.is_none() {
      return rpxy_handle.await?;
    }

    // spawn certificate reloader service, where cert service does not have cancellation token inside the service
    let cert_service = self.cert_service.as_ref().unwrap().clone();
    let cancel_token_clone = cancel_token.clone();
    let child_cancel_token = cancel_token.child_token();
    let cert_handle = runtime_handle.spawn(async move {
      tokio::select! {
        cert_res = cert_service.start() => {
          if let Err(ref e) = cert_res {
            error!("cert reloader service exited on error: {e}");
          }
          cancel_token_clone.cancel();
          cert_res.map_err(|e| anyhow!(e))
        }
        _ = child_cancel_token.cancelled() => {
          debug!("cert reloader service terminated");
          Ok(())
        }
      }
    });

    #[cfg(not(feature = "acme"))]
    {
      let (rpxy_res, cert_res) = tokio::join!(rpxy_handle, cert_handle);
      let (rpxy_res, cert_res) = (rpxy_res?, cert_res?);
      match (rpxy_res, cert_res) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), _) => Err(e),
        (_, Err(e)) => Err(e),
      }
    }

    #[cfg(feature = "acme")]
    {
      if acme_task_handles.is_empty() {
        let (rpxy_res, cert_res) = tokio::join!(rpxy_handle, cert_handle);
        let (rpxy_res, cert_res) = (rpxy_res?, cert_res?);
        return match (rpxy_res, cert_res) {
          (Ok(()), Ok(())) => Ok(()),
          (Err(e), _) => Err(e),
          (_, Err(e)) => Err(e),
        };
      }

      // spawn acme manager tasks, where cancellation token is possibly contained inside the service
      let select_all = futures_util::future::select_all(acme_task_handles);
      let cancel_token_clone = cancel_token.clone();
      let acme_handle = runtime_handle.spawn(async move {
        let (acme_res, _, remaining) = select_all.await;
        cancel_token_clone.cancel();
        let remaining_results = futures_util::future::join_all(remaining).await;
        if let Err(ref e) = acme_res {
          error!("acme manager exited on error: {e}");
        }
        acme_res?;
        for result in remaining_results {
          result?;
        }
        Ok::<(), anyhow::Error>(())
      });
      let (rpxy_res, cert_res, acme_res) = tokio::join!(rpxy_handle, cert_handle, acme_handle);
      let (rpxy_res, cert_res, acme_res) = (rpxy_res?, cert_res?, acme_res?);
      match (rpxy_res, cert_res, acme_res) {
        (Ok(()), Ok(()), Ok(())) => Ok(()),
        (Err(e), _, _) => Err(e),
        (_, Err(e), _) => Err(e),
        (_, _, Err(e)) => Err(e),
      }
    }
  }
}

async fn rpxy_service(
  config_path: &str,
  mut active_config: ConfigToml,
  mut config_rx: ReloaderReceiver<ConfigToml, String>,
  runtime_handle: tokio::runtime::Handle,
  unsafe_debug_headers: bool,
  access_log_enabled: bool,
) -> Result<(), anyhow::Error> {
  info!("Start rpxy service with dynamic config reloader");
  let mut service = RpxyService::new(
    &active_config,
    runtime_handle.clone(),
    unsafe_debug_headers,
    access_log_enabled,
  )
  .await?;
  let interval = Duration::from_secs(CONFIG_WATCH_DELAY_SECS.into());
  let mut recheck = interval_at(Instant::now() + interval, interval);
  recheck.set_missed_tick_behavior(MissedTickBehavior::Skip);
  let mut last_input = None;

  loop {
    let cancel_token = CancellationToken::new();
    let (next_config, next_service) = {
      let running = service.start(cancel_token.clone());
      tokio::pin!(running);
      let replacement = async {
        loop {
          // Read the current file after either trigger. A queued watcher value may
          // predate a periodic read, and filesystem notifications can be missed.
          tokio::select! {
            changed = config_rx.changed() => changed?,
            _ = recheck.tick() => {}
          }
          let Ok(input) = tokio::fs::read_to_string(config_path).await else {
            if last_input.take().is_some() {
              warn!("Configuration file unavailable, keeping the active configuration");
            }
            continue;
          };
          if last_input.as_ref() == Some(&input) {
            continue;
          }
          let config = ConfigToml::parse(&input);
          last_input = Some(input);
          let Ok(config) = config else {
            warn!("Configuration file contains invalid TOML, keeping the active configuration");
            continue;
          };
          // The watcher initially publishes the startup file, and may publish it again
          // after an unrelated edit or after the file is restored.
          if config == active_config {
            continue;
          }
          match RpxyService::new(&config, runtime_handle.clone(), unsafe_debug_headers, access_log_enabled).await {
            Ok(service) => return Ok::<_, anyhow::Error>((config, service)),
            Err(e) => error!("Configuration update rejected, keeping the active configuration: {e}"),
          }
        }
      };
      let next = tokio::select! {
        biased;
        result = &mut running => return result,
        result = replacement => result,
      };
      cancel_token.cancel();
      running.await?;
      next?
    };
    info!("Configuration updated. Rebinding TCP/UDP listeners");
    active_config = next_config;
    service = next_service;
  }
}
