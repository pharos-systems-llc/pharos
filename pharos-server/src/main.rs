/* ========================================================================
 * Project: pharos
 * Component: Server Core
 * File: pharos-server/src/main.rs
 * Author: Richard D. (https://github.com/iamrichardd)
 * License: AGPL-3.0 (See LICENSE file for details)
 * * Purpose (The "Why"):
 * This is the binary entry point for the pharos backend server. It initializes
 * the environment, storage, and middleware before starting the TCP listener.
 * * Traceability:
 * Implements RFC 2378 Section 2.
 * ======================================================================== */

use pharos_server::storage::{Storage, MemoryStorage, FileStorage, LdapStorage};
use pharos_server::metrics::{CPU_USAGE, MEMORY_USAGE_BYTES, TOTAL_RECORDS, gather_metrics, check_health_thresholds};
use pharos_server::auth::{AuthManager, SecurityTier};
use pharos_server::middleware::{MiddlewareChain, LoggingMiddleware, ReadOnlyMiddleware, SecurityTierMiddleware};
use pharos_server::handle_connection;
use pharos_server::sync;
use pharos_server::alerting::{self, AlertState};
use tokio::net::TcpListener;
use tracing::{info, error};
use std::sync::{Arc, RwLock};
use sysinfo::System;
use warp::Filter;
use std::time::Duration;
use std::path::PathBuf;
use std::env;
use std::path::Path;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_file_iter(path)
        .map_err(|e| anyhow::anyhow!("Failed to read certs from {:?}: {}", path, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to parse a certificate in {:?}: {}", path, e))
}

fn load_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|e| anyhow::anyhow!("No private key found in {:?}: {}", path, e))
}

fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> anyhow::Result<TlsAcceptor> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("Failed to create TLS config: {}", e))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

use std::time::Instant;

async fn wait_for_files(paths: &[&Path], timeout: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let all_exist = paths.iter().all(|p| p.exists());
        if all_exist {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("Timeout waiting for files: {:?}", paths)
}

fn validate_env() -> anyhow::Result<()> {
    let mandatory = ["PHAROS_TLS_CERT", "PHAROS_TLS_KEY"];
    for var in &mandatory {
        if env::var(var).is_err() {
            return Err(anyhow::anyhow!("Mandatory environment variable {} is missing", var));
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let use_tui = args.contains(&"--tui".to_string());

    // Initialize tracing for observability only if TUI is not taking over stdout
    if !use_tui {
        // `from_default_env()` would default to ERROR-only when RUST_LOG is unset; use the
        // builder directly so the existing INFO-level default is preserved when it's unset or
        // fails to parse entirely. Note: a RUST_LOG value that parses as a *valid* but irrelevant
        // target filter (e.g. a plain typo like "pharos_serverr") silently disables all output
        // with no warning — this is standard tracing_subscriber::EnvFilter behavior, not
        // something this fallback can catch.
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::builder()
                    .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .init();
    }

    info!("Performing environment sanity checks...");
    validate_env()?;

    // --- Mandatory TLS Configuration ---
    let cert_path_str = env::var("PHAROS_TLS_CERT")?;
    let key_path_str = env::var("PHAROS_TLS_KEY")?;

    let cert_path = Path::new(&cert_path_str);
    let key_path = Path::new(&key_path_str);

    // Wait for certificates to appear (up to 30 seconds)
    // This is critical for the Sandbox environment where certs are generated on-the-fly.
    info!("Waiting for TLS certificates to be available...");
    wait_for_files(&[cert_path, key_path], Duration::from_secs(30)).await?;

    info!("Loading TLS certificates from {:?} and {:?}", cert_path, key_path);
    let acceptor = build_tls_acceptor(cert_path, key_path)?;
    let tls_acceptor: Arc<RwLock<TlsAcceptor>> = Arc::new(RwLock::new(acceptor));

    // Determine storage backend based on environment variables
    let storage: Arc<RwLock<dyn Storage>> = if let Ok(url) = env::var("PHAROS_LDAP_URL") {
        info!("Initializing LdapStorage at {}", url);
        let bind_dn = env::var("PHAROS_LDAP_BIND_DN").unwrap_or_default();
        let bind_pw = env::var("PHAROS_LDAP_BIND_PW").unwrap_or_default();
        let base_dn = env::var("PHAROS_LDAP_BASE_DN").unwrap_or_default();
        Arc::new(RwLock::new(LdapStorage::new(url, bind_dn, bind_pw, base_dn)))
    } else if let Ok(path) = env::var("PHAROS_STORAGE_PATH") {
        info!("Initializing FileStorage at {:?}", path);
        Arc::new(RwLock::new(FileStorage::new(PathBuf::from(path))))
    } else {
        info!("Initializing in-memory storage (Development Tier)");
        Arc::new(RwLock::new(MemoryStorage::new()))
    };

    // --- Bootstrap & Self-Registration ---
    let my_addr = env::var("PHAROS_SYNC_ADDR").unwrap_or_default();
    if !my_addr.is_empty() {
        if let Ok(peer) = env::var("PHAROS_BOOTSTRAP_PEER") {
            let res = sync::bootstrap(Arc::clone(&storage), &peer).await;
            if let Err(e) = res {
                error!("Bootstrap failed: {}", e);
            }
        }
        if let Err(e) = sync::register_self(Arc::clone(&storage), &my_addr).await {
            error!("Self-registration failed: {}", e);
        }
    }

    let security_tier = match env::var("PHAROS_SECURITY_TIER").unwrap_or_else(|_| "open".to_string()).to_lowercase().as_str() {
        "protected" => SecurityTier::Protected,
        "scoped" => SecurityTier::Scoped,
        _ => SecurityTier::Open,
    };
    info!("Running with Security Tier: {:?}", security_tier);

    // Initialize AuthManager
    let keys_dir = env::var("PHAROS_KEYS_DIR").unwrap_or_else(|_| "./keys".to_string());
    let auth_manager = Arc::new(AuthManager::new(Path::new(&keys_dir), security_tier));

    // Key enrollment/rotation shouldn't require a restart: `systemctl reload pharos-server`
    // (or `kill -HUP <pid>`) re-scans keys_dir and atomically swaps in the new key set.
    #[cfg(unix)]
    {
        let reload_auth_manager = Arc::clone(&auth_manager);
        let reload_tls_acceptor = Arc::clone(&tls_acceptor);
        let reload_cert_path = cert_path_str.clone();
        let reload_key_path = key_path_str.clone();
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .expect("failed to install SIGHUP handler");
        tokio::spawn(async move {
            loop {
                hangup.recv().await;
                info!("SIGHUP received, reloading authorized keys...");
                reload_auth_manager.reload();

                info!("SIGHUP received, reloading TLS certificate/key...");
                match build_tls_acceptor(Path::new(&reload_cert_path), Path::new(&reload_key_path)) {
                    Ok(new_acceptor) => match reload_tls_acceptor.write() {
                        Ok(mut guard) => {
                            *guard = new_acceptor;
                            info!("TLS certificate/key reloaded successfully.");
                        }
                        Err(e) => error!("Failed to acquire write lock while reloading TLS certificate/key: {}", e),
                    },
                    Err(e) => error!(
                        "Failed to reload TLS certificate/key ({}); continuing to serve the previous certificate.",
                        e
                    ),
                }
            }
        });
    }

    // Initialize Middleware Chain
    let mut middleware_chain = MiddlewareChain::new();
    middleware_chain.add(Arc::new(LoggingMiddleware));

    middleware_chain.add(Arc::new(SecurityTierMiddleware {
        default_tier: security_tier,
    }));

    middleware_chain.add(Arc::new(pharos_server::middleware::RbacMiddleware));

    middleware_chain.add(Arc::new(ReadOnlyMiddleware {
        read_only_ids: vec!["guest".to_string()],
    }));
    let middleware_chain = Arc::new(middleware_chain);

    // --- Metrics Scrape Server (Pull Method) ---
    let storage_for_metrics: Arc<RwLock<dyn Storage>> = Arc::clone(&storage);
    let metrics_route = warp::path("metrics").map(move || {
        // Update storage count on scrape
        if let Ok(lock) = storage_for_metrics.read() {
            TOTAL_RECORDS.set(lock.record_count() as i64);
        }
        gather_metrics()
    });
    
    tokio::spawn(async move {
        info!("Prometheus metrics server starting on 0.0.0.0:9090/metrics");
        warp::serve(metrics_route).run(([0, 0, 0, 0], 9090)).await;
    });

    // --- Background Metrics Collection & Health Monitoring ---
    let storage_for_monitor: Arc<RwLock<dyn Storage>> = Arc::clone(&storage);
    tokio::spawn(async move {
        let mut sys = System::new_all();
        let pid = sysinfo::Pid::from_u32(std::process::id());
        let mut alert_state = AlertState::default();
        
        loop {
            // Update system and process info
            sys.refresh_all();
            
            // Record CPU Usage (average over all CPUs)
            let cpu_load: f32 = sys.cpus().iter().map(|cpu: &sysinfo::Cpu| cpu.cpu_usage()).sum::<f32>() / sys.cpus().len() as f32;
            CPU_USAGE.set(cpu_load as f64);

            // Record Process Memory Usage (RSS)
            if let Some(process) = sys.process(pid) {
                let used_mem = process.memory();
                MEMORY_USAGE_BYTES.set(used_mem as i64);
            }

            // Record Storage Count
            if let Ok(lock) = storage_for_monitor.read() {
                TOTAL_RECORDS.set(lock.record_count() as i64);
            }

            // Health Monitor Threshold Warnings
            let cpu_threshold = env::var("PHAROS_CPU_THRESHOLD")
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(90.0);
            let mem_threshold = env::var("PHAROS_MEM_THRESHOLD_GB")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|gb| gb * 1024 * 1024 * 1024)
                .unwrap_or(1024 * 1024 * 1024); // Default 1GB

            check_health_thresholds(cpu_threshold, mem_threshold);

            // Advanced Pulse Alerting (Dead Man's Switch) - Task 15.3
            let presence_threshold = env::var("PHAROS_PRESENCE_ALERT_THRESHOLD_SECONDS")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(7200); // Default 2 hours (2x the pulse agent's 1-hour heartbeat)
            let webhook_url = env::var("PHAROS_ALERT_WEBHOOK_URL").ok();
            let script_path = env::var("PHAROS_ALERT_SCRIPT").ok();
            alerting::check_presence(
                &storage_for_monitor,
                &mut alert_state,
                presence_threshold,
                webhook_url.as_deref(),
                script_path.as_deref(),
            ).await;

            alerting::check_version_mismatches(
                &storage_for_monitor,
                &mut alert_state,
                webhook_url.as_deref(),
                script_path.as_deref(),
            ).await;

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    let addr = env::var("PHAROS_ADDR").unwrap_or_else(|_| "0.0.0.0:2378".to_string());
    let listener = TcpListener::bind(&addr).await?;
    info!("Pharos Server listening on {} (SSL Mandatory)", addr);

    // Prepare shutdown signal
    let shutdown = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C handler");
        info!("Shutdown signal received, closing server...");
    };

    if use_tui {
        tokio::select! {
            _ = async {
                loop {
                    if let Ok((socket, peer_addr)) = listener.accept().await {
                        let storage_ref: Arc<RwLock<dyn Storage>> = Arc::clone(&storage);
                        let auth_ref = Arc::clone(&auth_manager);
                        let middleware_ref = Arc::clone(&middleware_chain);
                        let acceptor = match tls_acceptor.read() {
                            Ok(guard) => guard.clone(),
                            Err(e) => {
                                error!("TLS acceptor lock poisoned ({}), dropping connection from {}", e, peer_addr);
                                continue;
                            }
                        };
                        tokio::spawn(async move {
                            match acceptor.accept(socket).await {
                                Ok(tls_stream) => {
                                    if let Err(_e) = handle_connection(tls_stream, peer_addr.to_string(), storage_ref, auth_ref, middleware_ref).await {
                                        // Suppress error log since TUI uses stdout
                                    }
                                }
                                Err(e) => {
                                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                        tracing::debug!("TLS handshake EOF from {} (Likely health check)", peer_addr);
                                    } else {
                                        error!("TLS acceptance error from {}: {:?}", peer_addr, e);
                                    }
                                }
                            }
                        });
                    }
                }
            } => {},
            _ = shutdown => {},
            res = pharos_server::tui::run_tui() => {
                if let Err(e) = res {
                    eprintln!("TUI Error: {}", e);
                }
            }
        }
    } else {
        tokio::select! {
            _ = async {
                loop {
                    let (socket, peer_addr) = listener.accept().await?;
                    let storage_ref: Arc<RwLock<dyn Storage>> = Arc::clone(&storage);
                    let auth_ref = Arc::clone(&auth_manager);
                    let middleware_ref = Arc::clone(&middleware_chain);
                    let acceptor = match tls_acceptor.read() {
                        Ok(guard) => guard.clone(),
                        Err(e) => {
                            error!("TLS acceptor lock poisoned ({}), dropping connection from {}", e, peer_addr);
                            continue;
                        }
                    };
                    tokio::spawn(async move {
                        match acceptor.accept(socket).await {
                            Ok(tls_stream) => {
                                if let Err(e) = handle_connection(tls_stream, peer_addr.to_string(), storage_ref, auth_ref, middleware_ref).await {
                                    if e.downcast_ref::<std::io::Error>().is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::UnexpectedEof) {
                                        tracing::debug!("Connection from {} closed improperly (EOF)", peer_addr);
                                        return;
                                    }
                                    error!("Error handling connection from {}: {:?}", peer_addr, e);
                                }
                            }
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                    tracing::debug!("TLS handshake EOF from {} (Likely health check)", peer_addr);
                                } else {
                                    error!("TLS acceptance error from {}: {:?}", peer_addr, e);
                                }
                            }
                        }
                    });
                }
                #[allow(unreachable_code)]
                anyhow::Ok(())
            } => {},
            _ = shutdown => {},
        }
    }

    info!("Pharos Server shutdown complete.");
    Ok(())
}

#[cfg(test)]
mod tls_reload_tests {
    use super::*;
    use std::process::Command;

    fn generate_self_signed(dir: &std::path::Path, name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let key_path = dir.join(format!("{name}.key"));
        let crt_path = dir.join(format!("{name}.crt"));
        let status = Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", key_path.to_str().unwrap(),
                "-out", crt_path.to_str().unwrap(),
                "-subj", "/CN=test",
            ])
            .status()
            .expect("failed to run openssl - is it installed?");
        assert!(status.success(), "openssl cert generation failed");
        (crt_path, key_path)
    }

    #[test]
    fn test_should_build_acceptor_from_valid_cert_and_key() {
        let dir = std::env::temp_dir().join(format!("pharos-tls-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (crt, key) = generate_self_signed(&dir, "valid");

        let result = build_tls_acceptor(&crt, &key);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_should_reject_mismatched_cert_and_key() {
        let dir = std::env::temp_dir().join(format!("pharos-tls-test-mismatch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (crt_a, _key_a) = generate_self_signed(&dir, "a");
        let (_crt_b, key_b) = generate_self_signed(&dir, "b");

        // cert from pair A, key from pair B - must not silently succeed
        let result = build_tls_acceptor(&crt_a, &key_b);
        assert!(result.is_err(), "expected Err for mismatched cert/key pair, got Ok");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_should_error_on_missing_files() {
        let result = build_tls_acceptor(
            std::path::Path::new("/nonexistent/path.crt"),
            std::path::Path::new("/nonexistent/path.key"),
        );
        assert!(result.is_err());
    }
}
