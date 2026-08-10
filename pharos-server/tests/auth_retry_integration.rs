/* ========================================================================
 * Project: pharos
 * Component: Server Core
 * File: pharos-server/tests/auth_retry_integration.rs
 * Author: Richard D. (https://github.com/iamrichardd)
 * License: AGPL-3.0 (See LICENSE file for details)
 * * Purpose (The "Why"):
 * Integration test to verify that the PharosClient can transparently authenticate
 * and retry commands when encountering a 506 status code, preventing user-facing failures.
 * * Traceability:
 * Found live-testing mdb against a real Protected-tier hub (2026-08-03) - pharos-client's
 * parse_response() checked for status code 401, which the server has never sent; the real
 * "not logged in" code is 506, silently breaking the automatic auth-retry flow.
 * ======================================================================== */

use pharos_server::handle_connection;
use pharos_server::storage::{MemoryStorage, Storage};
use pharos_server::auth::{AuthManager, SecurityTier};
use pharos_server::middleware::{MiddlewareChain, RbacMiddleware, SecurityTierMiddleware};
use pharos_client::{PharosClient, PharosResponse};

use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::sync::{Arc, RwLock};
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, std::io::Error> {
    CertificateDer::pem_file_iter(path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, std::io::Error> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[tokio::test]
async fn test_should_transparently_auth_retry_when_506_received() {
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Setup temp directory
    let temp_dir = tempdir().unwrap();
    let dir_path = temp_dir.path();

    // 2. Generate SSL certificates using standard sandbox script. CARGO_MANIFEST_DIR (this
    // crate's own directory, baked in at compile time) is portable across environments -
    // unlike a hardcoded absolute path, it works whether this runs in a local Podman mount,
    // the real CI runner's checkout dir, or anywhere else.
    let script_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/gen-sandbox-certs.sh");
    let cert_status = Command::new(&script_path)
        .arg(dir_path)
        .status()
        .expect("Failed to execute gen-sandbox-certs.sh");
    assert!(cert_status.success());

    // 3. Generate SSH keys using ssh-keygen
    let admin_key_path = dir_path.join("admin_id_ed25519");
    let key_status = Command::new("ssh-keygen")
        .args(&["-t", "ed25519", "-N", "", "-f", admin_key_path.to_str().unwrap()])
        .status()
        .expect("Failed to execute ssh-keygen");
    assert!(key_status.success());

    let regular_key_path = dir_path.join("regular_id_ed25519");
    let reg_key_status = Command::new("ssh-keygen")
        .args(&["-t", "ed25519", "-N", "", "-f", regular_key_path.to_str().unwrap()])
        .status()
        .expect("Failed to execute ssh-keygen for regular user");
    assert!(reg_key_status.success());

    // Setup keys dir
    let keys_dir = dir_path.join("keys");
    std::fs::create_dir_all(&keys_dir).unwrap();
    std::fs::copy(dir_path.join("admin_id_ed25519.pub"), keys_dir.join("test-admin_id_ed25519.pub")).unwrap();
    std::fs::copy(dir_path.join("regular_id_ed25519.pub"), keys_dir.join("test-regular_id_ed25519.pub")).unwrap();

    // 4. Setup TLS Server
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let certs = load_certs(&dir_path.join("pharos-server.crt")).unwrap();
    let key = load_key(&dir_path.join("pharos-server.key")).unwrap();
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    // Initialize AuthManager & Middleware for Scoped tier (to verify both normal retry & role denial)
    let storage: Arc<RwLock<dyn Storage>> = Arc::new(RwLock::new(MemoryStorage::new()));
    let auth_manager = Arc::new(AuthManager::new(&keys_dir, SecurityTier::Scoped));
    
    let mut chain = MiddlewareChain::new();
    chain.add(Arc::new(SecurityTierMiddleware { default_tier: SecurityTier::Scoped }));
    chain.add(Arc::new(RbacMiddleware));
    let middleware_chain = Arc::new(chain);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let addr_str = format!("127.0.0.1:{}", port);

    // Spawn server accept loop
    let server_storage = Arc::clone(&storage);
    tokio::spawn(async move {
        loop {
            if let Ok((socket, peer_addr)) = listener.accept().await {
                let s = Arc::clone(&server_storage);
                let a = Arc::clone(&auth_manager);
                let m = Arc::clone(&middleware_chain);
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(tls_stream) = acc.accept(socket).await {
                        let _ = handle_connection(tls_stream, peer_addr.to_string(), s, a, m).await;
                    }
                });
            }
        }
    });

    // 5. Configure client environment
    unsafe {
        std::env::set_var("PHAROS_CA_CERT", dir_path.join("root-ca.crt").to_str().unwrap());
    }

    println!("--- Running Live Verification ---");

    // Scenario A: Connect with Admin key (which has write permission)
    unsafe {
        std::env::set_var("PHAROS_PRIVATE_KEY", admin_key_path.to_str().unwrap());
    }
    
    // Connect client
    let mut client = PharosClient::connect(&addr_str, "test-admin").await.unwrap();

    // Call execute_authenticated on a status or add command
    let response = client.execute_authenticated("query return name").await.unwrap();
    println!("Response for execute_authenticated(status): {:?}", response);

    // Transparent auth retry must succeed and yield the actual query response, not a raw 506 -
    // proves parse_response() correctly recognizes the server's real "not logged in" status code
    // and execute_authenticated() transparently logs in and retries before the caller ever sees it.
    match response {
        PharosResponse::Error { code: 501, .. } | PharosResponse::Ok(..) | PharosResponse::Matches { .. } => {}
        other => panic!("Expected transparent auth retry to succeed, but got: {:?}", other),
    }

    // Scenario B: Regression check (using non-admin key, check that 516/denial is NOT swallowed or retried endlessly)
    unsafe {
        std::env::set_var("PHAROS_PRIVATE_KEY", regular_key_path.to_str().unwrap());
    }
    let mut reg_client = PharosClient::connect(&addr_str, "test-regular").await.unwrap();
    
    // An authenticated non-admin write command in Scoped tier should yield 516 (Forbidden)
    let reg_response = reg_client.execute_authenticated("add hostname=reg-test-host").await.unwrap();
    println!("Response for non-admin execute_authenticated(add): {:?}", reg_response);
    
    assert!(
        matches!(reg_response, PharosResponse::Error { code: 516, .. }),
        "Expected PharosResponse::Error with code 516, got: {:?}", reg_response
    );

    println!("--- Live Verification SUCCESS ---");
}
