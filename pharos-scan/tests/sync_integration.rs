/* ========================================================================
 * Project: pharos
 * Component: Network Scanner Tests (pharos-scan)
 * File: pharos-scan/tests/sync_integration.rs
 * Author: Richard D. (https://github.com/iamrichardd)
 * License: AGPL-3.0 (See LICENSE file for details)
 * * Purpose (The "Why"):
 * Integration test suite for pharos-scan device synchronization logic.
 * Verifies creation, updating, skipping on ownership conflict, and error handling
 * against an in-process Pharos server instance.
 * * Traceability:
 * Related to pharos-scan --auto device discovery mode step 2 device sync.
 * ======================================================================== */

use pharos_client::{PharosClient, PharosResponse};
use pharos_scan::oui::derive_scan_alias;
use pharos_scan::sync::{sync_discovered_device, SyncOutcome};
use pharos_scan::DiscoveredNode;

use pharos_server::auth::{AuthManager, SecurityTier};
use pharos_server::handle_connection;
use pharos_server::middleware::{MiddlewareChain, SecurityTierMiddleware};
use pharos_server::storage::{MemoryStorage, Storage};

use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

struct TestTlsAssets {
    server_config: Arc<ServerConfig>,
    ca_cert_path: String,
    _temp_dir: tempfile::TempDir,
}

static TEST_TLS: OnceLock<TestTlsAssets> = OnceLock::new();

fn get_test_tls() -> (TlsAcceptor, String) {
    let assets = TEST_TLS.get_or_init(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

        let temp_dir = tempdir().unwrap();
        let ca_dir = temp_dir.path();

        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName("localhost".try_into().unwrap()),
            rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()),
        ];
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_pem = cert.pem();
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());

        let ca_path = ca_dir.join("root-ca.crt");
        std::fs::write(&ca_path, cert_pem.as_bytes()).unwrap();

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

        TestTlsAssets {
            server_config: Arc::new(server_config),
            ca_cert_path: ca_path.to_str().unwrap().to_string(),
            _temp_dir: temp_dir,
        }
    });

    (
        TlsAcceptor::from(Arc::clone(&assets.server_config)),
        assets.ca_cert_path.clone(),
    )
}

struct TestAuthAssets {
    keys_dir: PathBuf,
    priv_key_path: String,
    _temp_dir: tempfile::TempDir,
}

static TEST_AUTH: OnceLock<TestAuthAssets> = OnceLock::new();

fn get_test_auth_assets() -> (PathBuf, String) {
    let assets = TEST_AUTH.get_or_init(|| {
        let temp_dir = tempdir().unwrap();
        let base_dir = temp_dir.path();

        let mut rng = rand::rngs::OsRng;
        let priv_key = ssh_key::PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519).unwrap();
        let pub_key_openssh = priv_key.public_key().to_openssh().unwrap();
        let priv_key_openssh = priv_key.to_openssh(ssh_key::LineEnding::LF).unwrap();

        let keys_dir = base_dir.join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();
        std::fs::write(
            keys_dir.join("test-admin_id_ed25519.pub"),
            pub_key_openssh.as_bytes(),
        )
        .unwrap();

        let priv_key_path = base_dir.join("id_ed25519");
        std::fs::write(&priv_key_path, priv_key_openssh.as_bytes()).unwrap();

        TestAuthAssets {
            keys_dir,
            priv_key_path: priv_key_path.to_str().unwrap().to_string(),
            _temp_dir: temp_dir,
        }
    });

    (assets.keys_dir.clone(), assets.priv_key_path.clone())
}

async fn setup_test_server() -> (String, Arc<RwLock<dyn Storage>>) {
    setup_test_server_with_tier(SecurityTier::Open).await
}

// Real production hubs run SecurityTier::Protected, not Open - under Protected, every
// command except a small allowlist (status/id/login/auth/quit) requires authentication,
// unlike Open where `query` alone needs none. sync_discovered_device's query step
// originally used the non-authenticating `execute()` (only its later `add` step used
// `execute_authenticated()`), which worked fine against every test in this file (all of
// which used Open tier) but failed outright with "506: Authentication required" against
// the real Protected-tier hub - confirmed live, then fixed to use execute_authenticated()
// for both steps. This parameterized variant exists so a regression test can reproduce
// that exact real-world scenario instead of only ever exercising the tier that happened
// to mask the bug.
async fn setup_test_server_with_tier(tier: SecurityTier) -> (String, Arc<RwLock<dyn Storage>>) {
    let (acceptor, ca_path) = get_test_tls();
    let (keys_dir, priv_key_path) = get_test_auth_assets();

    unsafe {
        std::env::set_var("PHAROS_CA_CERT", &ca_path);
        std::env::set_var("PHAROS_PRIVATE_KEY", &priv_key_path);
    }

    let storage: Arc<RwLock<dyn Storage>> = Arc::new(RwLock::new(MemoryStorage::new()));
    let auth_manager = Arc::new(AuthManager::new(&keys_dir, tier));

    let mut chain = MiddlewareChain::new();
    chain.add(Arc::new(SecurityTierMiddleware {
        default_tier: tier,
    }));
    let middleware_chain = Arc::new(chain);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let addr_str = addr.to_string();

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

    (addr_str, storage)
}

#[tokio::test]
async fn test_should_create_new_record_for_never_before_seen_device() {
    let (addr, _storage) = setup_test_server().await;

    let mut client = PharosClient::connect(&addr, "pharos-scan").await.unwrap();

    let node = DiscoveredNode {
        ip: "192.168.1.100".parse().unwrap(),
        hostname: Some("new-device-01".to_string()),
        mac: Some("00:11:22:33:44:55".to_string()),
        manufacturer: Some("Acme Corp".to_string()),
        ports: vec![22, 80],
        role: Some("Server".to_string()),
        is_existing: false,
    };

    let outcome = sync_discovered_device(&mut client, &node).await;
    assert_eq!(outcome, SyncOutcome::Created);

    let resp = client.execute("query type=\"machine\" hostname=\"new-device-01\"").await.unwrap();
    if let PharosResponse::Matches { count, records } = resp {
        assert_eq!(count, 1);
        assert_eq!(records.len(), 1);
        let fields = &records[0].fields;

        let get_field = |k: &str| fields.iter().find(|f| f.key == k).map(|f| f.value.as_str());
        assert_eq!(get_field("hostname"), Some("new-device-01"));
        assert_eq!(get_field("mac_addr"), Some("00:11:22:33:44:55"));
        assert_eq!(get_field("manufacturer"), Some("Acme Corp"));
        assert_eq!(get_field("source"), Some("pharos-scan"));
    } else {
        panic!("Expected PharosResponse::Matches, got {:?}", resp);
    }
}

#[tokio::test]
async fn test_should_use_derived_alias_when_hostname_is_absent() {
    let (addr, _storage) = setup_test_server().await;

    let mut client = PharosClient::connect(&addr, "pharos-scan").await.unwrap();

    let mac_str = "00:AA:BB:CC:DD:EE";
    let expected_alias = derive_scan_alias(mac_str);
    assert_eq!(expected_alias, "device-00aabbccddee");

    let node = DiscoveredNode {
        ip: "192.168.1.101".parse().unwrap(),
        hostname: None,
        mac: Some(mac_str.to_string()),
        manufacturer: Some("Widget Vendor".to_string()),
        ports: vec![80],
        role: None,
        is_existing: false,
    };

    let outcome = sync_discovered_device(&mut client, &node).await;
    assert_eq!(outcome, SyncOutcome::Created);

    let query_str = format!("query type=\"machine\" alias=\"{}\"", expected_alias);
    let resp = client.execute(&query_str).await.unwrap();
    if let PharosResponse::Matches { count, records } = resp {
        assert_eq!(count, 1);
        assert_eq!(records.len(), 1);
        let fields = &records[0].fields;
        let alias_field = fields
            .iter()
            .find(|f| f.key == "alias")
            .map(|f| f.value.as_str());
        assert_eq!(alias_field, Some(expected_alias.as_str()));
    } else {
        panic!("Expected PharosResponse::Matches, got {:?}", resp);
    }
}

#[tokio::test]
async fn test_should_update_existing_scan_sourced_record() {
    let (addr, _storage) = setup_test_server().await;

    let mut client = PharosClient::connect(&addr, "pharos-scan").await.unwrap();

    let mut node = DiscoveredNode {
        ip: "192.168.1.102".parse().unwrap(),
        hostname: Some("rescan-target".to_string()),
        mac: Some("11:22:33:44:55:66".to_string()),
        manufacturer: Some("Test Co".to_string()),
        ports: vec![22],
        role: None,
        is_existing: false,
    };

    let outcome1 = sync_discovered_device(&mut client, &node).await;
    assert_eq!(outcome1, SyncOutcome::Created);

    node.ip = "192.168.1.202".parse().unwrap();
    let outcome2 = sync_discovered_device(&mut client, &node).await;
    assert_eq!(outcome2, SyncOutcome::Updated);

    let resp = client.execute("query type=\"machine\" hostname=\"rescan-target\"").await.unwrap();
    if let PharosResponse::Matches { records, .. } = resp {
        assert_eq!(records.len(), 1);
        let ip_fields: Vec<&str> = records[0]
            .fields
            .iter()
            .filter(|f| f.key == "ip_addr" || f.key.trim().is_empty())
            .map(|f| f.value.as_str())
            .collect();
        assert!(
            ip_fields.contains(&"192.168.1.102"),
            "Missing initial IP, got {:?}",
            ip_fields
        );
        assert!(
            ip_fields.contains(&"192.168.1.202"),
            "Missing updated IP, got {:?}",
            ip_fields
        );
    } else {
        panic!("Expected PharosResponse::Matches, got {:?}", resp);
    }
}

#[tokio::test]
async fn test_should_skip_device_already_owned_by_pulse() {
    let (addr, _storage) = setup_test_server().await;

    let mut pulse_client = PharosClient::connect(&addr, "pulse-test-host").await.unwrap();

    let add_resp = pulse_client
        .execute_authenticated(
            "add hostname=\"pulse-managed-host\" type=\"machine\" manufacturer=\"Dell Inc.\" ip_addr=\"10.0.0.1\"",
        )
        .await
        .unwrap();
    assert!(
        matches!(add_resp, PharosResponse::Ok(_)),
        "Pulse add failed: {:?}",
        add_resp
    );

    let mut scan_client = PharosClient::connect(&addr, "pharos-scan").await.unwrap();

    let scan_node = DiscoveredNode {
        ip: "10.0.0.2".parse().unwrap(),
        hostname: Some("pulse-managed-host".to_string()),
        mac: Some("AA:BB:CC:11:22:33".to_string()),
        manufacturer: Some("Some MAC-OUI Guess".to_string()),
        ports: vec![22, 80],
        role: None,
        is_existing: false,
    };

    let outcome = sync_discovered_device(&mut scan_client, &scan_node).await;
    assert_eq!(outcome, SyncOutcome::Skipped);

    let resp = scan_client.execute("query type=\"machine\" hostname=\"pulse-managed-host\"").await.unwrap();
    if let PharosResponse::Matches { count, records } = resp {
        assert_eq!(count, 1);
        assert_eq!(records.len(), 1);

        let mfr = records[0]
            .fields
            .iter()
            .find(|f| f.key == "manufacturer")
            .map(|f| f.value.as_str());
        assert_eq!(mfr, Some("Dell Inc."));
    } else {
        panic!("Expected PharosResponse::Matches, got {:?}", resp);
    }
}

// Regression test for a real production bug found live against pharos-01.iamrichardd.com:
// pharos-scan --auto created 8 duplicate records for devices already tracked by pharos-pulse,
// because hostname resolution failed for those devices during the scan (common on networks
// without real PTR records) and the resulting alias=device-<mac> identifier was never
// cross-referenced against mac_addr, the one field populated on both an alias-keyed scan record
// and a hostname-keyed pulse record for the same physical device.
#[tokio::test]
async fn test_should_skip_via_mac_cross_reference_when_hostname_resolution_failed() {
    let (addr, _storage) = setup_test_server().await;

    let mut pulse_client = PharosClient::connect(&addr, "pulse-test-host").await.unwrap();

    let add_resp = pulse_client
        .execute_authenticated(
            "add hostname=\"technitium-02\" type=\"machine\" manufacturer=\"Raspberry Pi\" mac_addr=\"bc:24:11:00:02:04\" ip_addr=\"10.0.0.50\"",
        )
        .await
        .unwrap();
    assert!(
        matches!(add_resp, PharosResponse::Ok(_)),
        "Pulse add failed: {:?}",
        add_resp
    );

    let mut scan_client = PharosClient::connect(&addr, "pharos-scan").await.unwrap();

    // hostname: None simulates a failed reverse-DNS lookup for this device during the scan -
    // sync_discovered_device falls back to the alias identifier, exactly like the real bug.
    let scan_node = DiscoveredNode {
        ip: "10.0.0.50".parse().unwrap(),
        hostname: None,
        mac: Some("bc:24:11:00:02:04".to_string()),
        manufacturer: Some("Some MAC-OUI Guess".to_string()),
        ports: vec![],
        role: None,
        is_existing: false,
    };

    let outcome = sync_discovered_device(&mut scan_client, &scan_node).await;
    assert_eq!(outcome, SyncOutcome::Skipped);

    // Confirm no duplicate alias-keyed record was created for this device.
    let expected_alias = derive_scan_alias("bc:24:11:00:02:04");
    let resp = scan_client
        .execute(&format!("query type=\"machine\" alias=\"{}\"", expected_alias))
        .await
        .unwrap();
    if let PharosResponse::Matches { count, records } = resp {
        assert_eq!(count, 0, "expected no duplicate alias record, got {:?}", records);
    } else {
        panic!("Expected PharosResponse::Matches with count 0, got {:?}", resp);
    }

    // The original pulse-owned record is untouched.
    let resp2 = scan_client
        .execute("query type=\"machine\" hostname=\"technitium-02\"")
        .await
        .unwrap();
    if let PharosResponse::Matches { count, records } = resp2 {
        assert_eq!(count, 1);
        let mfr = records[0]
            .fields
            .iter()
            .find(|f| f.key == "manufacturer")
            .map(|f| f.value.as_str());
        assert_eq!(mfr, Some("Raspberry Pi"), "pulse-owned record's manufacturer must be untouched");
    } else {
        panic!("Expected PharosResponse::Matches, got {:?}", resp2);
    }
}

#[tokio::test]
async fn test_should_fail_gracefully_with_no_hostname_or_mac() {
    let (addr, _storage) = setup_test_server().await;

    let mut client = PharosClient::connect(&addr, "pharos-scan").await.unwrap();

    let node = DiscoveredNode {
        ip: "192.168.1.250".parse().unwrap(),
        hostname: None,
        mac: None,
        manufacturer: None,
        ports: vec![80],
        role: None,
        is_existing: false,
    };

    let outcome = sync_discovered_device(&mut client, &node).await;
    assert!(matches!(outcome, SyncOutcome::Failed(_)));

    let resp = client.execute("query type=\"machine\" ip_addr=\"192.168.1.250\"").await.unwrap();
    if let PharosResponse::Matches { count, records } = resp {
        assert_eq!(count, 0);
        assert!(records.is_empty());
    } else {
        panic!("Expected Matches with count 0, got {:?}", resp);
    }
}

// Regression test for a real production bug: sync_discovered_device's query step originally
// used plain execute() (no auth retry), which only worked because every other test in this
// file runs SecurityTier::Open, where `query` needs no authentication. The real production
// hub runs SecurityTier::Protected, where `query` is not in the auth-bypass allowlist -
// confirmed live against the real hub, every single sync attempt failed outright with
// "506: Authentication required" before ever reaching the ownership check. Fixed by using
// execute_authenticated() for the query step too, matching the write step. This test runs
// the full create-then-update flow under Protected tier specifically, so a regression here
// fails loudly in CI instead of only being discoverable by deploying to real production.
#[tokio::test]
async fn test_should_create_and_update_under_protected_tier() {
    let (addr, _storage) = setup_test_server_with_tier(SecurityTier::Protected).await;

    let mut client = PharosClient::connect(&addr, "pharos-scan").await.unwrap();

    let mut node = DiscoveredNode {
        ip: "10.10.0.1".parse().unwrap(),
        hostname: Some("protected-tier-target".to_string()),
        mac: Some("AA:BB:CC:00:00:01".to_string()),
        manufacturer: Some("Test Co".to_string()),
        ports: vec![],
        role: None,
        is_existing: false,
    };

    let outcome1 = sync_discovered_device(&mut client, &node).await;
    assert_eq!(
        outcome1,
        SyncOutcome::Created,
        "expected Created under Protected tier, got {:?} - the query step likely failed auth",
        outcome1
    );

    node.ip = "10.10.0.2".parse().unwrap();
    let outcome2 = sync_discovered_device(&mut client, &node).await;
    assert_eq!(outcome2, SyncOutcome::Updated, "expected Updated on second sync under Protected tier, got {:?}", outcome2);

    let resp = client
        .execute_authenticated("query type=\"machine\" hostname=\"protected-tier-target\"")
        .await
        .unwrap();
    if let PharosResponse::Matches { count, records } = resp {
        assert_eq!(count, 1, "expected exactly one record, not a duplicate");
        assert_eq!(records.len(), 1);
    } else {
        panic!("Expected PharosResponse::Matches, got {:?}", resp);
    }
}
