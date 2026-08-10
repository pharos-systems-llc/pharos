/* ========================================================================
 * Project: pharos
 * Component: Shared Client Library (pharos-client)
 * File: crates/pharos-client/src/lib.rs
 * Author: Richard D. (https://github.com/iamrichardd)
 * License: AGPL-3.0 (See LICENSE file for details)
 * * Purpose (The "Why"):
 * This crate provides a shared, async-first client library for interacting
 * with a Pharos server using the RFC 2378 protocol. It supports connection
 * management, authentication (including SSH-key based challenges), and
 * parsing of responses.
 * * Traceability:
 * Related to Task 10.1 (Issue #39)
 * ======================================================================== */

use tokio::net::TcpStream;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use ssh_key::PrivateKey;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::path::Path;
use std::fs;
use std::env;
use anyhow::{Result, Context, anyhow};
use std::sync::Arc;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName, pki_types::CertificateDer};
use rustls_pki_types::pem::PemObject;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Represents a field in a record returned by the Pharos server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PharosField {
    pub key: String,
    pub value: String,
}

/// Represents a single record match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PharosRecord {
    pub id: i32,
    pub fields: Vec<PharosField>,
}

/// Represents the possible outcomes of a Pharos query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PharosResponse {
    Ok(String),
    Matches {
        count: i32,
        records: Vec<PharosRecord>,
    },
    Error {
        code: i32,
        message: String,
    },
    AuthenticationRequired {
        challenge: String,
    },
}

/// Reconstructs a single RFC 2378 wire command string from CLI argv tokens.
///
/// By the time `ph`/`mdb` see `cli.query`, the shell has already split on
/// whitespace and stripped whatever quotes the user typed — `name="Jane Smith"`
/// arrives as one argv element, `name=Jane Smith`, with the quotes gone but the
/// space still inside it. A naive `.join(" ")` sends that space to the server
/// unprotected, and the server's tokenizer (which splits on unquoted whitespace)
/// re-splits it into two tokens, breaking the command. This re-quotes any
/// `key=value` pair (or bare token) whose content contains whitespace so it
/// round-trips correctly.
pub fn join_wire_args(args: &[String]) -> String {
    args.iter()
        .map(|arg| quote_wire_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_wire_arg(arg: &str) -> String {
    match arg.split_once('=') {
        Some((key, value)) if needs_quoting(value) => {
            format!("{}=\"{}\"", key, escape_wire_value(value))
        }
        None if needs_quoting(arg) => format!("\"{}\"", escape_wire_value(arg)),
        _ => arg.to_string(),
    }
}

fn needs_quoting(s: &str) -> bool {
    s.chars().any(|c| c.is_whitespace())
}

fn escape_wire_value(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub struct PharosClient {
    stream: BufReader<TlsStream<TcpStream>>,
    client_id: String,
}

impl PharosClient {
    /// Connects to a Pharos server at the given address.
    pub async fn connect(addr: &str, client_id: &str) -> Result<Self> {
        // Explicitly select a default rustls CryptoProvider before building any TLS config.
        // Workspace-wide Cargo feature unification means any crate in this workspace enabling
        // an alternate provider (e.g. reqwest's rustls-tls, added to pharos-server for Issue #61)
        // can leave more than one candidate provider linked into every binary that depends on
        // pharos-client - not just pharos-server - with none selected as the process default.
        // rustls then panics on the first TLS config build instead of picking one. install_default()
        // is safe to call more than once per process (e.g. once per PharosClient::connect call) -
        // it simply returns an Err, which is discarded, if a provider was already installed.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

        let tcp_stream = TcpStream::connect(addr).await
            .with_context(|| format!("Failed to connect to Pharos server at {}", addr))?;

        // --- TLS Configuration ---
        let mut root_store = RootCertStore::empty();
        
        // Add native roots if available (rustls-native-certs 0.8 returns CertificateResult)
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            root_store.add(cert)?;
        }
        if !native_certs.errors.is_empty() {
            log::warn!("Errors loading some native certificates: {:?}", native_certs.errors);
        }

        // Add custom CA if PHAROS_CA_CERT is set
        if let Ok(ca_path_str) = env::var("PHAROS_CA_CERT") {
            let ca_path = Path::new(&ca_path_str);
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(30);
            
            while !ca_path.exists() && start.elapsed() < timeout {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }

            if !ca_path.exists() {
                return Err(anyhow!("Timeout waiting for CA cert at {:?}", ca_path));
            }

            for cert in CertificateDer::pem_file_iter(ca_path)
                .with_context(|| format!("Failed to read CA cert at {:?}", ca_path))?
            {
                let cert = cert.with_context(|| format!("Failed to parse a certificate in {:?}", ca_path))?;
                root_store.add(cert)?;
            }
        }

        // Add webpki roots as a fallback
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        
        let connector = TlsConnector::from(Arc::new(config));
        
        // Use the hostname part of the address for SNI
        let domain = addr.split(':').next().unwrap_or("localhost");
        let server_name = ServerName::try_from(domain)
            .map_err(|_| anyhow!("Invalid server name: {}", domain))?
            .to_owned();

        let tls_stream = connector.connect(server_name, tcp_stream).await
            .context("TLS handshake failed")?;

        let mut reader = BufReader::new(tls_stream);

        // Read banner
        let mut banner = String::new();
        reader.read_line(&mut banner).await
            .context("Failed to read banner from server")?;
        
        if banner.is_empty() {
            return Err(anyhow!("Connection closed by server during banner"));
        }

        let mut client = PharosClient {
            stream: reader,
            client_id: client_id.to_string(),
        };

        // Send ID
        client.send_line(&format!("id {}", client_id)).await?;
        let id_resp = client.read_line().await?;
        if !id_resp.starts_with("200") {
            return Err(anyhow!("Server rejected identification: {}", id_resp));
        }

        Ok(client)
    }

    /// Sends a single command and returns the parsed response.
    pub async fn execute(&mut self, command: &str) -> Result<PharosResponse> {
        self.send_line(command).await?;
        self.parse_response().await
    }

    /// Explicitly authenticates the session using the configured client ID.
    pub async fn authenticate(&mut self) -> Result<()> {
        self.send_line(&format!("login {}", self.client_id)).await?;
        let resp = self.read_line().await?;
        
        if resp.starts_with("301:") {
            let challenge = &resp[4..];
            let (pub_key_ssh, sig_b64) = Self::sign_message_async(challenge).await?;
            
            self.send_line(&format!("auth \"{}\" \"{}\"", pub_key_ssh, sig_b64)).await?;
            let auth_resp = self.read_line().await?;
            
            if auth_resp.starts_with("200") {
                Ok(())
            } else {
                Err(anyhow!("Authentication failed: {}", auth_resp))
            }
        } else {
            Err(anyhow!("Failed to receive challenge from server: {}", resp))
        }
    }

    async fn send_line(&mut self, line: &str) -> Result<()> {
        let mut cmd = line.to_string();
        if !cmd.ends_with("
") {
            cmd.push_str("
");
        }
        self.stream.write_all(cmd.as_bytes()).await
            .context("Failed to write to stream")?;
        self.stream.flush().await
            .context("Failed to flush stream")?;
        Ok(())
    }

    async fn read_line(&mut self) -> Result<String> {
        let mut line = String::new();
        self.stream.read_line(&mut line).await
            .context("Failed to read line from stream")?;
        Ok(line.trim().to_string())
    }

    async fn parse_response(&mut self) -> Result<PharosResponse> {
        let mut records = Vec::new();
        let mut current_record: Option<PharosRecord> = None;
        let mut match_count = 0;

        loop {
            let line = self.read_line().await?;
            if line.is_empty() {
                break;
            }

            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() < 2 {
                continue;
            }

            let code: i32 = parts[0].parse()
                .with_context(|| format!("Invalid response code: {}", parts[0]))?;
            let message = parts[1].trim();

            match code {
                200 => {
                    if let Some(record) = current_record.take() {
                        records.push(record);
                    }
                    if match_count > 0 || !records.is_empty() {
                        return Ok(PharosResponse::Matches { count: match_count, records });
                    } else {
                        return Ok(PharosResponse::Ok(message.to_string()));
                    }
                }
                102 => {
                    // Extract match count if possible
                    if let Some(count_str) = message.split_whitespace().nth(2) {
                        match_count = count_str.parse().unwrap_or(0);
                    }
                }
                506 => {
                    // The server's actual status code for "not logged in yet" (see
                    // pharos-server/src/middleware.rs's SecurityTierMiddleware) — triggers
                    // execute_authenticated()'s automatic login-challenge-sign-retry flow.
                    return Ok(PharosResponse::AuthenticationRequired { challenge: String::new() });
                }
                501 => {
                    // "No matches" for query/change/delete alike - the operation itself
                    // succeeded, it just found nothing to act on. Not a failure: represent
                    // it the same way a real, non-empty match set is represented, just
                    // with zero records, rather than falling into the generic Error bucket.
                    return Ok(PharosResponse::Matches { count: 0, records: Vec::new() });
                }
                c if c >= 400 => {
                    return Ok(PharosResponse::Error { code: c, message: message.to_string() });
                }
                c if c < 0 => {
                    // Data line: -200:ID:FIELD:VALUE
                    let data_parts: Vec<&str> = message.splitn(3, ':').collect();
                    if data_parts.len() == 3 {
                        let id: i32 = data_parts[0].parse().unwrap_or(0);
                        let field = data_parts[1].to_string();
                        let value = data_parts[2].trim().to_string();

                        if let Some(ref mut record) = current_record {
                            if record.id != id {
                                records.push(current_record.take().unwrap());
                                current_record = Some(PharosRecord { id, fields: vec![PharosField { key: field, value }] });
                            } else {
                                record.fields.push(PharosField { key: field, value });
                            }
                        } else {
                            current_record = Some(PharosRecord { id, fields: vec![PharosField { key: field, value }] });
                        }
                    }
                }
                _ => {
                    // Intermediate message (e.g. 100, 101)
                }
            }
        }

        if let Some(record) = current_record {
            records.push(record);
        }

        if match_count > 0 || !records.is_empty() {
            Ok(PharosResponse::Matches { count: match_count, records })
        } else {
            Ok(PharosResponse::Ok("Ok".to_string()))
        }
    }

    /// Performs authenticated execution of a command.
    pub async fn execute_authenticated(&mut self, command: &str) -> Result<PharosResponse> {
        let resp = self.execute(command).await?;
        
        if let PharosResponse::AuthenticationRequired { .. } = resp {
            self.authenticate().await?;
            // Retry original command
            return self.execute(command).await;
        }

        Ok(resp)
    }

    /// Pure and synchronous by design so it's cheaply unit-testable without touching real env
    /// vars, the filesystem, or the 60s wait loop in sign_message_async.
    fn describe_attempted_paths(
        personal_key_path: &str,
        used_personal_key: bool,
        resolved_path: &str,
        fallback_path: &str,
    ) -> Vec<String> {
        let mut tried = Vec::new();
        if !used_personal_key {
            tried.push(personal_key_path.to_string());
        }
        tried.push(resolved_path.to_string());
        tried.push(fallback_path.to_string());
        tried
    }

    pub async fn sign_message_async(message: &str) -> Result<(String, String)> {
        let home = env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let personal_key_path = format!("{}/.ssh/id_ed25519", home);

        let (priv_key_path_str, used_personal_key) = match env::var("PHAROS_PRIVATE_KEY") {
            Ok(explicit) => (explicit, false),
            Err(_) => {
                if Path::new(&personal_key_path).exists() {
                    (personal_key_path.clone(), true)
                } else {
                    (format!("{}/.ssh/admin_id_ed25519", home), false)
                }
            }
        };

        let priv_key_path = Path::new(&priv_key_path_str);

        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(60);

        if !priv_key_path.exists() {
            log::info!("Waiting for private key at {:?} (timeout: 60s)...", priv_key_path);
        }

        while !priv_key_path.exists() && start.elapsed() < timeout {
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }

        if !priv_key_path.exists() {
            let fallback_path = Path::new("/etc/pharos/keys/admin_id_ed25519");
            if fallback_path.exists() {
                log::info!("Primary key not found, but found fallback at {:?}", fallback_path);
                return Self::sign_with_key_path(fallback_path, message).await;
            }

            let tried = Self::describe_attempted_paths(
                &personal_key_path,
                used_personal_key,
                &priv_key_path_str,
                &fallback_path.display().to_string(),
            );
            let tried_list = tried.iter().map(|p| format!("  - {}", p)).collect::<Vec<_>>().join("\n");

            return Err(anyhow!(
                "No private key found for signing. Checked, in order:\n{}\n\n\
                 If this machine is separate from the hub that generated the admin key, generate \
                 a personal key here instead of copying the sensitive admin private key: \
                 `ssh-keygen -t ed25519 -f {}`, then enroll its PUBLIC half (the .pub file) in \
                 the hub's /etc/pharos/keys/ directory under a filename containing \"admin\" as \
                 its own token (e.g. <name>-admin_id_ed25519.pub), and reload pharos-server. Or \
                 set PHAROS_PRIVATE_KEY to point at a specific key file.",
                tried_list, personal_key_path
            ));
        }

        Self::sign_with_key_path(priv_key_path, message).await
    }

    async fn sign_with_key_path(path: &Path, message: &str) -> Result<(String, String)> {
        let key_content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read private key at {:?}", path))?;
        let priv_key = PrivateKey::from_openssh(&key_content)
            .map_err(|e| anyhow!("Failed to parse SSH private key: {}", e))?;
        
        // Use raw key data signing to match the server's raw verification logic.
        let sig_bytes = match priv_key.key_data() {
            ssh_key::private::KeypairData::Ed25519(kp) => {
                use ed25519_dalek::{Signer, SigningKey};
                let signing_key = SigningKey::from_bytes(&kp.private.to_bytes());
                signing_key.sign(message.as_bytes()).to_vec()
            }
            _ => return Err(anyhow!("Unsupported key type for raw signing. Only Ed25519 is supported.")),
        };

        let sig_b64 = STANDARD.encode(&sig_bytes);
        let pub_key_ssh = priv_key.public_key().to_openssh()
            .map_err(|e| anyhow!("Failed to export public key: {}", e))?;
        
        Ok((pub_key_ssh, sig_b64))
    }

    pub async fn quit(mut self) -> Result<()> {
        self.send_line("quit").await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_join_args_unchanged_when_no_value_contains_whitespace() {
        let args = vec!["add".to_string(), "hostname=db-01".to_string(), "ip=10.0.0.5".to_string()];
        assert_eq!(join_wire_args(&args), "add hostname=db-01 ip=10.0.0.5");
    }

    #[test]
    fn test_should_requote_value_when_shell_stripped_quotes_around_whitespace() {
        // Simulates argv after the shell has already parsed `name="Jane Smith"`:
        // one element, quotes gone, space still inside.
        let args = vec!["add".to_string(), "name=Jane Smith".to_string(), "type=person".to_string()];
        assert_eq!(join_wire_args(&args), r#"add name="Jane Smith" type=person"#);
    }

    #[test]
    fn test_should_quote_bare_multiword_token_without_a_key() {
        let args = vec!["query".to_string(), "Jane Smith".to_string()];
        assert_eq!(join_wire_args(&args), r#"query "Jane Smith""#);
    }

    #[test]
    fn test_should_escape_embedded_quotes_and_backslashes_in_value() {
        let args = vec![r#"name=Jane "JJ" Smith\Jones"#.to_string()];
        assert_eq!(join_wire_args(&args), r#"name="Jane \"JJ\" Smith\\Jones""#);
    }

    #[test]
    fn test_should_leave_value_containing_equals_sign_unquoted_when_no_whitespace() {
        let args = vec!["filter=a=b".to_string()];
        assert_eq!(join_wire_args(&args), "filter=a=b");
    }

    #[test]
    fn test_should_list_all_attempted_paths_when_personal_key_not_used() {
        let tried = PharosClient::describe_attempted_paths(
            "/home/user/.ssh/id_ed25519",
            false,
            "/home/user/.ssh/admin_id_ed25519",
            "/etc/pharos/keys/admin_id_ed25519",
        );
        assert_eq!(tried, vec![
            "/home/user/.ssh/id_ed25519".to_string(),
            "/home/user/.ssh/admin_id_ed25519".to_string(),
            "/etc/pharos/keys/admin_id_ed25519".to_string(),
        ]);
    }

    #[test]
    fn test_should_omit_personal_key_from_list_when_it_was_the_resolved_path() {
        let tried = PharosClient::describe_attempted_paths(
            "/home/user/.ssh/id_ed25519",
            true,
            "/home/user/.ssh/id_ed25519",
            "/etc/pharos/keys/admin_id_ed25519",
        );
        assert_eq!(tried, vec![
            "/home/user/.ssh/id_ed25519".to_string(),
            "/etc/pharos/keys/admin_id_ed25519".to_string(),
        ]);
    }
    
    // For more robust testing, we'd want to mock the TCP stream.
    // However, for this increment, we will verify integration with ph and mdb.
}
