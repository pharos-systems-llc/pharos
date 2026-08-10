/* ========================================================================
 * Project: pharos
 * Component: Server Core
 * File: pharos-server/src/lib.rs
 * Author: Richard D. (https://github.com/iamrichardd)
 * License: AGPL-3.0 (See LICENSE file for details)
 * * Purpose (The "Why"):
 * This is the library entry point for the pharos backend server. It exports
 * the core components like protocol, storage, metrics, auth, and middleware.
 * * Traceability:
 * Related to GitHub Issue #33.
 * ======================================================================== */

pub mod protocol;
pub mod storage;
pub mod metrics;
pub mod auth;
pub mod middleware;
pub mod tui;
pub mod sync;
pub mod alerting;
pub mod notifications;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, AsyncRead, AsyncWrite};
use tracing::{info, error, instrument};
use crate::protocol::{Command, parse_command, ProtocolError};
use crate::storage::{Storage};
use crate::auth::AuthManager;
use crate::middleware::{MiddlewareChain, ClientContext, MiddlewareAction};
use std::sync::{Arc, RwLock};

fn check_change_limits(
    matched: &[crate::storage::Record],
    modifications: &[(String, String)],
    options: &crate::middleware::SessionOptions,
) -> Result<(), crate::storage::StorageError> {
    if options.limit.is_some_and(|limit| matched.len() > limit) {
        return Err(crate::storage::StorageError::TooManyEntries(matched.len()));
    }
    if options.addonly {
        let overridden = matched.iter().any(|record| {
            modifications.iter().any(|(field, _)| record.fields.contains_key(field))
        });
        if overridden {
            return Err(crate::storage::StorageError::AddOnlyViolation);
        }
    }
    Ok(())
}

fn check_delete_limit(
    matched: &[crate::storage::Record],
    options: &crate::middleware::SessionOptions,
) -> Result<(), crate::storage::StorageError> {
    if options.limit.is_some_and(|limit| matched.len() > limit) {
        return Err(crate::storage::StorageError::TooManyEntries(matched.len()));
    }
    Ok(())
}

/// A SYNC-prefixed command's suppression effects (skip re-replication, skip webhook
/// notification) are only honored when the connection presenting it authenticated as a
/// recognized peer server (the `peer` role, granted via filename convention on
/// `PHAROS_KEYS_DIR` - see `auth.rs`'s `register_key`). Any other connection can still type
/// `SYNC ` in front of a command, but it has no effect: the write still happens, and it still
/// replicates/notifies exactly like an ordinary write - defeating the incentive to spoof it as
/// a way to hide a write from the audit trail.
fn is_trusted_sync_peer(is_forwarded: bool, roles: &[String]) -> bool {
    is_forwarded && roles.iter().any(|r| r == "peer")
}

/// Normalizes a client identification string (`client_id`) down to a canonical source category string
/// (`mdb`, `ph`, `pharos-scan`, `pharos-pulse`, `web-console`), or returns `None` if unrecognized.
/// This classification allows downstream write-path telemetry and provenance tracking to categorize
/// records into well-defined client sources regardless of specific hostnames or web tool sub-variants.
fn normalize_source(client_id: &str) -> Option<&'static str> {
    match client_id {
        "mdb" => Some("mdb"),
        "ph" => Some("ph"),
        "pharos-scan" => Some("pharos-scan"),
        id if id.starts_with("pulse-") => Some("pharos-pulse"),
        id if id.starts_with("web-") || id == "pharos-console-web" => Some("web-console"),
        _ => None,
    }
}

#[instrument(skip(socket, storage, auth_manager, middleware_chain))]
pub async fn handle_connection<S>(socket: S, peer_addr: String, storage: Arc<RwLock<dyn Storage>>, auth_manager: Arc<AuthManager>, middleware_chain: Arc<MiddlewareChain>) -> anyhow::Result<()> 
where S: AsyncRead + AsyncWrite + Unpin + Send + 'static
{
    let (reader, mut writer) = tokio::io::split(socket);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    let mut context = ClientContext {
        id: None,
        authenticated: false,
        peer_addr: peer_addr.clone(),
        roles: Vec::new(),
        teams: Vec::new(),
        tier: crate::auth::SecurityTier::Open,
        login_alias: None,
        fingerprint: None,
        options: crate::middleware::SessionOptions::default(),
    };

    let _ = crate::tui::EVENT_TX.send(format!("Connection established from {}", peer_addr));

    // Send initial status message as per Ph protocol expectation
    // S: 200:Database ready
    writer.write_all(b"200:Database ready\n").await?;
    writer.flush().await?;

    let my_addr = std::env::var("PHAROS_SYNC_ADDR").unwrap_or_default();

    loop {
        // write_all() on the TLS write-half only queues plaintext; without an
        // explicit flush, a response spanning enough write_all() calls (e.g. a
        // multi-record full-field query) can leave its tail sitting in the TLS
        // write buffer forever once the loop moves on to await the next read -
        // the client blocks reading bytes that were never actually sent. Flushing
        // whatever the previous iteration wrote, right before blocking on the next
        // read, covers every response path (including the early `continue`s below)
        // in one place instead of flushing after every individual write_all().
        writer.flush().await?;

        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            break; // Connection closed
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (is_forwarded, input) = crate::sync::strip_sync_prefix(trimmed);
        let is_trusted_sync = is_trusted_sync_peer(is_forwarded, &context.roles);

        if is_forwarded && !is_trusted_sync {
            tracing::warn!(
                peer = %context.peer_addr,
                "Received SYNC-prefixed command from a non-peer connection - ignoring the prefix for \
                 replication/notification-suppression purposes (command will still execute and will \
                 still replicate/notify normally)"
            );
        }

        if is_forwarded {
            info!("Received command: [SYNC] {}", crate::protocol::redact_wire_line_for_logging(input));
        } else {
            info!("Received command: {}", crate::protocol::redact_wire_line_for_logging(input));
        }

        match parse_command(input) {
            Ok(mut command) => {
                // Execute Middleware Chain (Pre-processing)
                match middleware_chain.pre_process(&mut command, &mut context) {
                    Ok(MiddlewareAction::ShortCircuit(resp)) => {
                        writer.write_all(resp.as_bytes()).await?;
                        continue;
                    }
                    Ok(MiddlewareAction::Continue) => {}
                    Err(e) => {
                        error!("Middleware error: {:?}", e);
                        writer.write_all(b"500:Internal server error (middleware)\n").await?;
                        continue;
                    }
                }

                match &command {
                    Command::Status => {
                        writer.write_all(b"100:Pharos server active\n200:Ok\n").await?;
                    }
                    Command::Id(id) => {
                        context.id = Some(id.to_lowercase());
                        writer.write_all(b"200:Ok\n").await?;
                    }
                    Command::Fields(requested) => {
                        // Harvest all record field keys to identify dynamically added user-defined fields.
                        let all_records = {
                            let lock = storage.read().map_err(|_| anyhow::anyhow!("Storage lock poisoned"))?;
                            lock.query(&[], None)
                        };

                        let mut harvested_fields = std::collections::HashSet::new();
                        match all_records {
                            Ok(records) => {
                                for record in records {
                                    for key in record.fields.keys() {
                                        harvested_fields.insert(key.clone());
                                    }
                                    for key in record.multi_fields.keys() {
                                        harvested_fields.insert(key.clone());
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Storage query failed for fields command: {}", e);
                            }
                        }

                        // Combine the dynamic fields with the baseline schema.
                        let mut merged: std::collections::HashMap<String, (usize, String)> = std::collections::HashMap::new();
                        let baseline = [
                            ("type", 64, "Record type discriminator (e.g. \"person\" or \"machine\")."),
                            ("hostname", 256, "Unique identifier for a machine entry; used to detect an existing record on add/upsert."),
                            ("alias", 32, "Unique short identifier for a person entry; used to detect an existing record on add/upsert."),
                            ("created_at", 32, "ISO-8601 timestamp of when this entry was first created (server-injected)."),
                            ("last_seen_at", 32, "ISO-8601 timestamp of the most recent update to this entry (server-injected)."),
                            ("status", 64, "Free-form status/presence value (e.g. \"active\", \"online\", \"offline\")."),
                        ];
                        for &(name, max_len, desc) in &baseline {
                            merged.insert(name.to_string(), (max_len, desc.to_string()));
                        }

                        for field_name in harvested_fields {
                            merged.entry(field_name).or_insert((256, "User-defined field; no additional metadata available.".to_string()));
                        }

                        // Maintain sorting for deterministic IDs and display order.
                        let mut sorted_names: Vec<String> = merged.keys().cloned().collect();
                        sorted_names.sort();

                        let fields_with_ids: Vec<(usize, String, usize, String)> = sorted_names
                            .into_iter()
                            .enumerate()
                            .map(|(index, name)| {
                                let (max_len, desc) = merged.get(&name).unwrap().clone();
                                (index + 1, name, max_len, desc)
                            })
                            .collect();

                        let to_emit = if requested.is_empty() {
                            fields_with_ids
                        } else {
                            let requested_set: std::collections::HashSet<&String> = requested.iter().collect();
                            let filtered: Vec<(usize, String, usize, String)> = fields_with_ids
                                .into_iter()
                                .filter(|(_, name, _, _)| requested_set.contains(name))
                                .collect();

                            if filtered.is_empty() {
                                writer.write_all(b"507:Field does not exist\n").await?;
                                continue;
                            }
                            filtered
                        };

                        // Output the fields technical details and descriptions sequentially.
                        for (id, name, max_len, description) in to_emit {
                            let technical_line = format!("-200:{}:{}:max {} Public\n", id, name, max_len);
                            let description_line = format!("-200:{}:{}:{}\n", id, name, description);
                            writer.write_all(technical_line.as_bytes()).await?;
                            writer.write_all(description_line.as_bytes()).await?;
                        }
                        writer.write_all(b"200:Ok.\n").await?;
                    }
                    Command::Login(alias) => {
                        let challenge = auth_manager.generate_challenge(alias);
                        context.login_alias = Some(alias.clone());
                        writer.write_all(format!("301:{}\n", challenge).as_bytes()).await?;
                    }
                    Command::Auth { public_key, signature } => {
                        let challenge = context.login_alias.as_ref()
                            .and_then(|alias| auth_manager.get_challenge(alias));

                        if let Some(challenge) = challenge {
                            if let Some(fingerprint) = auth_manager.verify_with_fingerprint(public_key, signature, &challenge) {
                                if let Some(alias) = &context.login_alias {
                                    auth_manager.consume_challenge(alias);
                                }
                                context.authenticated = true;
                                context.roles = auth_manager.get_roles(public_key);
                                context.teams = auth_manager.get_teams(public_key);
                                context.fingerprint = Some(fingerprint);
                                writer.write_all(b"200:Ok\n").await?;
                            } else {
                                writer.write_all(b"516:No authorization for request\n").await?;
                            }
                        } else {
                            writer.write_all(b"506:Request refused; must be logged in to execute (Challenge expired or not found)\n").await?;
                        }
                    }
                    Command::AuthCheck { public_key, signature, challenge } => {
                        if auth_manager.verify(public_key, signature, challenge) {
                            writer.write_all(b"200:Ok\n").await?;
                        } else {
                            writer.write_all(b"516:No authorization for request\n").await?;
                        }
                    }
                    Command::Quit => {
                        writer.write_all(b"200:Bye!\n").await?;
                        break;
                    }
                    Command::Add(fields) => {
                        let team = context.teams.first().cloned();

                        let mut augmented_fields: Vec<(String, String)> = fields
                            .iter()
                            .filter(|(k, _)| k != "source")
                            .cloned()
                            .collect();

                        let source = context.id.as_deref().and_then(normalize_source);
                        if let Some(s) = source {
                            augmented_fields.push(("source".to_string(), s.to_string()));
                        }

                        let field_map_for_notification: std::collections::HashMap<String, String> = augmented_fields.iter().cloned().collect();
                        let result = {
                            let mut lock = storage.write().map_err(|_| anyhow::anyhow!("Storage lock poisoned"))?;
                            lock.upsert_record(augmented_fields, context.fingerprint.clone(), team)
                        };

                        match result {
                            Ok(outcome) => {
                                let source_label = source.unwrap_or("unknown");
                                match outcome {
                                    crate::storage::UpsertOutcome::Created => {
                                        crate::metrics::RECORDS_ADDED_TOTAL.with_label_values(&[source_label]).inc();
                                    }
                                    crate::storage::UpsertOutcome::Updated => {
                                        crate::metrics::RECORDS_UPDATED_TOTAL.with_label_values(&[source_label]).inc();
                                    }
                                }

                                let _ = crate::tui::EVENT_TX.send(format!("[{}] Added/Updated record", context.peer_addr));
                                writer.write_all(b"200:Ok\n").await?;

                                if !is_trusted_sync {
                                    crate::notifications::notify(crate::notifications::NotificationEvent::Add {
                                        fields: field_map_for_notification,
                                    });
                                }

                                // Replicate to peers if not already forwarded
                                if !is_trusted_sync && !my_addr.is_empty() {
                                    let storage_clone = Arc::clone(&storage);
                                    let cmd_str = input.to_string();
                                    let my_addr_clone = my_addr.clone();
                                    tokio::spawn(async move {
                                        crate::sync::replicate_command(storage_clone, cmd_str, my_addr_clone).await;
                                    });
                                }
                            }
                            Err(crate::storage::StorageError::InvalidArgument(msg)) => {
                                writer.write_all(format!("512:Illegal value: {}\n", msg).as_bytes()).await?;
                            }
                            Err(crate::storage::StorageError::Collision) | Err(crate::storage::StorageError::Unauthorized) => {
                                writer.write_all(b"511:Not authorized to add entries\n").await?;
                            }
                            Err(crate::storage::StorageError::ReadOnly) => {
                                writer.write_all(b"517:Operation failed because database is read-only\n").await?;
                            }
                            Err(e) => {
                                error!("Storage error: {}", e);
                                writer.write_all(b"500:Internal storage error\n").await?;
                            }
                        }
                    }
                    Command::Query { selections, returns } => {
                        let default_type = match context.id.as_deref() {
                            Some(ctx) if ctx.contains("ph") => Some(crate::storage::RecordType::Person),
                            Some(ctx) if ctx.contains("mdb") => Some(crate::storage::RecordType::Machine),
                            _ => None,
                        };

                        let query_result = {
                            let lock = storage.read().map_err(|_| anyhow::anyhow!("Storage lock poisoned"))?;
                            lock.query(selections, default_type)
                        };

                        let (records, count) = match query_result {
                            Ok(results) => {
                                let count = results.len();
                                (results, count)
                            }
                            Err(crate::storage::StorageError::InvalidArgument(msg)) => {
                                writer.write_all(format!("512:Illegal value: {}\n", msg).as_bytes()).await?;
                                continue;
                            }
                            Err(e) => {
                                error!("Query error: {}", e);
                                writer.write_all(b"500:Internal storage error\n").await?;
                                continue;
                            }
                        };

                        let _ = crate::tui::EVENT_TX.send(format!("[{}] Queried records, matches: {}", context.peer_addr, count));

                        if records.is_empty() {
                            writer.write_all(b"501:No matches to query\n").await?;
                        } else {
                            writer.write_all(format!("102:There were {} matches to your request.\n", count).as_bytes()).await?;
                             for (i, record) in records.iter().enumerate() {
                                let index = i + 1;
                                let mut keys: Vec<&String> = if returns.is_empty() {
                                    let mut k_set: Vec<&String> = record.fields.keys().collect();
                                    for mk in record.multi_fields.keys() {
                                        if !k_set.contains(&mk) {
                                            k_set.push(mk);
                                        }
                                    }
                                    k_set
                                } else {
                                    returns.iter().filter(|k| record.fields.contains_key(*k) || record.multi_fields.contains_key(*k)).collect()
                                };
                                keys.sort();

                                for field_name in keys {
                                    if let Some(field_val) = record.fields.get(field_name) {
                                        let line = format!("-200:{}:{}: {}\n", index, field_name, field_val);
                                        writer.write_all(line.as_bytes()).await?;
                                    } else if let Some(values) = record.multi_fields.get(field_name) {
                                        let padding = " ".repeat(field_name.len());
                                        for (idx, val) in values.iter().enumerate() {
                                            let name_to_use = if idx == 0 { field_name.as_str() } else { &padding };
                                            let line = format!("-200:{}:{}: {}\n", index, name_to_use, val);
                                            writer.write_all(line.as_bytes()).await?;
                                        }
                                    }
                                }
                            }
                            writer.write_all(b"200:Ok\n").await?;
                        }
                    }
                    Command::Change { selections, modifications, force: _ } => {
                        // `force` is parsed but has no effect: it exists in the RFC to permit
                        // overriding fields marked "Encrypt", a concept Pharos's Record/Storage
                        // model doesn't have. Nothing to force-override yet.
                        let result = {
                            let mut lock = storage.write().map_err(|_| anyhow::anyhow!("Storage lock poisoned"))?;
                            if context.options.limit.is_none() && !context.options.addonly {
                                // No session limits configured - skip the extra pre-flight scan.
                                lock.change_record(selections, modifications, context.fingerprint.clone(), &context.teams)
                            } else {
                                match lock.query(selections, None) {
                                    Ok(matched) => match check_change_limits(&matched, modifications, &context.options) {
                                        Ok(()) => lock.change_record(selections, modifications, context.fingerprint.clone(), &context.teams),
                                        Err(e) => Err(e),
                                    },
                                    Err(e) => Err(e),
                                }
                            }
                        };

                        match result {
                            Ok(count) => {
                                if count > 0 {
                                    let noun = if count == 1 { "entry" } else { "entries" };
                                    writer.write_all(format!("200:{} {} changed.\n", count, noun).as_bytes()).await?;

                                    // Replicate change to peers, unless this command was itself a
                                    // replica of another node's change (would otherwise ping-pong
                                    // between peers forever - see Issue #170).
                                    if !is_trusted_sync && !my_addr.is_empty() {
                                        let storage_clone = Arc::clone(&storage);
                                        let cmd_str = input.to_string();
                                        let my_addr_clone = my_addr.clone();
                                        tokio::spawn(async move {
                                            crate::sync::replicate_command(storage_clone, cmd_str, my_addr_clone).await;
                                        });
                                    }

                                    if !is_trusted_sync {
                                        crate::notifications::notify(crate::notifications::NotificationEvent::Change {
                                            selections: selections.clone(),
                                            modifications: modifications.clone(),
                                            count,
                                        });
                                    }
                                } else {
                                    writer.write_all(b"501:No matches to change\n").await?;
                                }
                            }
                            Err(crate::storage::StorageError::InvalidArgument(msg)) => {
                                writer.write_all(format!("512:Illegal value: {}\n", msg).as_bytes()).await?;
                            }
                            Err(crate::storage::StorageError::TooManyEntries(n)) => {
                                writer.write_all(format!("518:Too many entries selected by change command ({} matched)\n", n).as_bytes()).await?;
                            }
                            Err(crate::storage::StorageError::AddOnlyViolation) => {
                                writer.write_all(b"521:Change command would have overridden existing field, and addonly option is on\n").await?;
                            }
                            Err(crate::storage::StorageError::Unauthorized) => {
                                writer.write_all(b"510:Not authorized to change this entry\n").await?;
                            }
                            Err(crate::storage::StorageError::ReadOnly) => {
                                writer.write_all(b"517:Operation failed because database is read-only\n").await?;
                            }
                            Err(e) => {
                                error!("Storage error: {}", e);
                                writer.write_all(b"500:Internal storage error\n").await?;
                            }
                        }
                    }
                    Command::Delete(selections) => {
                        let result = {
                            let mut lock = storage.write().map_err(|_| anyhow::anyhow!("Storage lock poisoned"))?;
                            if context.options.limit.is_none() {
                                // No session limit configured - skip the extra pre-flight scan.
                                lock.delete_record(selections, context.fingerprint.clone(), &context.teams, &context.roles)
                            } else {
                                match lock.query(selections, None) {
                                    Ok(matched) => match check_delete_limit(&matched, &context.options) {
                                        Ok(()) => lock.delete_record(selections, context.fingerprint.clone(), &context.teams, &context.roles),
                                        Err(e) => Err(e),
                                    },
                                    Err(e) => Err(e),
                                }
                            }
                        };

                        match result {
                            Ok(count) => {
                                if count > 0 {
                                    let source_label = context.id.as_deref().and_then(normalize_source).unwrap_or("unknown");
                                    crate::metrics::RECORDS_DELETED_TOTAL.with_label_values(&[source_label]).inc_by(count as u64);
                                    writer.write_all(b"200:Ok\n").await?;

                                    // Replicate delete to peers, unless this command was itself a
                                    // replica of another node's delete.
                                    if !is_trusted_sync && !my_addr.is_empty() {
                                        let storage_clone = Arc::clone(&storage);
                                        let cmd_str = input.to_string();
                                        let my_addr_clone = my_addr.clone();
                                        tokio::spawn(async move {
                                            crate::sync::replicate_command(storage_clone, cmd_str, my_addr_clone).await;
                                        });
                                    }

                                    if !is_trusted_sync {
                                        crate::notifications::notify(crate::notifications::NotificationEvent::Delete {
                                            selections: selections.clone(),
                                            count,
                                        });
                                    }
                                } else {
                                    writer.write_all(b"501:No matches to delete\n").await?;
                                }
                            }
                            Err(crate::storage::StorageError::TooManyEntries(n)) => {
                                writer.write_all(format!("518:Too many entries selected by delete command ({} matched)\n", n).as_bytes()).await?;
                            }
                            Err(crate::storage::StorageError::Unauthorized) => {
                                writer.write_all(b"516:No authorization for request\n").await?;
                            }
                            Err(crate::storage::StorageError::ReadOnly) => {
                                writer.write_all(b"517:Operation failed because database is read-only\n").await?;
                            }
                            Err(e) => {
                                error!("Storage error: {}", e);
                                writer.write_all(b"500:Internal storage error\n").await?;
                            }
                        }
                    }
                    Command::Set(tokens) => {
                        if tokens.is_empty() {
                            writer.write_all(format!("-200:echo:{}\n", if context.options.echo { "on" } else { "off" }).as_bytes()).await?;
                            writer.write_all(format!("-200:limit:{}\n", match context.options.limit {
                                Some(l) => l.to_string(),
                                None => "off".to_string(),
                            }).as_bytes()).await?;
                            writer.write_all(format!("-200:charset:{}\n", context.options.charset).as_bytes()).await?;
                            writer.write_all(format!("-200:verbose:{}\n", if context.options.verbose { "on" } else { "off" }).as_bytes()).await?;
                            writer.write_all(format!("-200:addonly:{}\n", if context.options.addonly { "on" } else { "off" }).as_bytes()).await?;
                            writer.write_all(format!("-200:nolog:{}\n", if context.options.nolog { "on" } else { "off" }).as_bytes()).await?;
                            writer.write_all(format!("-200:external:{}\n", if context.options.external { "on" } else { "off" }).as_bytes()).await?;
                            writer.write_all(b"200:Done.\n").await?;
                        } else {
                            let mut new_options = context.options.clone();
                            let mut validation_error = None;
                            for token in tokens {
                                let mut parts = token.splitn(2, '=');
                                let key = parts.next().unwrap_or("").trim().to_lowercase();
                                let val = parts.next().unwrap_or("on").trim();
                                
                                match key.as_str() {
                                    "limit" => {
                                        if val.eq_ignore_ascii_case("off") {
                                            new_options.limit = None;
                                        } else if let Ok(n) = val.parse::<usize>() {
                                            new_options.limit = Some(n);
                                        } else {
                                            validation_error = Some("512:Illegal value\n");
                                            break;
                                        }
                                    }
                                    "echo" => {
                                        if val.eq_ignore_ascii_case("on") {
                                            new_options.echo = true;
                                        } else if val.eq_ignore_ascii_case("off") {
                                            new_options.echo = false;
                                        } else {
                                            validation_error = Some("512:Illegal value\n");
                                            break;
                                        }
                                    }
                                    "verbose" => {
                                        if val.eq_ignore_ascii_case("on") {
                                            new_options.verbose = true;
                                        } else if val.eq_ignore_ascii_case("off") {
                                            new_options.verbose = false;
                                        } else {
                                            validation_error = Some("512:Illegal value\n");
                                            break;
                                        }
                                    }
                                    "addonly" => {
                                        if val.eq_ignore_ascii_case("on") {
                                            new_options.addonly = true;
                                        } else if val.eq_ignore_ascii_case("off") {
                                            new_options.addonly = false;
                                        } else {
                                            validation_error = Some("512:Illegal value\n");
                                            break;
                                        }
                                    }
                                    "nolog" => {
                                        if val.eq_ignore_ascii_case("on") {
                                            new_options.nolog = true;
                                        } else if val.eq_ignore_ascii_case("off") {
                                            new_options.nolog = false;
                                        } else {
                                            validation_error = Some("512:Illegal value\n");
                                            break;
                                        }
                                    }
                                    "external" => {
                                        if val.eq_ignore_ascii_case("on") {
                                            new_options.external = true;
                                        } else if val.eq_ignore_ascii_case("off") {
                                            new_options.external = false;
                                        } else {
                                            validation_error = Some("512:Illegal value\n");
                                            break;
                                        }
                                    }
                                    "charset" => {
                                        // Note: Pharos doesn't actually perform charset conversion.
                                        // This is accepted-and-echoed state only, matching existing project convention of not building unused functionality.
                                        new_options.charset = val.to_string();
                                    }
                                    _ => {
                                        validation_error = Some("513:Unknown option\n");
                                        break;
                                    }
                                }
                            }
                            if let Some(err_msg) = validation_error {
                                writer.write_all(err_msg.as_bytes()).await?;
                            } else {
                                context.options = new_options;
                                writer.write_all(b"200:Done.\n").await?;
                            }
                        }
                    }
                    _ => {
                        // Pharos extension: 597 Command recognized, but not yet implemented.
                        // Deliberately not 598 (RFC "Command unknown" which matches ProtocolError::UnknownCommand)
                        // and not colliding with any standard RFC-Appendix-B-defined number.
                        writer.write_all(b"597:Command recognized, but not yet implemented\n").await?;
                    }
                }

                // Post-processing
                middleware_chain.post_process(&command, &context);
            }
            Err(ProtocolError::UnknownCommand) => {
                writer.write_all(b"598:Command unknown\n").await?;
            }
            Err(ProtocolError::SyntaxError) => {
                writer.write_all(b"599:Syntax error\n").await?;
            }
            Err(ProtocolError::InvalidArgument) => {
                writer.write_all(b"512:Illegal value\n").await?;
            }
        }
    }

    // Covers responses written just before a `break` (e.g. Command::Quit's
    // "200:Bye!") that exit the loop without reaching the top-of-loop flush.
    writer.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Record, StorageError};
    use crate::middleware::SessionOptions;
    use std::collections::HashMap;

    #[test]
    fn test_check_delete_limit() {
        let matched = vec![
            Record { id: 1, record_type: None, fields: HashMap::new(), multi_fields: HashMap::new(), owner_fingerprint: None, owner_team: None },
            Record { id: 2, record_type: None, fields: HashMap::new(), multi_fields: HashMap::new(), owner_fingerprint: None, owner_team: None },
        ];
        
        let mut options = SessionOptions::default();
        // Default is None (no limit)
        assert!(check_delete_limit(&matched, &options).is_ok());

        // Limit matches count
        options.limit = Some(2);
        assert!(check_delete_limit(&matched, &options).is_ok());

        // Limit strictly less than count
        options.limit = Some(1);
        match check_delete_limit(&matched, &options) {
            Err(StorageError::TooManyEntries(n)) => assert_eq!(n, 2),
            _ => panic!("Expected TooManyEntries error"),
        }
    }

    #[test]
    fn test_check_change_limits() {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "alice".to_string());
        let matched = vec![
            Record { id: 1, record_type: None, fields, multi_fields: HashMap::new(), owner_fingerprint: None, owner_team: None },
        ];

        let mut options = SessionOptions::default();
        let modifications = vec![("name".to_string(), "bob".to_string())];

        // Default limit/addonly is permissive
        assert!(check_change_limits(&matched, &modifications, &options).is_ok());

        // Addonly checks
        options.addonly = true;
        // Overwriting existing field "name" should fail
        match check_change_limits(&matched, &modifications, &options) {
            Err(StorageError::AddOnlyViolation) => {},
            _ => panic!("Expected AddOnlyViolation error"),
        }

        // Modifying non-existent field should succeed even with addonly
        let new_modifications = vec![("age".to_string(), "30".to_string())];
        assert!(check_change_limits(&matched, &new_modifications, &options).is_ok());
    }

    #[test]
    fn test_is_trusted_sync_peer() {
        assert!(is_trusted_sync_peer(true, &["peer".to_string()]));
        assert!(!is_trusted_sync_peer(true, &["admin".to_string()]));
        assert!(!is_trusted_sync_peer(false, &["peer".to_string()]));
        assert!(!is_trusted_sync_peer(false, &[]));
    }

    #[test]
    fn test_should_normalize_mdb_client_id() {
        assert_eq!(normalize_source("mdb"), Some("mdb"));
    }

    #[test]
    fn test_should_normalize_ph_client_id() {
        assert_eq!(normalize_source("ph"), Some("ph"));
    }

    #[test]
    fn test_should_normalize_pharos_scan_client_id() {
        assert_eq!(normalize_source("pharos-scan"), Some("pharos-scan"));
    }

    #[test]
    fn test_should_normalize_pulse_prefixed_client_id_regardless_of_hostname() {
        assert_eq!(normalize_source("pulse-technitium-01"), Some("pharos-pulse"));
        assert_eq!(normalize_source("pulse-rdelgadoXPS15"), Some("pharos-pulse"));
    }

    #[test]
    fn test_should_normalize_all_known_web_console_client_ids() {
        assert_eq!(normalize_source("web-console"), Some("web-console"));
        assert_eq!(normalize_source("web-console-add"), Some("web-console"));
        assert_eq!(normalize_source("web-mdb-search"), Some("web-console"));
        assert_eq!(normalize_source("web-mcp"), Some("web-console"));
        assert_eq!(normalize_source("pharos-console-web"), Some("web-console"));
    }

    #[test]
    fn test_should_return_none_for_unrecognized_client_id() {
        assert_eq!(normalize_source("test-client"), None);
        assert_eq!(normalize_source(""), None);
    }

}
