/* ========================================================================
 * Project: pharos
 * Component: Server Core
 * File: pharos-server/src/storage.rs
 * Author: Richard D. (https://github.com/iamrichardd)
 * License: AGPL-3.0 (See LICENSE file for details)
 * * Purpose (The "Why"):
 * This module implements the in-memory storage engine for the Ph protocol.
 * It provides the core data structures for records and fields, along with
 * search logic optimized for read-heavy workloads.
 * * Traceability:
 * Implements RFC 2378 Section 1.1 and Section 3.
 * ======================================================================== */

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};
use tracing::{instrument, info, warn, error, debug};
use chrono::Utc;
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordType {
    Person,
    Machine,
    Other(String),
}

impl From<&str> for RecordType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "person" => RecordType::Person,
            "machine" => RecordType::Machine,
            _ => RecordType::Other(s.to_string()),
        }
    }
}

impl RecordType {
    pub fn as_str(&self) -> &str {
        match self {
            RecordType::Person => "person",
            RecordType::Machine => "machine",
            RecordType::Other(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Record {
    pub id: usize,
    pub record_type: Option<RecordType>,
    pub fields: HashMap<String, String>,
    #[serde(default)]
    pub multi_fields: HashMap<String, Vec<String>>,
    pub owner_fingerprint: Option<String>,
    pub owner_team: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
    Created,
    Updated,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Record already exists and is bonded to a different fingerprint (Collision)")]
    Collision,
    #[error("Unauthorized: Record belongs to another team")]
    Unauthorized,
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Internal storage error: {0}")]
    Internal(String),
    #[error("Too many entries selected ({0} matched)")]
    TooManyEntries(usize),
    #[error("Change command would have overridden existing field, and addonly option is on")]
    AddOnlyViolation,
    #[error("Operation failed because database is read-only")]
    ReadOnly,
}

pub trait Storage: Send + Sync {
    fn record_count(&self) -> usize;
    fn add_record(&mut self, fields: Vec<(String, String)>, fingerprint: Option<String>, team: Option<String>) -> Result<(), StorageError>;
    fn query(&self, selections: &[(Option<String>, String)], default_type: Option<RecordType>) -> Result<Vec<Record>, StorageError>;
    fn upsert_record(&mut self, fields: Vec<(String, String)>, fingerprint: Option<String>, team: Option<String>) -> Result<UpsertOutcome, StorageError>;
    fn delete_record(&mut self, selections: &[(Option<String>, String)], fingerprint: Option<String>, teams: &[String], roles: &[String]) -> Result<usize, StorageError>;
    /// Purpose (The "Why"): Modifies matching and authorized records' fields in-place.
    /// This matches selections, authorizes modifications using fingerprint/team checks,
    /// and applies field modifications.
    fn change_record(&mut self, selections: &[(Option<String>, String)], modifications: &[(String, String)], fingerprint: Option<String>, teams: &[String]) -> Result<usize, StorageError>;
}

pub struct MemoryStorage {
    records: Vec<Record>,
    next_id: usize,
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            next_id: 1,
        }
    }

    fn matches(&self, field_val: &str, query_val: &str) -> Result<bool, StorageError> {
        let field_val_lower = field_val.to_lowercase();
        let query_val_lower = query_val.to_lowercase();

        // Simple word-based matching for MVP
        // RFC 2378 says "normally done on a word-by-word basis"
        let query_words: Vec<&str> = query_val_lower.split_whitespace().collect();
        let field_words: Vec<&str> = field_val_lower.split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == ':').collect();

        for qw in query_words {
            let mut matched = false;
            for fw in &field_words {
                if qw.contains('*') || qw.contains('?') || qw.contains('+') || qw.contains('[') || qw.contains(']') {
                    if self.wildcard_match(fw, qw)? {
                        matched = true;
                        break;
                    }
                } else {
                    if fw == &qw {
                        matched = true;
                        break;
                    }
                }
            }
            if !matched {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn wildcard_match(&self, word: &str, pattern: &str) -> Result<bool, StorageError> {
        #[derive(Debug, Clone, PartialEq, Eq)]
        enum PatternToken {
            Literal(char),
            Star,
            Plus,
            Question,
            Set(std::collections::HashSet<char>),
        }

        let mut tokens = Vec::new();
        let mut chars = pattern.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                '*' => tokens.push(PatternToken::Star),
                '+' => tokens.push(PatternToken::Plus),
                '?' => tokens.push(PatternToken::Question),
                '[' => {
                    let mut set_chars = std::collections::HashSet::new();
                    let mut closed = false;
                    while let Some(&next_c) = chars.peek() {
                        if next_c == ']' {
                            chars.next();
                            closed = true;
                            break;
                        } else {
                            set_chars.insert(chars.next().unwrap());
                        }
                    }
                    if !closed {
                        return Err(StorageError::InvalidArgument(format!("Unclosed bracket in pattern '{}'", pattern)));
                    }
                    if set_chars.is_empty() {
                        return Err(StorageError::InvalidArgument(format!("Empty bracket set in pattern '{}'", pattern)));
                    }
                    tokens.push(PatternToken::Set(set_chars));
                }
                ']' => {
                    return Err(StorageError::InvalidArgument(format!("Stray ']' with no preceding '[' in pattern '{}'", pattern)));
                }
                other => {
                    tokens.push(PatternToken::Literal(other));
                }
            }
        }

        let w: Vec<char> = word.chars().collect();
        let n = w.len();
        let m = tokens.len();

        let mut dp = vec![vec![false; m + 1]; n + 1];
        dp[0][0] = true;

        for j in 1..=m {
            if let PatternToken::Star = tokens[j - 1] {
                dp[0][j] = dp[0][j - 1];
            } else {
                dp[0][j] = false;
            }
        }

        for i in 1..=n {
            for j in 1..=m {
                match &tokens[j - 1] {
                    PatternToken::Literal(c) => {
                        dp[i][j] = dp[i - 1][j - 1] && w[i - 1] == *c;
                    }
                    PatternToken::Question => {
                        dp[i][j] = dp[i - 1][j - 1];
                    }
                    PatternToken::Set(s) => {
                        dp[i][j] = dp[i - 1][j - 1] && s.contains(&w[i - 1]);
                    }
                    PatternToken::Star => {
                        dp[i][j] = dp[i][j - 1] || dp[i - 1][j];
                    }
                    PatternToken::Plus => {
                        dp[i][j] = dp[i - 1][j - 1] || dp[i - 1][j];
                    }
                }
            }
        }

        Ok(dp[n][m])
    }

    /// Compares an `ip_addr`/`mac_addr` field value against a query value by parsing both into
    /// their typed form and comparing by equality, sidestepping `matches()`'s word-splitting
    /// entirely - splitting on `:` (a legitimate delimiter for other free-text fields) fragments a
    /// MAC/IPv6 address into pieces that can never equal the unsplit query value, so an
    /// exact-value match against these two fields could never succeed under the generic
    /// word-based matcher. Typed comparison also correctly treats formatting differences (colon
    /// vs hyphen MAC separators, mixed case hex, IPv6 zero-compression) as equal, which
    /// `matches()` never attempted.
    ///
    /// Falls back to `matches()` (preserving existing wildcard-search support, e.g.
    /// `mac_addr="bc:*"`) whenever the query value doesn't parse as that field's typed form - a
    /// wildcard pattern never does, by construction.
    fn address_matches(&self, field_name: &str, field_val: &str, query_val: &str) -> Result<bool, StorageError> {
        if field_name == "ip_addr" {
            if let Ok(query_ip) = query_val.parse::<std::net::IpAddr>() {
                return Ok(field_val.parse::<std::net::IpAddr>() == Ok(query_ip));
            }
        } else if field_name == "mac_addr" {
            if let Some(query_mac) = parse_mac_bytes(query_val) {
                return Ok(parse_mac_bytes(field_val) == Some(query_mac));
            }
        }

        // Neither side parsed as its typed address (e.g. a wildcard pattern, or genuinely
        // malformed input). A wildcard pattern that itself contains ":" - the same delimiter
        // matches() splits the field value on - would otherwise be compared fragment-by-fragment
        // against the split field value and could never match as a coherent whole (e.g.
        // "bc:24:*" against split fragments "bc","24",... - no single fragment equals the whole
        // pattern). When the query contains wildcard syntax, match the whole (unsplit) field
        // value against the whole (unsplit) pattern directly instead, treating the address as one
        // indivisible token rather than word-splitting it - this is exactly how a dotted IPv4
        // wildcard like "192.168.*" already works today (dots were never a split delimiter, so an
        // IPv4 value was always compared as one whole fragment). Plain, non-wildcard query values
        // (e.g. "bc") keep using the existing fragment-based matches() fallback below, unchanged -
        // that's a separately-decided, already-locked-in behavior this fix must not disturb.
        if query_val.chars().any(|c| matches!(c, '*' | '?' | '+' | '[' | ']')) {
            return self.wildcard_match(&field_val.to_lowercase(), &query_val.to_lowercase());
        }

        self.matches(field_val, query_val)
    }
}

/// Parses a MAC address string (colon- or hyphen-separated, e.g. "bc:24:11:00:02:04" or
/// "BC-24-11-00-02-04") into its 6 raw bytes, or `None` if it isn't a valid MAC address.
/// Case-insensitive and separator-insensitive by construction, since it operates on the parsed
/// byte values rather than the original text - two different textual forms of the same address
/// parse to identical bytes.
fn parse_mac_bytes(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(|c| c == ':' || c == '-').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || part.len() > 2 {
            return None;
        }
        bytes[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(bytes)
}

fn is_valid_mac_address(s: &str) -> bool {
    parse_mac_bytes(s).is_some()
}

fn validate_ip_mac_field(key: &str, value: &str) -> Result<(), StorageError> {
    if key == "ip" || key == "ip_addr" {
        if value.parse::<std::net::IpAddr>().is_err() {
            return Err(StorageError::InvalidArgument(format!(
                "invalid IP address '{}' for field '{}'",
                value, key
            )));
        }
    } else if key == "mac" || key == "mac_addr" {
        if !is_valid_mac_address(value) {
            return Err(StorageError::InvalidArgument(format!(
                "invalid MAC address '{}' for field '{}'",
                value, key
            )));
        }
    }
    Ok(())
}

impl MemoryStorage {
    fn record_matches_selections(&self, record: &Record, selections: &[(Option<String>, String)]) -> Result<bool, StorageError> {
        for (field_opt, value) in selections {
            match field_opt {
                Some(field_name) => {
                    if field_name == "ip_addr" || field_name == "mac_addr" {
                        if let Some(list) = record.multi_fields.get(field_name) {
                            let mut match_found = false;
                            for item in list {
                                if self.address_matches(field_name, item, value)? {
                                    match_found = true;
                                    break;
                                }
                            }
                            if !match_found {
                                return Ok(false);
                            }
                        } else {
                            return Ok(false);
                        }
                    } else if let Some(field_val) = record.fields.get(field_name) {
                        if !self.matches(field_val, value)? {
                            return Ok(false);
                        }
                    } else {
                        return Ok(false);
                    }
                }
                None => {
                    let mut any_match = false;
                    for field_val in record.fields.values() {
                        if self.matches(field_val, value)? {
                            any_match = true;
                            break;
                        }
                    }
                    if !any_match {
                        for list in record.multi_fields.values() {
                            for item in list {
                                if self.matches(item, value)? {
                                    any_match = true;
                                    break;
                                }
                            }
                            if any_match {
                                break;
                            }
                        }
                    }
                    if !any_match {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }
}

impl Storage for MemoryStorage {
    #[instrument(skip(self))]
    fn record_count(&self) -> usize {
        self.records.len()
    }

    #[instrument(skip(self))]
    fn add_record(&mut self, fields: Vec<(String, String)>, fingerprint: Option<String>, team: Option<String>) -> Result<(), StorageError> {
        let type_val = fields.iter().find(|(k, _)| k == "type").map(|(_, v)| v.trim()).unwrap_or("");
        if type_val.is_empty() {
            return Err(StorageError::InvalidArgument(
                "a 'type' field is required (e.g. type=machine)".to_string(),
            ));
        }

        for (k, v) in &fields {
            validate_ip_mac_field(k, v)?;
        }

        let mut record_fields = HashMap::new();
        let mut multi_fields: HashMap<String, Vec<String>> = HashMap::new();

        for (k, v) in fields {
            if k == "ip_addr" || k == "mac_addr" {
                let vec = multi_fields.entry(k).or_default();
                if !vec.contains(&v) {
                    vec.push(v);
                }
            } else {
                record_fields.insert(k, v);
            }
        }

        let now = Utc::now().to_rfc3339();
        record_fields.entry("created_at".to_string()).or_insert_with(|| now.clone());
        record_fields.insert("last_seen_at".to_string(), now);
        
        let record_type = record_fields.get("type").map(|s| RecordType::from(s.as_str()));
        let record = Record {
            id: self.next_id,
            record_type,
            fields: record_fields,
            multi_fields,
            owner_fingerprint: fingerprint,
            owner_team: team,
        };
        self.records.push(record);
        self.next_id += 1;
        Ok(())
    }

    #[instrument(skip(self))]
    fn query(&self, selections: &[(Option<String>, String)], default_type: Option<RecordType>) -> Result<Vec<Record>, StorageError> {
        let mut results = Vec::new();
        for record in &self.records {
            // Check discriminator
            if let Some(ref dt) = default_type {
                if let Some(ref rt) = record.record_type {
                    if rt != dt && !selections.iter().any(|(f, _)| f.as_deref() == Some("type")) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            if self.record_matches_selections(record, selections)? {
                results.push(record.clone());
            }
        }
        Ok(results)
    }

    #[instrument(skip(self))]
    fn upsert_record(&mut self, fields: Vec<(String, String)>, fingerprint: Option<String>, team: Option<String>) -> Result<UpsertOutcome, StorageError> {
        for (k, v) in &fields {
            validate_ip_mac_field(k, v)?;
        }

        let now = Utc::now().to_rfc3339();
        let identifier = fields.iter().find(|(k, _)| k == "hostname" || k == "alias").map(|(_, v)| v.clone());

        if let Some(id_val) = identifier {
            let existing = self.records.iter_mut().find(|r| {
                r.fields.get("hostname") == Some(&id_val) || r.fields.get("alias") == Some(&id_val)
            });

            if let Some(record) = existing {
                if record.owner_fingerprint.as_ref().is_some_and(|bonded| Some(bonded) != fingerprint.as_ref()) {
                    return Err(StorageError::Collision);
                }

                // Check Member Authorization logic (Team match)
                if let Some(ref record_team) = record.owner_team {
                    if let Some(ref user_team) = team {
                         // User must be in the team that owns the record
                         if record_team != user_team {
                             return Err(StorageError::Unauthorized);
                         }
                    } else if record.owner_fingerprint.is_none() {
                         return Err(StorageError::Unauthorized);
                    }
                }

                if let Some((_, incoming_type)) = fields.iter().find(|(k, _)| k == "type") {
                    if let Some(existing_type) = record.fields.get("type") {
                        if incoming_type != existing_type {
                            return Err(StorageError::InvalidArgument(
                                "type is immutable after creation and cannot be changed".to_string(),
                            ));
                        }
                    }
                }

                if record.owner_fingerprint.is_none() {
                    record.owner_fingerprint = fingerprint;
                }
                if record.owner_team.is_none() {
                    record.owner_team = team;
                }

                for (k, v) in fields {
                    if k == "ip_addr" || k == "mac_addr" {
                        let vec = record.multi_fields.entry(k).or_default();
                        if !vec.contains(&v) {
                            vec.push(v);
                        }
                    } else if k == "source" && record.fields.contains_key("source") {
                        // source describes a record's provenance (how it was created), not who last
                        // touched it - once set, it must never be overwritten by a later write.
                    } else {
                        record.fields.insert(k, v);
                    }
                }
                record.fields.insert("last_seen_at".to_string(), now);
                return Ok(UpsertOutcome::Updated);
            }
        }

        self.add_record(fields, fingerprint, team).map(|_| UpsertOutcome::Created)
    }

    /// Purpose (The "Why"): Deletes matching, authorized records. A caller with the `admin` role
    /// (already treated as a root-equivalent credential elsewhere in this codebase - see
    /// `auth.rs`'s `auto_generate_admin_key`) can force-delete a record it doesn't otherwise own,
    /// as a last-resort recovery path for when a record's owning key has been lost or rotated and
    /// no other authorized key can reach it (Issue #210). This is deliberately delete-only, not a
    /// general ownership-reassignment mechanism - the caller is expected to re-add the record
    /// afterward with correct new ownership if it's still needed.
    #[instrument(skip(self))]
    fn delete_record(&mut self, selections: &[(Option<String>, String)], fingerprint: Option<String>, teams: &[String], roles: &[String]) -> Result<usize, StorageError> {
        let mut to_delete_ids = Vec::new();
        let is_admin = roles.contains(&"admin".to_string());

        for record in &self.records {
            if self.record_matches_selections(record, selections)? {
                // Check authorization for deletion
                let owner_matched = match (&record.owner_fingerprint, &record.owner_team) {
                    (Some(fp), _) if fingerprint.as_ref() == Some(fp) => true,
                    (_, Some(team)) if teams.contains(team) => true,
                    (None, None) => true, // System records?
                    _ => false,
                };

                if owner_matched {
                    to_delete_ids.push(record.id);
                } else if is_admin {
                    warn!(
                        record_id = record.id,
                        fingerprint = ?fingerprint,
                        "Admin-role override: force-deleting record not owned by the requesting key (Issue #210 recovery path)"
                    );
                    to_delete_ids.push(record.id);
                } else {
                    return Err(StorageError::Unauthorized);
                }
            }
        }

        let deleted_count = to_delete_ids.len();
        self.records.retain(|r| !to_delete_ids.contains(&r.id));

        Ok(deleted_count)
    }

    /// Purpose (The "Why"): Performs selection matching and authorized in-place modification
    /// of records. It iterates over existing records, validates ownership fingerprint or team
    /// matches, and inserts or updates fields as specified by modifications.
    #[instrument(skip(self))]
    fn change_record(&mut self, selections: &[(Option<String>, String)], modifications: &[(String, String)], fingerprint: Option<String>, teams: &[String]) -> Result<usize, StorageError> {
        if modifications.iter().any(|(k, _)| k.eq_ignore_ascii_case("type")) {
            return Err(StorageError::InvalidArgument(
                "type cannot be modified via change - it is set once at record creation".to_string(),
            ));
        }

        for (k, v) in modifications {
            validate_ip_mac_field(k, v)?;
        }

        let mut to_change_ids = Vec::new();

        for record in &self.records {
            if self.record_matches_selections(record, selections)? {
                // Check authorization for modification - identical policy to delete_record
                let authorized = match (&record.owner_fingerprint, &record.owner_team) {
                    (Some(fp), _) if fingerprint.as_ref() == Some(fp) => true,
                    (_, Some(team)) if teams.contains(team) => true,
                    (None, None) => true, // System records?
                    _ => false,
                };

                if authorized {
                    to_change_ids.push(record.id);
                } else {
                    return Err(StorageError::Unauthorized);
                }
            }
        }

        let changed_count = to_change_ids.len();
        for record in self.records.iter_mut() {
            if to_change_ids.contains(&record.id) {
                for (field, value) in modifications {
                    if field == "ip_addr" || field == "mac_addr" {
                        let vec = record.multi_fields.entry(field.clone()).or_default();
                        if !vec.contains(value) {
                            vec.push(value.clone());
                        }
                    } else {
                        record.fields.insert(field.clone(), value.clone());
                    }
                }
            }
        }

        Ok(changed_count)
    }
}

pub struct FileStorage {
    memory: MemoryStorage,
    path: PathBuf,
    tx: mpsc::UnboundedSender<Vec<Record>>,
}

impl FileStorage {
    #[instrument]
    pub fn new(path: PathBuf) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<Record>>();
        let worker_path = path.clone();

        // Spawn background persistence worker
        tokio::spawn(async move {
            info!("Persistence worker started for {:?}", worker_path);
            while let Some(records) = rx.recv().await {
                if let Err(e) = Self::persist_to_disk_atomic(&worker_path, &records) {
                    error!("Failed to persist records to disk: {}", e);
                }
            }
            info!("Persistence worker shutting down for {:?}", worker_path);
        });

        let mut storage = Self {
            memory: MemoryStorage::new(),
            path,
            tx,
        };
        storage.load_from_disk();
        storage
    }

    #[instrument(skip(self))]
    fn load_from_disk(&mut self) {
        if !self.path.exists() {
            info!("No existing data file found at {:?}", self.path);
            return;
        }

        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to open storage file: {}", e);
                return;
            }
        };

        let mut data = String::new();
        if let Err(e) = file.read_to_string(&mut data) {
            error!("Failed to read storage file: {}", e);
            return;
        }

        if data.is_empty() {
            return;
        }

        match serde_json::from_str::<Vec<Record>>(&data) {
            Ok(mut records) => {
                let max_id = records.iter().map(|r| r.id).max().unwrap_or(0);
                let mut corrected_count = 0;
                let mut migrated_multi_value_count = 0;

                for record in records.iter_mut() {
                    if let Some(type_str) = record.fields.get("type") {
                        let parsed_type = RecordType::from(type_str.as_str());
                        if record.record_type.as_ref() != Some(&parsed_type) {
                            record.record_type = Some(parsed_type);
                            corrected_count += 1;
                        }
                    } else {
                        tracing::warn!(
                            "record ID {} has no type field, cannot self-heal, remains invisible to mdb/ph queries — needs manual correction",
                            record.id
                        );
                    }

                    // Migrate legacy plain-string ip_addr/mac_addr fields (from before these
                    // became multi-valued) into multi_fields. A record with the same key present
                    // in both maps would otherwise silently shadow the correct multi_fields data
                    // forever in query responses (fields is checked first) - confirmed live in
                    // production on a record created before this feature existed.
                    for key in ["ip_addr", "mac_addr"] {
                        if let Some(legacy_val) = record.fields.remove(key) {
                            let vec = record.multi_fields.entry(key.to_string()).or_default();
                            if !vec.contains(&legacy_val) {
                                vec.push(legacy_val);
                            }
                            migrated_multi_value_count += 1;
                        }
                    }
                }

                if corrected_count > 0 {
                    tracing::warn!(
                        "Self-healed {} records with missing or stale record_type",
                        corrected_count
                    );
                }
                if migrated_multi_value_count > 0 {
                    tracing::warn!(
                        "Migrated {} legacy plain-string ip_addr/mac_addr fields into multi_fields",
                        migrated_multi_value_count
                    );
                }

                self.memory.records = records;
                self.memory.next_id = max_id + 1;
                if corrected_count > 0 || migrated_multi_value_count > 0 {
                    self.queue_persistence();
                }
                info!("Loaded {} records from {:?}", self.memory.records.len(), self.path);
            }
            Err(e) => {
                error!("Failed to parse storage file: {}", e);
            }
        }
    }

    /// Atomically replaces the storage file using a temporary file and rename.
    fn persist_to_disk_atomic(path: &Path, records: &[Record]) -> anyhow::Result<()> {
        debug!("Starting atomic persistence to {:?}", path);
        let data = serde_json::to_string_pretty(records)?;
        
        let tmp_path = path.with_extension("tmp");
        {
            let mut file = File::create(&tmp_path)?;
            file.write_all(data.as_bytes())?;
            file.sync_all()?;
        }

        std::fs::rename(tmp_path, path)?;
        debug!("Atomic persistence completed successfully for {:?}", path);
        Ok(())
    }

    fn queue_persistence(&self) {
        if let Err(e) = self.tx.send(self.memory.records.clone()) {
            error!("Failed to queue persistence: {}", e);
        }
    }
}

impl Storage for FileStorage {
    fn record_count(&self) -> usize {
        self.memory.record_count()
    }

    fn add_record(&mut self, fields: Vec<(String, String)>, fingerprint: Option<String>, team: Option<String>) -> Result<(), StorageError> {
        self.memory.add_record(fields, fingerprint, team)?;
        self.queue_persistence();
        Ok(())
    }

    fn query(&self, selections: &[(Option<String>, String)], default_type: Option<RecordType>) -> Result<Vec<Record>, StorageError> {
        self.memory.query(selections, default_type)
    }

    fn upsert_record(&mut self, fields: Vec<(String, String)>, fingerprint: Option<String>, team: Option<String>) -> Result<UpsertOutcome, StorageError> {
        let outcome = self.memory.upsert_record(fields, fingerprint, team)?;
        self.queue_persistence();
        Ok(outcome)
    }

    fn delete_record(&mut self, selections: &[(Option<String>, String)], fingerprint: Option<String>, teams: &[String], roles: &[String]) -> Result<usize, StorageError> {
        let count = self.memory.delete_record(selections, fingerprint, teams, roles)?;
        if count > 0 {
            self.queue_persistence();
        }
        Ok(count)
    }

    /// Purpose (The "Why"): Delegates modification to MemoryStorage and triggers storage
    /// persistence when modifications are actually applied.
    fn change_record(&mut self, selections: &[(Option<String>, String)], modifications: &[(String, String)], fingerprint: Option<String>, teams: &[String]) -> Result<usize, StorageError> {
        let count = self.memory.change_record(selections, modifications, fingerprint, teams)?;
        if count > 0 {
            self.queue_persistence();
        }
        Ok(count)
    }
}

pub struct LdapStorage {
    // Config
    url: String,
    bind_dn: String,
    bind_pw: String,
    base_dn: String,
    
    // Schema mapping
    // Ph Field -> LDAP Attribute
    field_map: HashMap<String, String>,
}

impl LdapStorage {
    pub fn new(url: String, bind_dn: String, bind_pw: String, base_dn: String) -> Self {
        let mut field_map = HashMap::new();
        // Default mappings
        field_map.insert("name".to_string(), "cn".to_string());
        field_map.insert("email".to_string(), "mail".to_string());
        field_map.insert("phone".to_string(), "telephoneNumber".to_string());
        field_map.insert("hostname".to_string(), "cn".to_string());
        field_map.insert("ip".to_string(), "ipHostNumber".to_string());

        Self {
            url,
            bind_dn,
            bind_pw,
            base_dn,
            field_map,
        }
    }

    fn build_filter(&self, selections: &[(Option<String>, String)], default_type: Option<RecordType>) -> String {
        let mut filters = Vec::new();

        if let Some(ref dt) = default_type {
            match dt {
                RecordType::Person => filters.push("(objectClass=inetOrgPerson)".to_string()),
                RecordType::Machine => filters.push("(objectClass=ipHost)".to_string()),
                RecordType::Other(s) => filters.push(format!("(objectClass={})", s)),
            }
        }

        for (field_opt, val) in selections {
            if let Some(field_name) = field_opt {
                let ldap_attr = self.field_map.get(field_name).cloned().unwrap_or_else(|| field_name.clone());
                filters.push(format!("({}={})", ldap_attr, val));
            } else {
                filters.push(format!("(|(cn={})(mail={}))", val, val));
            }
        }

        if filters.len() > 1 {
            format!("(&{})", filters.join(""))
        } else if !filters.is_empty() {
            filters[0].clone()
        } else {
            "(objectClass=*)".to_string()
        }
    }
}

impl Storage for LdapStorage {
    #[instrument(skip(self))]
    fn record_count(&self) -> usize {
        0
    }

    #[instrument(skip(self))]
    fn add_record(&mut self, _fields: Vec<(String, String)>, _fingerprint: Option<String>, _team: Option<String>) -> Result<(), StorageError> {
        error!("LDAP storage is currently read-only (Write operations pending Task 4.3)");
        Err(StorageError::ReadOnly)
    }

    #[instrument(skip(self))]
    fn query(&self, selections: &[(Option<String>, String)], default_type: Option<RecordType>) -> Result<Vec<Record>, StorageError> {
        info!("Executing LDAP query...");
        
        let filter = self.build_filter(selections, default_type);
        info!("LDAP Filter: {}", filter);

        let mut ldap = match ldap3::LdapConn::new(&self.url) {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to connect to LDAP server: {}", e);
                return Ok(Vec::new());
            }
        };

        if let Err(e) = ldap.simple_bind(&self.bind_dn, &self.bind_pw) {
            error!("Failed to bind to LDAP: {}", e);
            return Ok(Vec::new());
        }

        let rs = match ldap.search(
            &self.base_dn,
            ldap3::Scope::Subtree,
            &filter,
            vec!["*"]
        ) {
            Ok(res) => match res.success() {
                Ok((entries, _)) => entries,
                Err(e) => {
                    error!("LDAP search successful but returned error result: {}", e);
                    return Ok(Vec::new());
                }
            },
            Err(e) => {
                error!("LDAP search failed: {}", e);
                return Ok(Vec::new());
            }
        };

        let mut records = Vec::new();
        for (i, entry) in rs.into_iter().enumerate() {
            let search_entry = ldap3::SearchEntry::construct(entry);
            let mut fields = HashMap::new();
            
            for (attr, vals) in search_entry.attrs {
                if !vals.is_empty() {
                    let ph_field = self.field_map.iter()
                        .find(|(_, ldap_attr)| **ldap_attr == attr)
                        .map(|(k, _)| k.clone())
                        .unwrap_or(attr);
                    
                    fields.insert(ph_field, vals.join(", "));
                }
            }

            let record_type = if fields.get("objectClass").map(|s| s.contains("inetOrgPerson")).unwrap_or(false) {
                Some(RecordType::Person)
            } else if fields.get("objectClass").map(|s| s.contains("ipHost")).unwrap_or(false) {
                Some(RecordType::Machine)
            } else {
                None
            };

            records.push(Record {
                id: i + 1,
                record_type,
                fields,
                multi_fields: HashMap::new(),
                owner_fingerprint: None,
                owner_team: None,
            });
        }

        Ok(records)
    }

    #[instrument(skip(self))]
    fn upsert_record(&mut self, _fields: Vec<(String, String)>, _fingerprint: Option<String>, _team: Option<String>) -> Result<UpsertOutcome, StorageError> {
        error!("LDAP storage is currently read-only (Write operations pending Task 4.3)");
        Err(StorageError::ReadOnly)
    }

    #[instrument(skip(self))]
    fn delete_record(&mut self, _selections: &[(Option<String>, String)], _fingerprint: Option<String>, _teams: &[String], _roles: &[String]) -> Result<usize, StorageError> {
        error!("LDAP storage is currently read-only");
        Err(StorageError::ReadOnly)
    }

    /// Purpose: Enforces read-only behavior for LDAP storage when changes are attempted.
    #[instrument(skip(self))]
    fn change_record(&mut self, _selections: &[(Option<String>, String)], _modifications: &[(String, String)], _fingerprint: Option<String>, _teams: &[String]) -> Result<usize, StorageError> {
        error!("LDAP storage is currently read-only (Write operations pending Task 4.3)");
        Err(StorageError::ReadOnly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_inject_created_at_and_last_seen_at_on_add() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "person".to_string()),
            ("name".to_string(), "John Doe".to_string()),
        ];
        storage.add_record(fields, None, None).unwrap();

        let results = storage.query(&[(Some("name".to_string()), "john".to_string())], None).unwrap();
        assert!(results[0].fields.contains_key("created_at"));
        assert!(results[0].fields.contains_key("last_seen_at"));
    }

    #[test]
    fn test_should_update_last_seen_at_but_preserve_created_at_on_upsert() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "srv-01".to_string()),
        ];
        storage.upsert_record(fields.clone(), None, None).unwrap();

        let initial_results = storage.query(&[(Some("hostname".to_string()), "srv-01".to_string())], None).unwrap();
        let created_at = initial_results[0].fields.get("created_at").unwrap().clone();

        let mut update_fields = fields.clone();
        update_fields.push(("status".to_string(), "online".to_string()));
        storage.upsert_record(update_fields, None, None).unwrap();

        let updated_results = storage.query(&[(Some("hostname".to_string()), "srv-01".to_string())], None).unwrap();
        assert_eq!(updated_results[0].fields.get("created_at").unwrap(), &created_at);
        assert!(updated_results[0].fields.contains_key("last_seen_at"));
    }

    #[test]
    fn test_should_return_matching_record_when_query_matches_name() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "person".to_string()),
            ("name".to_string(), "John Doe".to_string()),
            ("email".to_string(), "john@example.com".to_string()),
        ];
        storage.add_record(fields, None, None).unwrap();

        let selections = vec![(Some("name".to_string()), "john".to_string())];
        let results = storage.query(&selections, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].fields.get("email").unwrap(), "john@example.com");
    }

    #[test]
    fn test_should_return_empty_when_query_does_not_match() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "person".to_string()),
            ("name".to_string(), "John Doe".to_string()),
        ];
        storage.add_record(fields, None, None).unwrap();

        let selections = vec![(Some("name".to_string()), "jane".to_string())];
        let results = storage.query(&selections, None).unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_should_support_wildcard_matching() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "person".to_string()),
            ("name".to_string(), "John Doe".to_string()),
        ];
        storage.add_record(fields, None, None).unwrap();

        let selections = vec![(Some("name".to_string()), "jo*".to_string())];
        let results = storage.query(&selections, None).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_hand_checkable_cases() {
        let storage = MemoryStorage::new();
        assert!(storage.wildcard_match("ab", "+").unwrap());
        assert!(!storage.wildcard_match("", "+").unwrap());
        assert!(storage.wildcard_match("abc", "a?c").unwrap());
        assert!(!storage.wildcard_match("ac", "a?c").unwrap());
    }

    #[test]
    fn test_wildcard_advanced_patterns() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "person".to_string()),
            ("name".to_string(), "John Doe".to_string()),
        ];
        storage.add_record(fields, None, None).unwrap();

        let results = storage.query(&[(Some("name".to_string()), "*doe".to_string())], None).unwrap();
        assert_eq!(results.len(), 1);
        let results = storage.query(&[(Some("name".to_string()), "j*n".to_string())], None).unwrap();
        assert_eq!(results.len(), 1);

        let results = storage.query(&[(Some("name".to_string()), "jo+n".to_string())], None).unwrap();
        assert_eq!(results.len(), 1);
        let results = storage.query(&[(Some("name".to_string()), "jn+".to_string())], None).unwrap();
        assert_eq!(results.len(), 0);

        let results = storage.query(&[(Some("name".to_string()), "j?hn".to_string())], None).unwrap();
        assert_eq!(results.len(), 1);
        let results = storage.query(&[(Some("name".to_string()), "j??hn".to_string())], None).unwrap();
        assert_eq!(results.len(), 0);

        let results = storage.query(&[(Some("name".to_string()), "[jrg]ohn".to_string())], None).unwrap();
        assert_eq!(results.len(), 1);

        let results = storage.query(&[(Some("name".to_string()), "j?hn*".to_string())], None).unwrap();
        assert_eq!(results.len(), 1);
        let results = storage.query(&[(Some("name".to_string()), "[jrg]oh?".to_string())], None).unwrap();
        assert_eq!(results.len(), 1);

        let results = storage.query(&[(Some("name".to_string()), "[ab".to_string())], None);
        assert!(matches!(results, Err(StorageError::InvalidArgument(_))));
        let results = storage.query(&[(Some("name".to_string()), "[]".to_string())], None);
        assert!(matches!(results, Err(StorageError::InvalidArgument(_))));

        let results = storage.query(&[(Some("name".to_string()), "abc]".to_string())], None);
        assert!(matches!(results, Err(StorageError::InvalidArgument(_))));
    }

    #[test]
    fn test_should_match_any_field_when_no_field_name_provided() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "person".to_string()),
            ("name".to_string(), "John Doe".to_string()),
            ("alias".to_string(), "jdoe".to_string()),
        ];
        storage.add_record(fields, None, None).unwrap();

        let selections = vec![(None, "jdoe".to_string())];
        let results = storage.query(&selections, None).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_should_match_multiple_criteria_with_implicit_and() {
        let mut storage = MemoryStorage::new();
        let fields1 = vec![
            ("type".to_string(), "person".to_string()),
            ("name".to_string(), "John Doe".to_string()),
            ("city".to_string(), "New York".to_string()),
        ];
        storage.add_record(fields1, None, None).unwrap();
        let fields2 = vec![
            ("type".to_string(), "person".to_string()),
            ("name".to_string(), "Jane Doe".to_string()),
            ("city".to_string(), "London".to_string()),
        ];
        storage.add_record(fields2, None, None).unwrap();

        let selections = vec![
            (Some("name".to_string()), "doe".to_string()),
            (Some("city".to_string()), "london".to_string()),
        ];
        let results = storage.query(&selections, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].fields.get("name").unwrap(), "Jane Doe");
    }

    #[test]
    fn test_should_filter_by_type_discriminator() {
        let mut storage = MemoryStorage::new();
        
        let fields1 = vec![
            ("name".to_string(), "John Person".to_string()),
            ("type".to_string(), "person".to_string()),
        ];
        storage.add_record(fields1, None, None).unwrap();

        let fields2 = vec![
            ("name".to_string(), "Server Machine".to_string()),
            ("type".to_string(), "machine".to_string()),
        ];
        storage.add_record(fields2, None, None).unwrap();

        let selections = vec![(Some("name".to_string()), "server".to_string())];
        
        let results = storage.query(&selections, Some(RecordType::Person)).unwrap();
        assert_eq!(results.len(), 0);

        let results = storage.query(&selections, Some(RecordType::Machine)).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].fields.get("name").unwrap(), "Server Machine");

        let results = storage.query(&selections, None).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_should_bond_record_to_fingerprint_when_upserted_first_time() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "server-01".to_string()),
        ];
        
        let fingerprint = Some("SHA256:abcd".to_string());
        storage.upsert_record(fields, fingerprint.clone(), None).unwrap();
        
        let results = storage.query(&[(Some("hostname".to_string()), "server-01".to_string())], None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].owner_fingerprint, fingerprint);
    }

    #[test]
    fn test_should_fail_upsert_when_fingerprint_mismatch() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "server-01".to_string()),
        ];
        
        storage.upsert_record(fields.clone(), Some("SHA256:abcd".to_string()), None).unwrap();
        
        let result = storage.upsert_record(fields, Some("SHA256:wrong".to_string()), None);
        assert!(matches!(result, Err(StorageError::Collision)));
    }

    #[test]
    fn test_should_allow_upsert_when_fingerprint_matches() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "server-01".to_string()),
            ("status".to_string(), "online".to_string()),
        ];
        
        let fingerprint = Some("SHA256:abcd".to_string());
        storage.upsert_record(fields.clone(), fingerprint.clone(), None).unwrap();
        
        let mut update_fields = fields.clone();
        update_fields.push(("status".to_string(), "busy".to_string()));
        storage.upsert_record(update_fields, fingerprint.clone(), None).unwrap();
        
        let results = storage.query(&[(Some("hostname".to_string()), "server-01".to_string())], None).unwrap();
        assert_eq!(results[0].fields.get("status").unwrap(), "busy");
    }

    #[tokio::test]
    async fn test_should_persist_and_reload_records_when_using_file_storage() {
        let temp_dir = std::env::temp_dir();
        let storage_path = temp_dir.join("pharos_test_rbac.json");
        
        if storage_path.exists() {
            let _ = std::fs::remove_file(&storage_path);
        }

        {
            let mut storage = FileStorage::new(storage_path.clone());
            let fields = vec![
                ("type".to_string(), "person".to_string()),
                ("name".to_string(), "Persistent Pete".to_string()),
            ];
            storage.add_record(fields, None, None).unwrap();
            assert_eq!(storage.record_count(), 1);
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        {
            let storage = FileStorage::new(storage_path.clone());
            assert_eq!(storage.record_count(), 1);
            let results = storage.query(&[(Some("name".to_string()), "pete".to_string())], None).unwrap();
            assert_eq!(results.len(), 1);
        }

        let _ = std::fs::remove_file(&storage_path);
    }

    #[test]
    fn test_should_change_matching_record_when_authorized() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "vm1".to_string()),
            ("status".to_string(), "up".to_string()),
        ];
        storage.add_record(fields, Some("fp1".to_string()), None).unwrap();

        let selections = vec![(Some("hostname".to_string()), "vm1".to_string())];
        let modifications = vec![("status".to_string(), "down".to_string())];
        let result = storage.change_record(&selections, &modifications, Some("fp1".to_string()), &[]);

        assert_eq!(result.unwrap(), 1);
        let updated = storage.query(&selections, None).unwrap();
        assert_eq!(updated[0].fields.get("status").unwrap(), "down");
    }

    #[test]
    fn test_should_reject_change_when_unauthorized() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "vm1".to_string()),
        ];
        storage.add_record(fields, Some("fp1".to_string()), None).unwrap();

        let selections = vec![(Some("hostname".to_string()), "vm1".to_string())];
        let modifications = vec![("status".to_string(), "down".to_string())];
        let result = storage.change_record(&selections, &modifications, Some("someone-else".to_string()), &[]);

        assert!(matches!(result, Err(StorageError::Unauthorized)));
    }

    #[test]
    fn test_should_return_zero_when_no_matches_to_change() {
        let mut storage = MemoryStorage::new();
        let selections = vec![(Some("hostname".to_string()), "does-not-exist".to_string())];
        let modifications = vec![("status".to_string(), "down".to_string())];
        let result = storage.change_record(&selections, &modifications, None, &[]);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_should_change_multiple_matching_records() {
        let mut storage = MemoryStorage::new();
        for i in 0..3 {
            let fields = vec![
                ("type".to_string(), "machine".to_string()),
                ("hostname".to_string(), format!("vm{}", i)),
            ];
            storage.add_record(fields, None, None).unwrap();
        }
        let selections = vec![(Some("type".to_string()), "machine".to_string())];
        let modifications = vec![("status".to_string(), "maintenance".to_string())];
        let result = storage.change_record(&selections, &modifications, None, &[]);
        assert_eq!(result.unwrap(), 3);
    }

    #[test]
    fn test_should_return_invalid_argument_when_add_record_missing_type() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("hostname".to_string(), "srv-01".to_string()),
        ];
        let res = storage.add_record(fields, None, None);
        assert!(matches!(res, Err(StorageError::InvalidArgument(_))));
    }

    #[test]
    fn test_should_reject_upsert_when_type_mismatches_existing_field() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("hostname".to_string(), "srv-01".to_string()),
            ("type".to_string(), "machine".to_string()),
        ];
        storage.upsert_record(fields.clone(), None, None).unwrap();

        let mismatch_fields = vec![
            ("hostname".to_string(), "srv-01".to_string()),
            ("type".to_string(), "person".to_string()),
        ];
        let res = storage.upsert_record(mismatch_fields, None, None);
        assert!(matches!(res, Err(StorageError::InvalidArgument(_))));
    }

    #[test]
    fn test_should_allow_upsert_when_type_matches_existing_field() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("hostname".to_string(), "srv-01".to_string()),
            ("type".to_string(), "machine".to_string()),
        ];
        storage.upsert_record(fields.clone(), None, None).unwrap();

        let res = storage.upsert_record(fields, None, None);
        assert!(res.is_ok());
    }

    #[test]
    fn test_should_reject_change_when_modifications_contain_type() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("hostname".to_string(), "srv-01".to_string()),
            ("type".to_string(), "machine".to_string()),
        ];
        storage.add_record(fields, None, None).unwrap();

        let selections = vec![(Some("hostname".to_string()), "srv-01".to_string())];
        let modifications = vec![("type".to_string(), "person".to_string())];
        let res = storage.change_record(&selections, &modifications, None, &[]);
        assert!(matches!(res, Err(StorageError::InvalidArgument(_))));
    }

    #[tokio::test]
    async fn test_should_self_heal_record_type_on_load_from_disk() {
        let temp_dir = std::env::temp_dir();
        let storage_path = temp_dir.join("pharos_test_self_heal.json");
        if storage_path.exists() {
            let _ = std::fs::remove_file(&storage_path);
        }

        let raw_json = r#"[
            {
                "id": 1,
                "record_type": null,
                "fields": {
                    "hostname": "srv-heal",
                    "type": "machine"
                },
                "owner_fingerprint": null,
                "owner_team": null
            }
        ]"#;
        std::fs::write(&storage_path, raw_json).unwrap();

        let storage = FileStorage::new(storage_path.clone());
        let records = storage.query(&[(Some("hostname".to_string()), "srv-heal".to_string())], None).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_type, Some(RecordType::Machine));

        let _ = std::fs::remove_file(&storage_path);
    }

    #[tokio::test]
    async fn test_should_migrate_legacy_plain_ip_addr_field_on_load_from_disk() {
        // Reproduces a real production record (id 2, created 2026-08-05, before ip_addr/mac_addr
        // became multi-valued): a plain string in `fields`, no `multi_fields` key at all. Query
        // responses check `fields` before `multi_fields` for a given key name, so an unmigrated
        // record like this would silently shadow any correctly-collected multi_fields data with
        // the stale single value forever - confirmed live, this is the exact bug that was found.
        let temp_dir = std::env::temp_dir();
        let storage_path = temp_dir.join("pharos_test_legacy_ip_addr_migration.json");
        if storage_path.exists() {
            let _ = std::fs::remove_file(&storage_path);
        }

        let raw_json = r#"[
            {
                "id": 2,
                "record_type": "Machine",
                "fields": {
                    "hostname": "legacy-host",
                    "type": "machine",
                    "ip_addr": "172.17.0.1",
                    "mac_addr": "de:16:42:a0:af:ee"
                },
                "owner_fingerprint": null,
                "owner_team": null
            }
        ]"#;
        std::fs::write(&storage_path, raw_json).unwrap();

        let storage = FileStorage::new(storage_path.clone());
        let records = storage.query(&[(Some("hostname".to_string()), "legacy-host".to_string())], None).unwrap();
        assert_eq!(records.len(), 1);

        // The stale plain-string entries must be gone from `fields`...
        assert_eq!(records[0].fields.get("ip_addr"), None);
        assert_eq!(records[0].fields.get("mac_addr"), None);
        // ...and present in multi_fields instead, so query responses render them correctly.
        assert_eq!(records[0].multi_fields.get("ip_addr"), Some(&vec!["172.17.0.1".to_string()]));
        assert_eq!(records[0].multi_fields.get("mac_addr"), Some(&vec!["de:16:42:a0:af:ee".to_string()]));

        let _ = std::fs::remove_file(&storage_path);
    }

    #[test]
    fn test_should_store_multi_valued_ip_and_mac_fields_on_add() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "srv-01".to_string()),
            ("ip_addr".to_string(), "192.168.86.5".to_string()),
            ("ip_addr".to_string(), "192.168.86.6".to_string()),
            ("mac_addr".to_string(), "e0:51:d8:1d:e3:22".to_string()),
        ];
        storage.add_record(fields, None, None).unwrap();
        let records = storage.query(&[(Some("hostname".to_string()), "srv-01".to_string())], None).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].multi_fields.get("ip_addr").unwrap(), &vec!["192.168.86.5".to_string(), "192.168.86.6".to_string()]);
        assert_eq!(records[0].multi_fields.get("mac_addr").unwrap(), &vec!["e0:51:d8:1d:e3:22".to_string()]);
    }

    #[test]
    fn test_should_append_new_ip_on_later_change_without_duplication() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "srv-01".to_string()),
            ("ip_addr".to_string(), "192.168.86.5".to_string()),
            ("mac_addr".to_string(), "e0:51:d8:1d:e3:22".to_string()),
        ];
        storage.add_record(fields, None, None).unwrap();

        let selections = vec![(Some("hostname".to_string()), "srv-01".to_string())];
        let modifications = vec![("ip_addr".to_string(), "192.168.86.6".to_string())];
        storage.change_record(&selections, &modifications, None, &[]).unwrap();

        // Repeat change with duplicate IP
        storage.change_record(&selections, &modifications, None, &[]).unwrap();

        let records = storage.query(&selections, None).unwrap();
        assert_eq!(records[0].multi_fields.get("ip_addr").unwrap(), &vec!["192.168.86.5".to_string(), "192.168.86.6".to_string()]);
        assert_eq!(records[0].multi_fields.get("mac_addr").unwrap(), &vec!["e0:51:d8:1d:e3:22".to_string()]);
    }

    #[test]
    fn test_should_reject_malformed_ip_or_mac_and_fail_closed() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "srv-01".to_string()),
            ("ip_addr".to_string(), "192.168.86.5".to_string()),
            ("ip_addr".to_string(), "not-an-ip".to_string()),
        ];
        let res = storage.add_record(fields, None, None);
        assert!(matches!(res, Err(StorageError::InvalidArgument(_))));
        assert_eq!(storage.record_count(), 0);
    }

    #[test]
    fn test_should_allow_records_without_ip_mac_fields() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("name".to_string(), "Jane Smith".to_string()),
            ("type".to_string(), "person".to_string()),
        ];
        let res = storage.add_record(fields, None, None);
        assert!(res.is_ok());
    }

    #[test]
    fn test_should_return_created_outcome_when_adding_new_record_via_upsert() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "srv-new".to_string()),
        ];
        let outcome = storage.upsert_record(fields, None, None).unwrap();
        assert_eq!(outcome, UpsertOutcome::Created);
    }

    #[test]
    fn test_should_return_updated_outcome_when_upserting_existing_record() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "srv-exist".to_string()),
        ];
        let outcome1 = storage.upsert_record(fields.clone(), None, None).unwrap();
        assert_eq!(outcome1, UpsertOutcome::Created);

        let mut update_fields = fields;
        update_fields.push(("status".to_string(), "online".to_string()));
        let outcome2 = storage.upsert_record(update_fields, None, None).unwrap();
        assert_eq!(outcome2, UpsertOutcome::Updated);
    }

    #[test]
    fn test_should_keep_existing_source_field_immutable_on_upsert() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "srv-source".to_string()),
            ("source".to_string(), "pharos-scan".to_string()),
        ];
        storage.upsert_record(fields, None, None).unwrap();

        let update_fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "srv-source".to_string()),
            ("source".to_string(), "mdb".to_string()),
        ];
        storage.upsert_record(update_fields, None, None).unwrap();

        let records = storage.query(&[(Some("hostname".to_string()), "srv-source".to_string())], None).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].fields.get("source").unwrap(), "pharos-scan");
    }

    #[test]
    fn test_should_set_source_field_on_first_creation_via_upsert() {
        let mut storage = MemoryStorage::new();
        let fields = vec![
            ("type".to_string(), "machine".to_string()),
            ("hostname".to_string(), "srv-first".to_string()),
            ("source".to_string(), "web-console".to_string()),
        ];
        storage.upsert_record(fields, None, None).unwrap();

        let records = storage.query(&[(Some("hostname".to_string()), "srv-first".to_string())], None).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].fields.get("source").unwrap(), "web-console");
    }

    #[test]
    fn test_should_match_exact_mac_address_query() {
        // This is the exact bug: before the fix, this returned zero matches despite the record
        // genuinely existing, because matches() splits "bc:24:11:00:02:04" into word fragments
        // ("bc", "24", ...) that can never equal the unsplit query string.
        let mut storage = MemoryStorage::new();
        storage.add_record(
            vec![
                ("type".to_string(), "machine".to_string()),
                ("hostname".to_string(), "test-host".to_string()),
                ("mac_addr".to_string(), "bc:24:11:00:02:04".to_string()),
            ],
            None,
            None,
        ).unwrap();

        let records = storage.query(&[(Some("mac_addr".to_string()), "bc:24:11:00:02:04".to_string())], None).unwrap();
        assert_eq!(records.len(), 1, "exact-value mac_addr query must match the record that has it");
    }

    #[test]
    fn test_should_match_mac_address_query_regardless_of_case_and_separator() {
        let mut storage = MemoryStorage::new();
        storage.add_record(
            vec![
                ("type".to_string(), "machine".to_string()),
                ("hostname".to_string(), "test-host-2".to_string()),
                ("mac_addr".to_string(), "bc:24:11:00:02:04".to_string()),
            ],
            None,
            None,
        ).unwrap();

        // Different case AND different separator (hyphen) than how it was stored.
        let records = storage.query(&[(Some("mac_addr".to_string()), "BC-24-11-00-02-04".to_string())], None).unwrap();
        assert_eq!(records.len(), 1, "typed MAC comparison must be case- and separator-insensitive");
    }

    #[test]
    fn test_should_still_support_fragment_mac_address_search_via_fallback() {
        // Regression: a query value that isn't a full, parseable MAC address (here, just one
        // octet) must still fall back to matches() exactly as it did before this fix - confirming
        // address_matches() doesn't accidentally block the pre-existing fragment-search behavior.
        //
        // NOTE: wildcard patterns containing colons (e.g. mac_addr="bc:24:*") are handled by a
        // separate branch in address_matches() that matches the whole field value against the
        // whole pattern directly, rather than this fragment-based fallback - see
        // test_should_match_wildcard_mac_pattern_containing_colon below.
        let mut storage = MemoryStorage::new();
        storage.add_record(
            vec![
                ("type".to_string(), "machine".to_string()),
                ("hostname".to_string(), "test-host-3".to_string()),
                ("mac_addr".to_string(), "bc:24:11:00:02:04".to_string()),
            ],
            None,
            None,
        ).unwrap();

        let records = storage.query(&[(Some("mac_addr".to_string()), "bc".to_string())], None).unwrap();
        assert_eq!(records.len(), 1, "fragment mac_addr search must still work via the matches() fallback");
    }

    #[test]
    fn test_should_match_ipv6_address_query_regardless_of_compression() {
        let mut storage = MemoryStorage::new();
        storage.add_record(
            vec![
                ("type".to_string(), "machine".to_string()),
                ("hostname".to_string(), "test-host-4".to_string()),
                ("ip_addr".to_string(), "::1".to_string()),
            ],
            None,
            None,
        ).unwrap();

        // Fully-expanded form of the same address - must match via typed IpAddr comparison.
        let records = storage.query(&[(Some("ip_addr".to_string()), "0:0:0:0:0:0:0:1".to_string())], None).unwrap();
        assert_eq!(records.len(), 1, "typed IP comparison must treat IPv6 compression forms as equal");
    }

    #[test]
    fn test_should_match_wildcard_mac_pattern_containing_colon() {
        // The exact bug from Issue #207: before this fix, this query matched zero records despite
        // the record genuinely existing, because the wildcard pattern "bc:24:*" was compared against
        // colon-split field fragments ("bc", "24", ...) that can never satisfy the whole pattern.
        let mut storage = MemoryStorage::new();
        storage.add_record(
            vec![
                ("type".to_string(), "machine".to_string()),
                ("hostname".to_string(), "wildcard-test-host".to_string()),
                ("mac_addr".to_string(), "bc:24:11:00:02:04".to_string()),
            ],
            None,
            None,
        ).unwrap();

        let records = storage.query(&[(Some("mac_addr".to_string()), "bc:24:*".to_string())], None).unwrap();
        assert_eq!(records.len(), 1, "wildcard mac_addr pattern containing a colon must match");
    }

    #[test]
    fn test_should_not_match_wildcard_mac_pattern_with_wrong_prefix() {
        // Negative case: confirms the fix does real prefix matching, not just "any wildcard query
        // returns everything."
        let mut storage = MemoryStorage::new();
        storage.add_record(
            vec![
                ("type".to_string(), "machine".to_string()),
                ("hostname".to_string(), "wildcard-negative-host".to_string()),
                ("mac_addr".to_string(), "bc:24:11:00:02:04".to_string()),
            ],
            None,
            None,
        ).unwrap();

        let records = storage.query(&[(Some("mac_addr".to_string()), "ff:24:*".to_string())], None).unwrap();
        assert_eq!(records.len(), 0, "wildcard mac_addr pattern with a non-matching prefix must not match");
    }

    #[test]
    fn test_should_match_wildcard_mac_pattern_without_colon() {
        // Regression: a wildcard pattern with no colon (e.g. "bc*") already worked correctly
        // before the #207 fix, via the old fragment-based matches() fallback (wildcard_match("bc",
        // "bc*") against the split fragment "bc"). This must keep working now that it takes the
        // new whole-string branch instead (wildcard_match against the full unsplit field value) -
        // confirms that branch didn't only fix colon-containing patterns while accidentally
        // breaking the simpler colon-free wildcard case.
        let mut storage = MemoryStorage::new();
        storage.add_record(
            vec![
                ("type".to_string(), "machine".to_string()),
                ("hostname".to_string(), "wildcard-no-colon-host".to_string()),
                ("mac_addr".to_string(), "bc:24:11:00:02:04".to_string()),
            ],
            None,
            None,
        ).unwrap();

        let records = storage.query(&[(Some("mac_addr".to_string()), "bc*".to_string())], None).unwrap();
        assert_eq!(records.len(), 1, "wildcard mac_addr pattern without a colon must still match");
    }

    #[test]
    fn test_should_match_wildcard_ipv6_pattern_containing_colon() {
        let mut storage = MemoryStorage::new();
        storage.add_record(
            vec![
                ("type".to_string(), "machine".to_string()),
                ("hostname".to_string(), "wildcard-ipv6-host".to_string()),
                ("ip_addr".to_string(), "2001:db8:85a3:0:0:0:0:1".to_string()),
            ],
            None,
            None,
        ).unwrap();

        let records = storage.query(&[(Some("ip_addr".to_string()), "2001:db8:*".to_string())], None).unwrap();
        assert_eq!(records.len(), 1, "wildcard ip_addr pattern containing a colon must match an IPv6 value");
    }

    #[test]
    fn test_should_allow_admin_role_to_force_delete_record_owned_by_different_fingerprint() {
        let mut storage = MemoryStorage::new();
        storage.add_record(
            vec![
                ("type".to_string(), "machine".to_string()),
                ("hostname".to_string(), "orphaned-host".to_string()),
            ],
            Some("original-owner-fingerprint".to_string()),
            None,
        ).unwrap();

        // A different fingerprint, but with the admin role, must still be able to delete it.
        let result = storage.delete_record(
            &[(Some("hostname".to_string()), "orphaned-host".to_string())],
            Some("different-fingerprint".to_string()),
            &[],
            &["admin".to_string()],
        );
        assert!(matches!(result, Ok(1)), "admin role must be able to force-delete a record it doesn't own");
    }

    #[test]
    fn test_should_still_reject_delete_from_non_admin_non_owner() {
        let mut storage = MemoryStorage::new();
        storage.add_record(
            vec![
                ("type".to_string(), "machine".to_string()),
                ("hostname".to_string(), "owned-host".to_string()),
            ],
            Some("original-owner-fingerprint".to_string()),
            None,
        ).unwrap();

        // Different fingerprint, no admin role - must still be rejected exactly as before this fix.
        let result = storage.delete_record(
            &[(Some("hostname".to_string()), "owned-host".to_string())],
            Some("different-fingerprint".to_string()),
            &[],
            &[],
        );
        assert!(matches!(result, Err(StorageError::Unauthorized)), "non-admin, non-owner delete must still be rejected");
    }

    #[test]
    fn test_should_allow_owner_to_delete_own_record_without_admin_role() {
        let mut storage = MemoryStorage::new();
        storage.add_record(
            vec![
                ("type".to_string(), "machine".to_string()),
                ("hostname".to_string(), "self-owned-host".to_string()),
            ],
            Some("owner-fingerprint".to_string()),
            None,
        ).unwrap();

        // The actual owner, no admin role needed - the common case, must be completely unaffected.
        let result = storage.delete_record(
            &[(Some("hostname".to_string()), "self-owned-host".to_string())],
            Some("owner-fingerprint".to_string()),
            &[],
            &[],
        );
        assert!(matches!(result, Ok(1)), "the record's actual owner must still be able to delete it without needing the admin role");
    }
}
