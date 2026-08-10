/* ========================================================================
 * Project: pharos
 * Component: pharos-console
 * File: crates/pharos-console/src/main.rs
 * Author: Richard D. (https://github.com/iamrichardd)
 * License: AGPL-3.0 (See LICENSE file for details)
 * * Purpose (The "Why"):
 * This is the entry point for the `pharos-console` MCP Server. It reads
 * standard input for JSON-RPC messages and provides tools to manage
 * Pharos security (e.g. provision SSH keys for scoped tier).
 * * Traceability:
 * Related to Task 14.3 (Issue #51)
 * ======================================================================== */

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, BufRead, Write};
use tracing::{info, error, debug};
use ssh_key::{PrivateKey, rand_core::OsRng};
use std::fs;
use std::path::Path;
use std::env;

#[derive(Serialize, Deserialize, Debug)]
struct RpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcResponse {
    jsonrpc: String,
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcError {
    code: i32,
    message: String,
}

fn handle_provision_key(params: Option<Value>) -> Result<Value, RpcError> {
    let params_obj = params.and_then(|p| p.as_object().cloned()).unwrap_or_default();
    
    // Extract role or default to 'user'
    let role = params_obj.get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("user")
        .to_string();

    debug!("Provisioning new key for role: {}", role);

    // Generate new Ed25519 key
    let key = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519)
        .map_err(|e| RpcError { code: -32603, message: format!("Failed to generate key: {}", e) })?;

    // Determine keys directory (simulating server's environment)
    let keys_dir = env::var("PHAROS_KEYS_DIR").unwrap_or_else(|_| "/tmp/pharos_keys".to_string());
    let keys_path = Path::new(&keys_dir);
    
    if !keys_path.exists() {
        fs::create_dir_all(keys_path)
            .map_err(|e| RpcError { code: -32603, message: format!("Failed to create keys directory: {}", e) })?;
    }

    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let filename = format!("{}_{}_{}.pub", role, "mcp", timestamp);
    let pub_path = keys_path.join(&filename);

    let pub_key_str = key.public_key().to_openssh()
        .map_err(|e| RpcError { code: -32603, message: format!("Failed to serialize public key: {}", e) })?;

    // The auth manager extracts role from filename in our current implementation
    fs::write(&pub_path, &pub_key_str)
        .map_err(|e| RpcError { code: -32603, message: format!("Failed to save public key: {}", e) })?;

    info!("Provisioned new key at {:?}", pub_path);

    let priv_key_str = key.to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| RpcError { code: -32603, message: format!("Failed to serialize private key: {}", e) })?;

    Ok(serde_json::json!({
        "status": "success",
        "public_key": pub_key_str,
        "private_key": priv_key_str.to_string(),
        "role": role,
        "path": pub_path.to_string_lossy().to_string(),
    }))
}

fn handle_list_keys() -> Result<Value, RpcError> {
    let keys_dir = env::var("PHAROS_KEYS_DIR").unwrap_or_else(|_| "/tmp/pharos_keys".to_string());
    let keys_path = Path::new(&keys_dir);

    let mut keys = Vec::new();
    if keys_path.exists() && keys_path.is_dir() {
        if let Ok(entries) = fs::read_dir(keys_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().map(|s| s == "pub").unwrap_or(false) {
                    keys.push(path.file_name().unwrap_or_default().to_string_lossy().to_string());
                }
            }
        }
    }

    Ok(serde_json::json!({
        "keys": keys
    }))
}

fn process_request(req: RpcRequest) -> RpcResponse {
    let result = match req.method.as_str() {
        "mcp.provision_key" => handle_provision_key(req.params),
        "mcp.list_keys" => handle_list_keys(),
        _ => Err(RpcError {
            code: -32601,
            message: "Method not found".to_string(),
        }),
    };

    match result {
        Ok(val) => RpcResponse {
            jsonrpc: "2.0".to_string(),
            id: req.id,
            result: Some(val),
            error: None,
        },
        Err(err) => RpcResponse {
            jsonrpc: "2.0".to_string(),
            id: req.id,
            result: None,
            error: Some(err),
        },
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(io::stderr) // Important: logs go to stderr to not corrupt JSON-RPC stdout
        .init();

    info!("Starting pharos-console MCP server...");

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                error!("Error reading stdin: {}", e);
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        match serde_json::from_str::<RpcRequest>(&line) {
            Ok(req) => {
                debug!("Received request: {:?}", req);
                let response = process_request(req);
                let response_str = serde_json::to_string(&response)?;
                writeln!(stdout, "{}", response_str)?;
                stdout.flush()?;
            }
            Err(e) => {
                error!("Failed to parse request: {}", e);
                let err_resp = RpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: None,
                    result: None,
                    error: Some(RpcError {
                        code: -32700,
                        message: "Parse error".to_string(),
                    }),
                };
                writeln!(stdout, "{}", serde_json::to_string(&err_resp)?)?;
                stdout.flush()?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_process_list_keys_request() {
        let req = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(Value::Number(1.into())),
            method: "mcp.list_keys".to_string(),
            params: None,
        };

        let response = process_request(req);
        assert!(response.result.is_some());
        assert!(response.error.is_none());
        assert_eq!(response.id, Some(Value::Number(1.into())));
    }

    #[test]
    fn test_should_return_error_for_unknown_method() {
         let req = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(Value::Number(2.into())),
            method: "mcp.unknown".to_string(),
            params: None,
        };

        let response = process_request(req);
        assert!(response.result.is_none());
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32601);
    }
}
