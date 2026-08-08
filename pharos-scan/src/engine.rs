/* ========================================================================
 * Project: pharos
 * Component: Network Scanner (pharos-scan)
 * File: pharos-scan/src/engine.rs
 * Author: Richard D. (https://github.com/iamrichardd)
 * License: AGPL-3.0 (See LICENSE file for details)
 * * Purpose (The "Why"):
 * This module implements the scanning engines for mDNS discovery and
 * port fingerprinting, providing the core discovery functionality.
 * * Traceability:
 * Related to Task 10.2 (Issue #40)
 * ======================================================================== */

use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use anyhow::{Result, Context};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use tracing::{info, debug};
use crate::DiscoveredNode;
use pharos_client::{PharosClient, PharosResponse};
use futures::stream::{self, StreamExt};
use ipnet::IpNet;

pub struct ScannerEngine {
    timeout: Duration,
    common_ports: Vec<u16>,
}

impl Default for ScannerEngine {
    fn default() -> Self {
        ScannerEngine {
            timeout: Duration::from_millis(500),
            common_ports: vec![22, 80, 443, 8006, 32400],
        }
    }
}

impl ScannerEngine {
    /// Constructs a `ScannerEngine` with explicit timeout/port settings. Production code should
    /// use `ScannerEngine::default()`; this exists so tests can use a safe, non-privileged port
    /// and a short timeout instead of the production defaults.
    pub fn new(timeout: Duration, common_ports: Vec<u16>) -> Self {
        ScannerEngine { timeout, common_ports }
    }

    /// Checks if a node already exists in the Pharos server.
    pub async fn check_existing(&self, node: &mut DiscoveredNode, client: &mut PharosClient) -> Result<()> {
        let query = format!("ip={}", node.ip);
        let resp = client.execute(&query).await?;
        if let PharosResponse::Matches { count, .. } = resp {
            node.is_existing = count > 0;
        }
        Ok(())
    }

    /// Perform mDNS discovery on the local network.
    pub async fn discover_mdns(&self) -> Result<Vec<DiscoveredNode>> {
        let mdns = ServiceDaemon::new().context("Failed to start mDNS daemon")?;
        let service_type = "_ssh._tcp.local.";
        let receiver = mdns.browse(service_type).context("Failed to browse mDNS")?;

        info!("Browsing for mDNS services (_ssh._tcp.local.)...");

        let mut nodes = std::collections::HashMap::new();
        let scan_duration = Duration::from_secs(5);
        let start = std::time::Instant::now();

        while start.elapsed() < scan_duration {
            if let Ok(ServiceEvent::ServiceResolved(info)) = receiver.recv_timeout(Duration::from_millis(100)) {
                for ip in info.get_addresses() {
                    let node = DiscoveredNode {
                        ip: *ip,
                        hostname: Some(info.get_fullname().to_string()),
                        mac: None,
                        manufacturer: None,
                        ports: Vec::new(),
                        role: None,
                        is_existing: false,
                    };
                    nodes.insert(*ip, node);
                }
            }
        }

        Ok(nodes.into_values().collect())
    }

    /// Perform a fast port scan on a specific IP.
    pub async fn probe_node(&self, ip: IpAddr) -> Vec<u16> {
        let mut open_ports = Vec::new();
        for port in &self.common_ports {
            let addr = format!("{}:{}", ip, port);
            if let Ok(Ok(_)) = timeout(self.timeout, TcpStream::connect(&addr)).await {
                debug!("Port {} is open on {}", port, ip);
                open_ports.push(*port);
            }
        }
        open_ports
    }

    /// Perform a TCP-probe-based sweep of every host address in `subnet` (CIDR notation, e.g.
    /// "192.168.1.0/24"), returning a `DiscoveredNode` for every address with at least one of
    /// `common_ports` open. Does not require elevated privileges (unlike ICMP/ARP scanning) -
    /// this matters since pharos-scan may run unprivileged or inside a container.
    ///
    /// Each live node is additionally enriched, best-effort, with MAC address (read from the
    /// OS's ARP cache, populated automatically by the probe connection attempts), manufacturer
    /// (resolved from the MAC via `OUIResolver`), and hostname (reverse DNS) - none of these are
    /// required for a host to be reported as discovered, they're populated when available.
    ///
    /// Trade-off: a live host with none of `common_ports` open will not be detected by this
    /// method. This is a deliberate choice to avoid requiring raw sockets; such a host may still
    /// be found via `discover_mdns` if it advertises mDNS services.
    pub async fn scan_subnet(&self, subnet: &str) -> Result<Vec<DiscoveredNode>> {
        let net: IpNet = subnet
            .parse()
            .with_context(|| format!("Invalid subnet '{}' (expected CIDR notation, e.g. 192.168.1.0/24)", subnet))?;

        let host_ips: Vec<IpAddr> = net.hosts().collect();
        info!("Scanning {} candidate address(es) in {}...", host_ips.len(), subnet);

        let nodes: Vec<DiscoveredNode> = stream::iter(host_ips)
            .map(|ip| async move {
                let ports = self.probe_node(ip).await;
                (ip, ports)
            })
            .buffer_unordered(64)
            .filter_map(|(ip, ports)| async move {
                if ports.is_empty() {
                    None
                } else {
                    debug!("Live host found: {} (open ports: {:?})", ip, ports);
                    Some(DiscoveredNode {
                        ip,
                        hostname: None,
                        mac: None,
                        manufacturer: None,
                        ports,
                        role: None,
                        is_existing: false,
                    })
                }
            })
            .collect()
            .await;

        let arp_cache = read_arp_cache();
        let oui = crate::oui::OUIResolver::default();
        let mut enriched = Vec::with_capacity(nodes.len());
        for mut node in nodes {
            node.mac = arp_cache.get(&node.ip).cloned();
            if let Some(ref mac) = node.mac {
                node.manufacturer = oui.resolve(mac);
            }
            node.hostname = lookup_hostname(node.ip).await;
            enriched.push(node);
        }

        Ok(enriched)
    }
}

/// Parses `/proc/net/arp`-formatted content into a map of IP -> MAC address. Pure/testable -
/// does no I/O itself. Skips "incomplete" entries (MAC `00:00:00:00:00:00`, meaning an ARP
/// request was sent but no reply received yet).
fn parse_arp_cache(contents: &str) -> std::collections::HashMap<IpAddr, String> {
    let mut map = std::collections::HashMap::new();
    for line in contents.lines().skip(1) { // skip header row
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 {
            let parsed_ip = fields[0].parse::<IpAddr>();
            if let Ok(ip) = parsed_ip {
                let mac = fields[3];
                if mac != "00:00:00:00:00:00" {
                    map.insert(ip, mac.to_string());
                }
            }
        }
    }
    map
}

/// Reads the OS's ARP/neighbor cache. Linux-specific (`/proc/net/arp`); returns an empty map
/// (not an error) if the file is unavailable - MAC enrichment is best-effort, not required for
/// a scan to succeed.
pub fn read_arp_cache() -> std::collections::HashMap<IpAddr, String> {
    std::fs::read_to_string("/proc/net/arp")
        .map(|contents| parse_arp_cache(&contents))
        .unwrap_or_default()
}

/// Best-effort reverse-DNS lookup for a discovered host's hostname. Returns `None` (not an
/// error) if there's no PTR record - this must never fail the overall scan. Wrapped in
/// `spawn_blocking` because `dns_lookup::lookup_addr` is a blocking libc call.
pub(crate) async fn lookup_hostname(ip: IpAddr) -> Option<String> {
    match tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip)).await {
        Ok(Ok(hostname)) => Some(hostname),
        Ok(Err(e)) => {
            debug!("Reverse DNS lookup failed for {}: {}", ip, e);
            None
        }
        Err(e) => {
            debug!("Reverse DNS lookup task failed for {}: {}", ip, e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Ensures that malformed input (e.g. non-CIDR strings) is safely rejected
    /// by the parser, preventing runtime panic or unexpected behavior when parsing subnet input.
    #[tokio::test]
    async fn test_should_reject_invalid_subnet_string() {
        let engine = ScannerEngine::default();
        let result = engine.scan_subnet("not-a-valid-subnet").await;
        assert!(result.is_err());
    }

    /// Verifies that the scanner successfully probes and detects a live port
    /// listener on the specified IP within the subnet scan. This prevents regressions
    /// in the basic TCP connect logic and results collection.
    #[tokio::test]
    async fn test_should_find_live_host_with_open_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let engine = ScannerEngine::new(Duration::from_millis(300), vec![port]);
        let nodes = engine.scan_subnet("127.0.0.1/32").await.unwrap();

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(nodes[0].ports, vec![port]);
    }

    /// Verifies that subnets with no active ports yield an empty result list,
    /// preventing false positives or hangs when scanning dead or unroutable networks.
    #[tokio::test]
    async fn test_should_return_empty_for_subnet_with_no_live_hosts() {
        // 192.0.2.0/29 is TEST-NET-1 (RFC 5737) - reserved for documentation/testing, guaranteed
        // no real host will ever respond here. Deliberately NOT using a second 127.0.0.0/8
        // address for this negative control: Linux's loopback local-delivery routing means a
        // listener bound to 127.0.0.1 also accepts connections addressed to other 127.x.x.x
        // addresses, which would make a same-block negative control unreliable (confirmed
        // empirically before this plan was written - do not "fix" this test to use a loopback
        // address instead, it would be flaky/wrong).
        let engine = ScannerEngine::new(Duration::from_millis(300), vec![22, 80]);
        let nodes = engine.scan_subnet("192.0.2.0/29").await.unwrap();
        assert!(nodes.is_empty());
    }

    /// Verifies that closed but reachable ports (which return connection refused)
    /// are not mistakenly counted as open. This prevents incorrect reports of open
    /// ports on hosts in the subnet block.
    #[tokio::test]
    async fn test_should_not_count_a_closed_but_reachable_port_as_open() {
        // Regression test for a real bug found during Issue #110's live-LAN verification: see
        // probe_node's fix for the full explanation (timeout(...).await.is_ok() checked the wrong
        // layer of a nested Result).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener); // free the port immediately - nothing is listening on it anymore

        let engine = ScannerEngine::new(Duration::from_millis(300), vec![port]);
        let ports = engine.probe_node("127.0.0.1".parse().unwrap()).await;
        assert!(ports.is_empty(), "a closed-but-reachable port must not be reported as open");
    }

    /// Verifies that we can correctly parse standard Linux /proc/net/arp cache format
    /// and correctly skip entries with a HW address of all zeroes (incomplete ARP cache items).
    #[test]
    fn test_should_parse_arp_cache_and_skip_incomplete_entries() {
        let sample = "IP address       HW type     Flags       HW address            Mask     Device\n\
                      192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n\
                      192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        let cache = parse_arp_cache(sample);
        assert_eq!(
            cache.get(&"192.168.1.1".parse::<IpAddr>().unwrap()),
            Some(&"aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(cache.get(&"192.168.1.2".parse::<IpAddr>().unwrap()), None);
    }

    #[tokio::test]
    async fn test_should_return_none_without_panicking_for_unresolvable_ip() {
        // 192.0.2.1 is TEST-NET-1 (RFC 5737) - reserved for documentation/testing, guaranteed to
        // have no real reverse-DNS record anywhere.
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let result = lookup_hostname(ip).await;
        assert!(result.is_none());
    }
}
