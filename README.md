# Pharos: Deterministic Infrastructure

<p align="center">
<!-- BADGES_START -->
  <a href="docs/DORA.md"><img src="https://img.shields.io/badge/DORA:__Deployment-Medium%20(monthly)-yellow" alt="DORA: Deployment" /></a>
  <a href="docs/DORA.md"><img src="https://img.shields.io/badge/DORA:__Failure-0.0%25-brightgreen" alt="DORA: Failure" /></a>
<!-- BADGES_END -->
  <a href="artifacts/rfc2378.md"><img src="https://img.shields.io/badge/Protocol-RFC_2378-orange" alt="Protocol: RFC 2378" /></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Made%20with-Rust-black?logo=rust" alt="Made with Rust" /></a>
</p>

**The Unified Source of Truth for Humans and AI Agents. Born in the Home Lab, Rooted in Enterprise Experience.**

Pharos is a high-rigor, read-optimized client-server ecosystem designed to eliminate the **"Hallucination Gap"** in infrastructure discovery. By providing **Deterministic Infrastructure** through an optimized implementation of **RFC 2378** (The Phonebook Protocol), Pharos serves as a Collaborative Force Multiplier for both high-performance engineering teams and autonomous agents.

## The Ecosystem

Pharos is a modular architecture designed for high-rigor systems management:
1. **`pharos-server` (The Engine):** A high-performance, read-optimized backend daemon. It provides a deterministic grounding layer for network assets and human contacts via the RFC 2378 protocol.
2. **`pharos-console-web` (Manager Success):** The primary orchestration interface. A resource-first Web Console providing the **webMCP Grounding Layer** for autonomous AI Agents, ensuring deterministic action across complex environments.
3. **`ph` and `mdb` (Engineer Success):** Ultra-fast CLI clients providing millisecond access to the "Physical Truth" of the network, reducing engineering toil through high-rigor attribution.

## High-Rigor Storage Tiering

Pharos maintains architectural integrity by adapting to your environment:
* **Development:** Volatile, in-memory execution for rapid iteration.
* **Home Lab (Engineer Success):** File-level, restart-survivable storage optimized for Proxmox/LXC environments.
* **Enterprise (Manager Success):** LDAP-backed integration, providing a high-speed, read-optimized proxy for corporate sources of truth.

## Documentation & Traceability

The latest documentation and architecture diagrams are available at:

👉 **[iamrichardd.com/pharos/](https://iamrichardd.com/pharos/)**

Detailed guides (Local versions in [`docs/`](docs/)):
- **[CLI Reference](docs/ARCHITECTURE.md)** - Millisecond access to truth.
- **[Management Console](docs/ARCHITECTURE.md)** - webMCP and orchestration.
- **[Architecture Overview](docs/ARCHITECTURE.md)** - High-rigor system design.
- **[Contributing Guide](CONTRIBUTING.md)** - Collaborative standards.

### Quick Start (Sandbox / Lab-in-a-Box)
The fastest way to evaluate Pharos is via our one-liner sandbox deployment:
```bash
curl -sSL https://raw.githubusercontent.com/iamrichardD/pharos/main/deploy/sandbox.yml -o sandbox.yml && \
podman-compose -f sandbox.yml up -d && \
rm sandbox.yml
```

Once running, you can access the ecosystem:
*   **Web Console:** [http://localhost:3000](http://localhost:3000) (User: `admin` / Pass: `admin`)
*   **Pharos Server (RFC 2378):** `localhost:2378`
*   **Interactive CLI Access:**
    ```bash
    # Access the server container shell
    podman exec -it pharos-server bash
    
    # Access the Web Console container shell
    podman exec -it pharos-web bash
    ```

## Engineering Philosophy
This project is built using strict **Zero-Host Execution** practices. All execution, testing, and dependency management occurs securely within Podman containers, ensuring total environmental parity and absolute security for CI/CD and production deployments. By isolating the build and run environments from the host system, we eliminate "it works on my machine" issues and provide a predictable, reproducible lifecycle. It further enforces atomic unit testing, continuous integration, and transparent DORA metric tracking via GitHub Issues.

## License
This project is licensed under the **AGPL-3.0 License**.

We believe Home Labbers should have absolute, unfettered freedom to experiment, modify, and master their environments. At the same time, we require that Enterprise/SMB entities utilizing Pharos as a networked service contribute their modifications back to the community and maintain clear attribution. See the `LICENSE` file for full details.

## Troubleshooting

### Sandbox: "Connection Refused" to GHCR.io
If the "One-Liner" fails with a `connection refused` error while pulling from `ghcr.io`, your DNS (e.g., Pi-hole, AdGuard, or corporate firewall) may be blocking the GitHub Container Registry.

**Fix:** Ensure `ghcr.io` is whitelisted in your DNS, or try forcing a public DNS for the pull (use `deploy/sandbox.yml` if you have cloned the repository):
```bash
podman-compose --podman-pull-args="--dns 8.8.8.8" -f deploy/sandbox.yml up -d
```

### Sandbox: "403 Forbidden" from GHCR.io
If you receive a `403 Forbidden` error, the packages may still be marked as "Private" (the default for new GHCR images).

**Fix:** Navigate to your GitHub profile -> **Packages**, select the `pharos-*` images, and change their visibility to **Public** in the "Package Settings" at the bottom of the page.

### Sandbox: "syscall bdflush: permission denied"
If you see an error related to `seccomp` and `bdflush` (common on Ubuntu 24.04 with older container runtimes), the sandbox configuration now includes a bypass (`seccomp: unconfined`) to ensure a smooth evaluation.

**Note:** This bypass is only for the ephemeral sandbox and should not be used in production environments where a custom seccomp profile or an updated runtime (`crun`) is preferred.

---

<!-- DORA_START -->
### 🚀 Project Velocity (DORA)
| Metric | Status | Category |
| :--- | :--- | :--- |
| **Deployment Frequency** | 0 tags | Medium (monthly) |
| **Change Failure Rate** | 0.0% | Elite |

> [View Full DORA Report](docs/DORA.md)
<!-- DORA_END -->
