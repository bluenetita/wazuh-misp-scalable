# Security Policy

This project is security-adjacent (log ingestion, enrichment, and incident-response pipelines). We take vulnerabilities seriously.

## Supported Versions

Only the latest **minor** release line is supported with security fixes. If you are running an older version, please upgrade before reporting (when possible).

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security reports.

Instead, use one of the following private channels:

1) **GitHub Security Advisories** (preferred, if enabled on the repository)
- Go to the repository → **Security** → **Advisories** → **Report a vulnerability**

2) **Email**
- If the repository owner provides a security contact address in the README, email that address.
- If no address is available, open a GitHub Security Advisory request (option 1).

### What to include

To help us triage quickly, please include:

- A clear description of the vulnerability and potential impact
- Affected component(s) (forwarder, worker, systemd unit, docs)
- Version / commit hash
- Configuration details relevant to the issue (redact secrets)
- Reproduction steps (preferably minimal)
- Proof of concept (PoC) if available (keep it safe)
- Any proposed fix or mitigation
- Whether you plan to disclose publicly, and when

**Please redact**:
- `MISP_API_KEY` and any credentials
- Internal hostnames / IPs / domains
- Sensitive logs or alert payloads

If you need to share data, anonymize it and/or share only the smallest subset required.

## Coordinated Disclosure

We aim to acknowledge reports within **72 hours** and will work with you on a coordinated disclosure timeline.
If the issue is critical and actively exploitable, we may publish a mitigation advisory sooner.

## Security Best Practices (Operators)

### Secrets handling
- Never commit real API keys.
- Use `/var/ossec/etc/misp_worker.env` with restrictive permissions (e.g., `0640`).
- Consider using a secrets manager if available in your environment.

### TLS
- Use TLS verification (`MISP_VERIFY=/path/to/ca-bundle.crt`).
- Disabling TLS verification (`MISP_VERIFY=0`) should be used only for temporary testing.

### Least privilege
- Run the worker as a non-root user (typically `wazuh` or `ossec`), if possible.
- Restrict file permissions under `/var/ossec`.
- Consider systemd hardening options (NoNewPrivileges, ProtectSystem, ReadWritePaths).

### Availability / backpressure
- Use Redis Streams for buffering and consumer groups.
- Tune cache TTLs to reduce MISP traffic.
- When `DLQ_MAX_RETRIES=0`, choose `ACK_ON_MISP_ERROR` behavior that matches your
  outage strategy. With DLQ enabled, MISP query failures remain pending until
  the retry threshold.

## Scope

This policy applies to:
- The forwarder source and build artifacts
- The Python worker code and its configuration
- The systemd unit provided in this repository
- Documentation and example configs

It does not apply to:
- Wazuh itself
- Redis itself
- MISP itself
- Third-party libraries (report upstream as well)

Thank you for helping keep this project secure.
