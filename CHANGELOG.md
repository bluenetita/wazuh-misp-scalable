# Changelog

## 1.6 - 2026-08-05

- Keep MISP failures pending until the configured DLQ retry threshold and
  acknowledge the source only after a successful DLQ write.
- Allow retries of the same stream message through short-window deduplication.
- Complete one cursor-based pending scan during startup recovery.
- Limit circuit-breaker half-open state to one probe at a time.
- Add focused regression tests for delivery-state behavior.

## 1.5 - 2026-08-05

- Namespace detailed enrichment data under `misp_context` to prevent
  OpenSearch mapping conflicts with generic Wazuh fields such as `data.source`.
- Preserve flat `misp_*` fields used by Wazuh rules and dashboards.
- Extract Falco connection IPs from `data.output_fields.fd.sip` and
  `data.output_fields.fd.cip` by default.
- Correct installation paths, MISP base URL guidance, permissions, integration
  scope, and worker reload behavior in `README.md` and `INSTALL.md`.
