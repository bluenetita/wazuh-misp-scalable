# Changelog

## 1.7 - 2026-08-05

- Leave messages pending when the circuit breaker prevents a MISP query instead of
  acknowledging them as unmatched or consuming a DLQ retry.
- Enable periodic, circuit-aware pending recovery by default and retain its existing
  idle-time and batch-size controls.
- Document production sizing, duplicate-delivery, and outage-recovery guidance.

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
