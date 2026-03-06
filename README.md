# Wazuh → MISP Enrichment (Forwarder C + Redis Streams + Worker Python)

A fast, scalable enrichment pipeline for Wazuh alerts using MISP.

Instead of running a one-shot script per alert (slow startup + HTTP per event), this project uses:
- a **tiny C forwarder** (runs per alert, does *only* enqueue),
- **Redis Streams** (buffer + consumer groups),
- a **persistent Python worker** (extract IoCs, cache/dedupe, query MISP, emit back to Wazuh).

## What it enriches

This project intentionally supports only these observable families:
- **IP** (public/global only)
- **FQDN**
- **Hashes**: `md5`, `sha1`, `sha256`

That narrow scope keeps extraction robust and performance predictable.

## Architecture (high level)

```
Wazuh alert (group: to_misp)
  └─> forwarder (C)
       └─> Redis Stream (field: alert="<raw Wazuh JSON>")
            └─> worker (Python, persistent)
                 ├─> extract observables (defaults + optional YAML)
                 ├─> dedupe TTL (burst control)
                 ├─> cache TTL hit/miss (reduce MISP calls)
                 ├─> POST MISP /attributes/restSearch (+ optional searchall fallback)
                 └─> send aggregated enrichment event to Wazuh queue socket
```

## Repository layout

- `forwarder/` — C forwarder (enqueue raw alert to Redis Stream)
- `worker/` — Python worker (extract, cache, query, emit)
- `systemd/` — systemd unit for the worker
- `config/` — example env and extractor config files
- `examples/` — sanitized alert examples
- `docs/` — architecture, install, config, troubleshooting, tuning, FAQ

## Quickstart (Wazuh Manager host)

> This is the “fast path”. For full details see `docs/INSTALL.md`.

### 1) Redis
Install and start Redis, then verify:
```bash
redis-cli PING
# PONG
```

### 2) Build + install forwarder
```bash
cd forwarder
make
sudo install -m 0750 custom-misp-forwarder /var/ossec/integrations/custom-misp-forwarder
```

### 3) Install worker under /var/ossec
```bash
sudo mkdir -p /var/ossec/var/misp_worker
sudo python3 -m venv /var/ossec/var/misp_worker/venv
sudo /var/ossec/var/misp_worker/venv/bin/pip install -U pip
sudo /var/ossec/var/misp_worker/venv/bin/pip install requests redis pyyaml

sudo install -m 0750 worker/misp_worker.py /var/ossec/integrations/misp_worker.py
```

### 4) Configure env + extractors (examples)
```bash
sudo cp config/misp_worker.env.example /var/ossec/etc/misp_worker.env
sudo chmod 0640 /var/ossec/etc/misp_worker.env
sudo $EDITOR /var/ossec/etc/misp_worker.env
```

Optional: extend extraction paths (defaults are already built-in):
```bash
sudo cp config/misp_extractors.yml.example /var/ossec/etc/misp_extractors.yml
```

### 5) Tell Wazuh to call the forwarder for `to_misp`
In `/var/ossec/etc/ossec.conf`:
```xml
<integration>
  <name>custom-misp-forwarder</name>
  <group>to_misp</group>
  <alert_format>json</alert_format>
</integration>
```

Restart Wazuh manager:
```bash
sudo systemctl restart wazuh-manager
```

### 6) Start the worker (systemd)
```bash
sudo cp systemd/wazuh-misp-worker.service /etc/systemd/system/wazuh-misp-worker.service
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-misp-worker
sudo systemctl status wazuh-misp-worker --no-pager
```

## Configuration notes (important)

### MISP endpoint
The worker uses **POST** on MISP:
- `https://<misp>/attributes/restSearch`

Set in env:
- `MISP_BASE_URL=https://misp.example.local/attributes/restSearch`
- `MISP_API_KEY=...`

Optional fallback for composite values (e.g., `filename|sha256`, `domain|ip`):
- `MISP_FALLBACK_SEARCHALL=1`
- `MISP_SEARCHALL_WRAP_PERCENT=1`

### Cache and dedupe
Recommended starting values:
- `DEDUP_TTL=2`
- `CACHE_MISS_TTL=600`
- `CACHE_HIT_TTL=3600`

### Extractors (defaults + optional YAML)
Out of the box, extraction covers:
- generic IP fields (src/dst variants from many default decoders),
- Sysmon (FQDN + hashes),
- FIM/syscheck hashes.

To extend without code changes, add paths in:
- `/var/ossec/etc/misp_extractors.yml` (see `config/misp_extractors.yml.example`)

### Observability
- Heartbeat logs every `HEARTBEAT_SEC` seconds (stream_len/pending/last_delivered_id + counters)
- Temporary deep debug:
  - `TRACE=1`
  - `HEARTBEAT_SEC=10`

## Verify it works

### Redis stream receives messages
```bash
redis-cli XLEN wazuh:misp:in
redis-cli XREVRANGE wazuh:misp:in + - COUNT 1
```

### Worker consumes and acks
```bash
redis-cli XINFO GROUPS wazuh:misp:in
redis-cli XPENDING wazuh:misp:in misp
```

### Worker logs
```bash
sudo tail -f /var/ossec/logs/misp_worker.log
```

## Documentation

- `docs/ARCHITECTURE.md`
- `docs/INSTALL.md`
- `docs/CONFIG.md`
- `docs/TROUBLESHOOTING.md`
- `docs/PERFORMANCE_TUNING.md`
- `docs/FAQ.md`

## License

This project is licensed under the **GNU AGPL v3**. See `LICENSE`.

## Security

Please do not file public issues for security reports.
See `SECURITY.md` for reporting instructions.

## Contributing

See `CONTRIBUTING.md`.
