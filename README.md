# Wazuh → MISP Enrichment

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
Wazuh alert
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
- `rules/` — Wazuh rules for MISP enrichment events
- `INSTALL.md` — complete manager-host installation procedure
- `docs/ARCHITECTURE.md` — pipeline architecture and failure behavior

## Quickstart (Wazuh Manager host)

> This is the “fast path”. Run these commands from the repository root. For
> full details see `INSTALL.md`.

### 1) Redis
Install and start Redis, then verify:
```bash
redis-cli PING
# PONG
```

### 2) Build + install forwarder
```bash
gcc -O2 -Wall -Wextra \
  -o /tmp/custom-misp-forwarder \
  forwarder/src/custom-misp.c \
  -lhiredis
sudo install -o root -g wazuh -m 0750 \
  /tmp/custom-misp-forwarder \
  /var/ossec/integrations/custom-misp-forwarder
```

### 3) Install worker under /var/ossec
```bash
sudo mkdir -p /var/ossec/var/misp_worker
sudo python3 -m venv /var/ossec/var/misp_worker/venv
sudo /var/ossec/var/misp_worker/venv/bin/pip install -U pip
sudo /var/ossec/var/misp_worker/venv/bin/pip install requests redis pyyaml

sudo install -o root -g wazuh -m 0750 \
  worker/src/misp_worker.py \
  /var/ossec/integrations/misp_worker.py
```

### 4) Configure env + extractors (examples)
```bash
sudo install -o root -g wazuh -m 0640 \
  config/misp_worker.env.example \
  /var/ossec/etc/misp_worker.env
sudo $EDITOR /var/ossec/etc/misp_worker.env
```

Optional: extend extraction paths (defaults are already built-in):
```bash
sudo install -o root -g wazuh -m 0640 \
  config/misp_extractors.yml.example \
  /var/ossec/etc/misp_extractors.yml
```

### 5) Install Wazuh rules and call the forwarder

```bash
sudo install -o wazuh -g wazuh -m 0660 \
  rules/local_rules.xml \
  /var/ossec/etc/rules/misp.xml
```

In `/var/ossec/etc/ossec.conf`:
```xml
<integration>
  <name>custom-misp-forwarder</name>
  <alert_format>json</alert_format>
</integration>
```

Restart Wazuh manager:
```bash
sudo systemctl restart wazuh-manager
```

### 6) Start the worker (systemd)
```bash
sudo install -o root -g root -m 0644 \
  systemd/wazuh-misp-worker.service \
  /etc/systemd/system/wazuh-misp-worker.service
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-misp-worker
sudo systemctl status wazuh-misp-worker --no-pager
```

## Configuration notes (important)

### MISP endpoint
The worker uses **POST** on MISP:
- `https://<misp>/attributes/restSearch`

Set in env:
- `MISP_BASE_URL=https://misp.example.local`
- `MISP_API_KEY=...`

`MISP_BASE_URL` is the instance base URL. The worker appends
`/attributes/restSearch`; do not include that endpoint in the variable.

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

The built-in defaults also cover Falco connection fields such as
`data.output_fields.fd.sip`

### Wazuh integration scope
The integration block above forwards every eligible Wazuh alert. To restrict
enrichment, add `<group>to_misp</group>` to the block and ensure the source rules
belong to that group. Worker v1.5 does not impose a second hard-coded group gate.

### Worker v1.5+ output
Matched observables remain available through flat `misp_*` fields for Wazuh
rules. Detailed source and match arrays are emitted under `misp_context` so they
cannot collide with generic OpenSearch mappings such as `data.source`.

### Observability
- Heartbeat logs every `HEARTBEAT_SEC` seconds (stream_len/pending/last_delivered_id + counters)
- Temporary deep debug:
  - `TRACE=1`
  - `HEARTBEAT_SEC=10`

### MISP outage recovery

Circuit-denied messages remain pending instead of being acknowledged as unmatched.
Keep `AUTOCLAIM_LOOP=1` so the worker reclaims them when MISP recovery can be probed.
For production sizing, idle-time safety, duplicate-delivery expectations, and backlog
monitoring, see `docs/ARCHITECTURE.md`.

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

- `INSTALL.md`
- `docs/ARCHITECTURE.md`

## License

This project is licensed under the **GNU AGPL v3**. See `LICENSE`.

## Security

Please do not file public issues for security reports.
See `SECURITY.md` for reporting instructions.

## Contributing

See `CONTRIBUTING.md`.
