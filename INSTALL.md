# Install

This guide assumes installation on the Wazuh Manager host. Run repository file
commands from the repository root.

## Prerequisites

- Wazuh Manager running
- Redis available (local recommended)
- Python 3 with virtual environment support
- gcc and hiredis development headers

## 1) Redis

Install and start Redis.

Debian/Ubuntu:

```bash
sudo apt install redis-server redis-tools gcc libhiredis-dev python3 python3-venv
sudo systemctl enable --now redis-server
```

RHEL/Alma/Rocky:

```bash
sudo dnf install redis gcc hiredis-devel python3
sudo systemctl enable --now redis
```

Verify:

```bash
redis-cli PING
# PONG
```

## 2) Forwarder (C)

Build the actual source file and install it into the Wazuh integrations
directory:

```bash
gcc -O2 -Wall -Wextra \
  -o /tmp/custom-misp-forwarder \
  forwarder/src/custom-misp.c \
  -lhiredis
sudo install -o root -g wazuh -m 0750 \
  /tmp/custom-misp-forwarder \
  /var/ossec/integrations/custom-misp-forwarder
```

The forwarder should enqueue raw Wazuh alerts into a Redis Stream (field name: `alert`).

## 3) Worker (Python) inside /var/ossec

Create the virtual environment, install dependencies, and deploy the worker:

```bash
sudo mkdir -p /var/ossec/var/misp_worker
sudo python3 -m venv /var/ossec/var/misp_worker/venv
sudo /var/ossec/var/misp_worker/venv/bin/pip install -U pip
sudo /var/ossec/var/misp_worker/venv/bin/pip install requests redis pyyaml
sudo install -o root -g wazuh -m 0750 \
  worker/src/misp_worker.py \
  /var/ossec/integrations/misp_worker.py
```

## 4) Config

Install the example environment and extractor configuration:

```bash
sudo install -o root -g wazuh -m 0640 \
  config/misp_worker.env.example \
  /var/ossec/etc/misp_worker.env
sudo install -o root -g wazuh -m 0640 \
  config/misp_extractors.yml.example \
  /var/ossec/etc/misp_extractors.yml
sudo $EDITOR /var/ossec/etc/misp_worker.env
```

Set these values:

- `MISP_BASE_URL` to the MISP instance base URL, for example
  `https://misp.example.local`. Do not append `/attributes/restSearch`; the
  worker appends it.
- `MISP_API_KEY` to a MISP automation key.
- `MISP_VERIFY` to a trusted CA bundle. Use `0` only for isolated testing.

The extractor file is optional because the worker has built-in defaults. Those
defaults include Falco connection fields;
the example demonstrates how to add other site-specific paths.

## 5) Wazuh integration entry

Install the rules emitted by the worker:

```bash
sudo install -o wazuh -g wazuh -m 0660 \
  rules/local_rules.xml \
  /var/ossec/etc/rules/misp.xml
```

In `/var/ossec/etc/ossec.conf`, add:

```xml
<integration>
  <name>custom-misp-forwarder</name>
  <alert_format>json</alert_format>
</integration>
```

This sends every eligible Wazuh alert to the Redis stream. To restrict the
integration, add `<group>to_misp</group>` and ensure each intended source rule
belongs to that group. Worker v1.5 does not require or enforce `to_misp` itself.

Restart the manager:

```bash
sudo systemctl restart wazuh-manager
```

## 6) systemd service for the worker

Install the supplied unit, then enable and start the worker:

```bash
sudo install -o root -g root -m 0644 \
  systemd/wazuh-misp-worker.service \
  /etc/systemd/system/wazuh-misp-worker.service
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-misp-worker
sudo systemctl status wazuh-misp-worker --no-pager
```

`systemctl reload wazuh-misp-worker` sends SIGHUP and reloads only
`misp_extractors.yml`. Restart the worker after changing the environment file,
worker code, Python dependencies, or systemd unit.

Worker v1.5 preserves flat `misp_*` fields for Wazuh rules and places detailed
source/match objects under `misp_context`. This avoids OpenSearch field mapping
conflicts with generic keys such as `data.source`.

## 7) Verify pipeline

1. Confirm the Redis stream is receiving messages:

```bash
redis-cli XLEN wazuh:misp:in
redis-cli XREVRANGE wazuh:misp:in + - COUNT 1
```

2. Confirm the worker is consuming and acknowledging them:

```bash
redis-cli XINFO GROUPS wazuh:misp:in
redis-cli XPENDING wazuh:misp:in misp
```

3. For temporary tracing, set `TRACE=1` and `HEARTBEAT_SEC=10` in
   `/var/ossec/etc/misp_worker.env`, restart the worker, and inspect
   `/var/ossec/logs/misp_worker.log`.
