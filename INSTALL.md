# Install

This guide assumes installation on the Wazuh Manager host.

## Prerequisites

- Wazuh Manager running
- Redis available (local recommended)
- Python 3 available on the manager
- (For forwarder build) gcc + hiredis dev libs

## 1) Redis

Install and start Redis (examples):

Debian/Ubuntu:
- `apt install redis-server redis-tools`

RHEL/Alma/Rocky:
- `dnf install redis`

Verify:
- `redis-cli PING` -> `PONG`

## 2) Forwarder (C)

Build and install into Wazuh integrations directory:

- Build:
  - `gcc -O2 -o custom-misp-forwarder custom-misp-forwarder.c -lhiredis`

- Install:
  - `install -m 0750 custom-misp-forwarder /var/ossec/integrations/custom-misp-forwarder`

The forwarder should enqueue raw Wazuh alerts into a Redis Stream (field name: `alert`).

## 3) Worker (Python) inside /var/ossec

Create virtualenv and install deps:

- `mkdir -p /var/ossec/var/misp_worker`
- `python3 -m venv /var/ossec/var/misp_worker/venv`
- `/var/ossec/var/misp_worker/venv/bin/pip install -U pip`
- `/var/ossec/var/misp_worker/venv/bin/pip install requests redis pyyaml`

Copy worker:

- `install -m 0750 worker/misp_worker.py /var/ossec/integrations/misp_worker.py`

## 4) Config

Copy example env/config:

- `cp config/misp_worker.env.example /var/ossec/etc/misp_worker.env`
- `chmod 0640 /var/ossec/etc/misp_worker.env`
- Edit values:
  - `MISP_BASE_URL` must point to `.../attributes/restSearch`
  - `MISP_API_KEY`
  - TLS verify (`MISP_VERIFY`)

Optional (extractors override):
- `cp config/misp_extractors.yml.example /var/ossec/etc/misp_extractors.yml`

## 5) Wazuh integration entry

In `/var/ossec/etc/ossec.conf` add:

```xml
<integration>
  <name>custom-misp-forwarder</name>
  <group>to_misp</group>
  <alert_format>json</alert_format>
</integration>
```

Restart manager:

- `systemctl restart wazuh-manager`

## 6) systemd service for the worker

Install the unit file:

- `cp systemd/wazuh-misp-worker.service /etc/systemd/system/wazuh-misp-worker.service`
- Ensure `EnvironmentFile=/var/ossec/etc/misp_worker.env` is set inside the unit.

Enable and start:

- `systemctl daemon-reload`
- `systemctl enable --now wazuh-misp-worker`
- `systemctl status wazuh-misp-worker`

Reload worker after config change (SIGHUP):

- `systemctl reload wazuh-misp-worker`

## 7) Verify pipeline

1) Confirm Redis stream is receiving messages:
- `redis-cli XLEN wazuh:misp:in`
- `redis-cli XREVRANGE wazuh:misp:in + - COUNT 1`

2) Confirm worker is consuming:
- `redis-cli XINFO GROUPS wazuh:misp:in`
- `redis-cli XPENDING wazuh:misp:in misp`

3) Enable temporary tracing (optional):
- set `TRACE=1` and `HEARTBEAT_SEC=10` in env
- `systemctl restart wazuh-misp-worker`
- tail logs: `/var/ossec/logs/misp_worker.log`
