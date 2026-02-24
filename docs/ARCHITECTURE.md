# Architecture

This project adds fast, scalable MISP enrichment to Wazuh without running one-shot HTTP calls per alert.

## Components

### 1) Wazuh integration (trigger)
Wazuh `integratord` runs a custom integration for alerts whose rule group includes `to_misp`. At the time of writing, this Wazuh component is single threaded, it means that custom integrations need to be VERY FAST to scale in high EPS environments.

### 2) Forwarder (C)
The forwarder is intentionally “dumb and fast”:
- Input: Wazuh passes the path of the alert JSON file as argv[1]
- Action: reads the raw JSON and enqueues it into a Redis Stream (field: `alert`)
- Output: exits immediately (milliseconds)

**Design goal:** never block Wazuh on network calls to MISP.

### 3) Redis Stream (buffer + durability)
Redis Streams provide:
- backpressure buffer
- consumer groups (scale-out with multiple workers)
- pending list + reclaim (XAUTOCLAIM) for crash recovery

Stream message format (minimal):
- `alert`: JSON string (the entire Wazuh alert)

### 4) Worker (Python, persistent)
The worker:
1. reads messages from Redis Stream consumer group
2. extracts observables (ONLY): IP (public), FQDN, hash (md5/sha1/sha256)
3. applies:
   - short dedupe TTL (burst control)
   - cache TTL (hit/miss) to reduce MISP traffic
4. queries MISP (POST `/attributes/restSearch`)
   - primary: `{"value": "<ioc>"}`
   - optional fallback: `{"searchall": "%<ioc>%"}`
5. emits an aggregated enrichment event back to Wazuh via UNIX datagram socket:
   `/var/ossec/queue/sockets/queue`

## Data flow

Wazuh alert (to_misp)
  └─> forwarder (C)
       └─> Redis Stream: wazuh:misp:in (field alert="<json>")
            └─> worker (Python)
                 ├─> extract observables
                 ├─> cache/dedupe
                 ├─> query MISP (restSearch)
                 └─> send enrichment event to Wazuh queue socket

## Delivery semantics

- Stream consumption is effectively **at-least-once**.
- Duplicate enrichment is controlled by:
  - dedupe TTL (short)
  - cache TTL (hit/miss)

## What "to_misp" means

`to_misp` is a routing flag only:
- it means “send this alert into the enrichment pipeline”
- it does **not** imply the alert contains a specific field such as `data.srcip`

## Config-driven extraction

The worker includes a built-in default extractor set to support:
- generic default decoder IP fields (src/dst variants)
- Sysmon FQDN and hashes
- FIM/syscheck hashes

Optionally, you can extend/override extraction with `/var/ossec/etc/misp_extractors.yml`.

## Failure behavior

- If Redis is unavailable: forwarder should fail closed (Wazuh continues; enrichment is skipped).
- If MISP is slow/down:
  - with `ACK_ON_MISP_ERROR=1`, the worker acks the message and continues (no backlog buildup).
  - with `ACK_ON_MISP_ERROR=0`, the message remains pending for retry (risk of backlog growth).

## Observability

- Worker logs heartbeat (stream len/pending/last delivered id) every `HEARTBEAT_SEC`.
- With `TRACE=1`, logs per-message extracted observables and MISP query payloads (very verbose).