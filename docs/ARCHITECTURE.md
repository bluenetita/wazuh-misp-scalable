# Architecture

This project adds fast, scalable MISP enrichment to Wazuh without running one-shot HTTP calls per alert.

## Components

### 1) Wazuh integration (trigger)
Wazuh `integratord` runs custom integrations. At the time of writing, this Wazuh component is single threaded, it means that custom integrations need to be VERY FAST to scale in high EPS environments.

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
- pending list + cursor-based reclaim (XAUTOCLAIM) for crash recovery

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

Wazuh alert
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
- A retry of the same stream message can pass its own dedupe key; a separate
  message for the same observable remains deduplicated.


## Config-driven extraction

The worker includes a built-in default extractor set to support:
- generic default decoder IP fields (src/dst variants)
- Sysmon FQDN and hashes
- FIM/syscheck hashes

Optionally, you can extend/override extraction with `/var/ossec/etc/misp_extractors.yml`.

## Failure behavior

- If Redis is unavailable: forwarder should fail closed (Wazuh continues; enrichment is skipped).
- If a MISP query fails:
  - with `DLQ_MAX_RETRIES>0`, the message remains pending until the retry threshold;
  - at the threshold, the worker writes to `DLQ_STREAM` before acknowledging the source;
  - if the DLQ write fails, the source remains pending;
  - with `DLQ_MAX_RETRIES=0`, `ACK_ON_MISP_ERROR` controls whether the worker drops
    or retains the failed message.
- Missing, invalid, or non-object alert JSON is logged and explicitly acknowledged.
- Unexpected processing exceptions are logged and left pending.
- Startup recovery advances the `XAUTOCLAIM` cursor until Redis returns `0-0`.
- While the circuit is open, the existing outage policy skips MISP and
  acknowledges the message as unmatched. Half-open state admits one probe at a time.

## Observability

- Worker logs heartbeat (stream len/pending/last delivered id) every `HEARTBEAT_SEC`.
- With `TRACE=1`, logs per-message extracted observables and MISP query payloads (very verbose).
