#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  ____  _            _   _      _                      _
# |  _ \| |          | \ | |    | |                    | |
# | |_) | |_   _  ___|  \| | ___| |___      _____  _ __| | _____
# |  _ <| | | | |/ _ \ . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ / __|
# | |_) | | |_| |  __/ |\  |  __/ |_ \ V  V / (_) | |  |   <\__ \
# |____/|_|\__,_|\___|_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\___/
#
# -= Scalable MISP Integration :: Wazuh Worker =-
# Github @bluenetita
# Version: 1.7
# License: AGPL v3.0 https://www.gnu.org/licenses/agpl-3.0.html
#
# Fixes vs 1.0:
#   [BUG-1] Removed hard-coded "to_misp" group gate in process_message -- all alerts
#           are now processed; extractor rules control what gets extracted per alert.
#   [BUG-2] Removed "groups_any: to_misp" from all default generic extractor rules so
#           they actually fire on all alerts after BUG-1 fix.
#           fim_syscheck_hashes keeps "syscheck" as the discriminating group.
#   [BUG-3] load_extractors() used a direct reference to DEFAULT_EXTRACTORS, risking
#           mutation of the module-level default on subsequent reloads. Fixed with
#           copy.deepcopy().
#   [BUG-4] socket import moved to module level.
#   [BUG-5] On ACK_ON_MISP_ERROR=False returned processed=1 even though message was
#           not acked. Fixed to return processed=0.
#   [BUG-6] agent fields (id, name, ip) could be None, producing "None" strings.
#           Fixed with explicit fallbacks.
#   [BUG-7] MISP_FAST_LIMIT redundant double-check cleaned up.
#
# Changes vs 1.1:
#   [FEAT-1] Periodic stream trimming added to heartbeat loop.
#            XACK removes messages from the PEL but NOT from the stream itself.
#            Every STREAM_TRIM_INTERVAL_SEC the worker calls XTRIM MAXLEN ~ STREAM_MAXLEN.
#            Set STREAM_MAXLEN=0 to disable.
#
# Changes vs 1.2:
#   [FEAT-2] Dead-letter stream for permanently failed messages.
#            Per-message retry counter tracked in Redis (misp:retries:<msg_id>,
#            TTL = DLQ_RETRY_TTL_SEC). After DLQ_MAX_RETRIES MISP errors the message
#            is written to DLQ_STREAM (default wazuh:misp:dead) with the original
#            fields plus dlq_reason / dlq_retries / dlq_ts / dlq_src_id metadata,
#            then acked from the main stream so the PEL stays clean.
#            Set DLQ_MAX_RETRIES=0 to disable (legacy ACK_ON_MISP_ERROR behaviour).
#
#   [FEAT-3] MISP circuit breaker.
#            Consecutive MISP errors across all worker threads are counted in a shared
#            thread-safe counter. Once CB_OPEN_THRESHOLD is reached the circuit opens:
#            worker threads skip MISP queries and leave the affected messages pending.
#            After CB_RESET_SEC seconds the circuit half-opens and exactly one probe is
#            allowed through. On success the circuit closes and pending work is reclaimed;
#            on failure it reopens for another CB_RESET_SEC.
#            Set CB_OPEN_THRESHOLD=0 to disable the circuit breaker entirely.
#
#   [FEAT-4] Graceful HTTP session cleanup on shutdown.
#            Worker threads call session.close() when their loop exits so TCP
#            connections to MISP are properly torn down instead of being left half-open.
#
# Changes vs 1.3:
#   [FEAT-5] Flat summary fields added to the Wazuh event payload.
#            Wazuh's $(field) interpolation in rule <description> tags only resolves
#            root-level decoded fields. The nested matched[]/misp[] array structure
#            was causing description fields to render blank in alerts.
#            send_wazuh_event() now emits flat root-level keys alongside the existing
#            nested structure (which is preserved for OpenSearch/dashboards):
#              misp_observable_value  -- IOC value of the first match
#              misp_observable_type   -- observable type (ip, fqdn, md5, ...)
#              misp_event_id          -- MISP event ID of the first attribute hit
#              misp_category          -- MISP attribute category of the first hit
#              misp_ioc_type          -- MISP attribute type of the first hit
#              misp_source_rule       -- description of the Wazuh rule that triggered
#              misp_match_count       -- total number of matched observables
#            Wazuh rules can now use e.g.:
#              <description>MISP Hit | $(misp_observable_type): $(misp_observable_value)
#                           | Event #$(misp_event_id) | $(misp_category)
#                           | Source: $(misp_source_rule)</description>
#
# Changes vs 1.4:
#   [BUG-8] Nested enrichment fields moved below misp_context. Generic root keys
#           such as source and matched can already be mapped as keywords in a
#           Wazuh daily index, causing OpenSearch to reject the whole alert when
#           the worker later emits objects at those paths.
#   [FEAT-5] Added Falco fd.sip/fd.cip decoded paths to the built-in IP extractor.
#
# Changes vs 1.5:
#   [BUG-9] Preserve failed messages until their DLQ retry threshold is reached,
#           and acknowledge them only after a successful DLQ write.
#   [BUG-10] Advance the XAUTOCLAIM cursor during pending-message recovery.
#   [BUG-11] Enforce one bounded half-open circuit-breaker probe.
#
# Changes vs 1.6:
#   [POLICY-1] Leave messages pending while the circuit breaker prevents a MISP
#              query, then reclaim them when the breaker is ready to recover.


import copy
import os
import re
import json
import socket as pysock
import time
import signal
import logging
import threading
import queue
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

import ipaddress
import requests
import redis

try:
    import yaml  # pyyaml
except Exception:
    yaml = None


# -----------------------------------------------------------------------
# Env / config
# -----------------------------------------------------------------------
REDIS_URL        = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
STREAM           = os.getenv("REDIS_STREAM", "wazuh:misp:in")
GROUP            = os.getenv("REDIS_GROUP", "misp")
CONSUMER         = os.getenv("REDIS_CONSUMER", os.uname().nodename)

READ_COUNT       = int(os.getenv("REDIS_READ_COUNT", "200"))
READ_BLOCK_MS    = int(os.getenv("REDIS_BLOCK_MS", "1000"))

WORKER_THREADS   = int(os.getenv("WORKER_THREADS", "8"))
QUEUE_MAX        = int(os.getenv("QUEUE_MAX", "2000"))

DEDUP_TTL        = int(os.getenv("DEDUP_TTL", "2"))
CACHE_HIT_TTL    = int(os.getenv("CACHE_HIT_TTL", "3600"))
CACHE_MISS_TTL   = int(os.getenv("CACHE_MISS_TTL", "600"))

# IMPORTANT: base host only, no trailing path
MISP_BASE_URL    = os.getenv("MISP_BASE_URL", "").rstrip("/")
MISP_API_KEY     = os.getenv("MISP_API_KEY", "")
MISP_VERIFY_RAW  = os.getenv("MISP_VERIFY", "1")
MISP_VERIFY: Any = False if MISP_VERIFY_RAW.lower() in ("0", "false", "no") else MISP_VERIFY_RAW
MISP_TIMEOUT_CONNECT = float(os.getenv("MISP_TIMEOUT_CONNECT", "0.5"))
MISP_TIMEOUT_READ    = float(os.getenv("MISP_TIMEOUT_READ", "2.5"))

MISP_MAX_ATTRS   = int(os.getenv("MISP_MAX_ATTRS", "5"))
MISP_FAST_LIMIT  = int(os.getenv("MISP_FAST_LIMIT", "1"))
MISP_FAST_PAGE   = int(os.getenv("MISP_FAST_PAGE", "1"))

WAZUH_QUEUE      = os.getenv("WAZUH_QUEUE", "/var/ossec/queue/sockets/queue")

ACK_ON_MISP_ERROR        = os.getenv("ACK_ON_MISP_ERROR", "1") in ("1", "true", "True")
PROCESS_PENDING_ON_START = os.getenv("PROCESS_PENDING_ON_START", "1") in ("1", "true", "True")
AUTOCLAIM_LOOP           = os.getenv("AUTOCLAIM_LOOP", "1") in ("1", "true", "True")
AUTOCLAIM_IDLE_MS        = int(os.getenv("AUTOCLAIM_IDLE_MS", "60000"))
AUTOCLAIM_COUNT          = int(os.getenv("AUTOCLAIM_COUNT", "200"))

EXTRACTORS_FILE  = os.getenv("EXTRACTORS_FILE", "/var/ossec/etc/misp_extractors.yml")
LOG_FILE         = os.getenv("LOG_FILE", "/var/ossec/logs/misp_worker.log")
LOG_LEVEL        = os.getenv("LOG_LEVEL", "INFO").upper()
HEARTBEAT_SEC    = int(os.getenv("HEARTBEAT_SEC", "30"))
TRACE            = os.getenv("TRACE", "0") in ("1", "true", "True")

# [FEAT-1] Stream trimming
STREAM_MAXLEN            = int(os.getenv("STREAM_MAXLEN", "500000"))
STREAM_TRIM_INTERVAL_SEC = int(os.getenv("STREAM_TRIM_INTERVAL_SEC", str(HEARTBEAT_SEC)))

# [FEAT-2] Dead-letter queue
DLQ_STREAM        = os.getenv("DLQ_STREAM", "wazuh:misp:dead")
DLQ_MAX_RETRIES   = int(os.getenv("DLQ_MAX_RETRIES", "5"))
DLQ_RETRY_TTL_SEC = int(os.getenv("DLQ_RETRY_TTL_SEC", "3600"))

# [FEAT-3] Circuit breaker
CB_OPEN_THRESHOLD = int(os.getenv("CB_OPEN_THRESHOLD", "10"))
CB_RESET_SEC      = int(os.getenv("CB_RESET_SEC", "60"))


# -----------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------
logger = logging.getLogger("misp_worker")
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
_log_handler = RotatingFileHandler(LOG_FILE, maxBytes=20_000_000, backupCount=5, encoding="utf-8")
_log_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(_log_handler)


# -----------------------------------------------------------------------
# Signals
# -----------------------------------------------------------------------
stop_evt   = threading.Event()
reload_evt = threading.Event()


def _sigterm(_signo, _frame):
    stop_evt.set()


def _sighup(_signo, _frame):
    reload_evt.set()


signal.signal(signal.SIGTERM, _sigterm)
signal.signal(signal.SIGINT,  _sigterm)
try:
    signal.signal(signal.SIGHUP, _sighup)
except Exception:
    pass


# -----------------------------------------------------------------------
# [FEAT-3] Circuit breaker
# -----------------------------------------------------------------------
class CircuitBreaker:
    """
    Three-state circuit breaker: CLOSED -> OPEN -> HALF_OPEN -> CLOSED.

    CLOSED   : Normal operation. Consecutive error counter increments per MISP failure.
               Trips to OPEN when counter >= threshold.
    OPEN     : MISP queries are skipped entirely. Messages remain pending without
               consuming a DLQ retry or being classified as unmatched.
               Transitions to HALF_OPEN after reset_sec seconds.
    HALF_OPEN: Exactly one probe thread is allowed through (one bounded permit).
               Success -> CLOSED + counter reset.
               Failure -> OPEN for another reset_sec.
    """
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"

    def __init__(self, threshold: int, reset_sec: int):
        self._lock       = threading.Lock()
        self._threshold  = threshold
        self._reset_sec  = reset_sec
        self._state      = self.CLOSED
        self._errors     = 0
        self._opened_at  = 0.0
        self._probe_sem  = threading.BoundedSemaphore(1)

    @property
    def enabled(self) -> bool:
        return self._threshold > 0

    def admit_query(self) -> Tuple[bool, bool]:
        """Return whether a query may run and whether it owns the probe permit."""
        if not self.enabled:
            return True, False
        with self._lock:
            if self._state == self.CLOSED:
                return True, False
            if self._state == self.OPEN:
                if time.time() - self._opened_at < self._reset_sec:
                    return False, False
                self._state = self.HALF_OPEN
                logger.info("CircuitBreaker half-open -- probing MISP")
            is_probe = self._probe_sem.acquire(blocking=False)
            return is_probe, is_probe

    def recovery_ready(self) -> bool:
        """Return whether pending work may be reclaimed without circuit churn."""
        if not self.enabled:
            return True
        with self._lock:
            if self._state == self.CLOSED:
                return True
            if self._state == self.HALF_OPEN:
                return False
            return time.time() - self._opened_at >= self._reset_sec

    def release_probe(self):
        self._probe_sem.release()

    def record_success(self):
        if not self.enabled:
            return
        with self._lock:
            prev         = self._state
            self._errors = 0
            self._state  = self.CLOSED
        if prev != self.CLOSED:
            logger.info("CircuitBreaker closed -- MISP is reachable again")

    def record_failure(self):
        if not self.enabled:
            return
        with self._lock:
            self._errors += 1
            if self._state == self.HALF_OPEN:
                self._state     = self.OPEN
                self._opened_at = time.time()
                logger.warning("CircuitBreaker reopened after failed probe")
            elif self._state == self.CLOSED and self._errors >= self._threshold:
                self._state     = self.OPEN
                self._opened_at = time.time()
                logger.warning(
                    "CircuitBreaker opened after %d consecutive MISP errors -- "
                    "queries suspended for %ds",
                    self._errors, self._reset_sec,
                )

    @property
    def state(self) -> str:
        with self._lock:
            return self._state


circuit_breaker = CircuitBreaker(CB_OPEN_THRESHOLD, CB_RESET_SEC)


# -----------------------------------------------------------------------
# Thread-local HTTP session  (requests.Session is NOT thread-safe)
# -----------------------------------------------------------------------
_tls = threading.local()


def get_session() -> requests.Session:
    s = getattr(_tls, "session", None)
    if s is None:
        s = requests.Session()
        _tls.session = s
    return s


def close_session():
    """[FEAT-4] Close the thread-local session to release TCP connections."""
    s = getattr(_tls, "session", None)
    if s is not None:
        try:
            s.close()
        except Exception:
            pass
        _tls.session = None


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------
def deep_get(obj: Dict[str, Any], path: str) -> Optional[Any]:
    cur: Any = obj
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


# -----------------------------------------------------------------------
# Observable validation
# -----------------------------------------------------------------------
RE_FQDN   = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
RE_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_SYS_KV = re.compile(r"\b(MD5|SHA1|SHA256)=([A-Fa-f0-9]{32,64})\b")


def is_global_ip(s: str) -> bool:
    try:
        return ipaddress.ip_address(s.strip()).is_global
    except Exception:
        return False


def normalize_fqdn(s: str) -> Optional[str]:
    s = s.strip().strip(".").lower()
    if not s or len(s) > 253:
        return None
    return s if RE_FQDN.fullmatch(s) else None


def normalize_hash(t: str, v: str) -> Optional[Dict[str, str]]:
    vv, tt = v.strip().lower(), t.strip().lower()
    if tt == "md5"    and RE_MD5.fullmatch(vv):    return {"type": "md5",    "value": vv}
    if tt == "sha1"   and RE_SHA1.fullmatch(vv):   return {"type": "sha1",   "value": vv}
    if tt == "sha256" and RE_SHA256.fullmatch(vv): return {"type": "sha256", "value": vv}
    return None


def parse_hashes(value: str, mode: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    s = value.strip()
    if not s:
        return out
    if mode == "sysmon_kv":
        for m in RE_SYS_KV.finditer(s):
            n = normalize_hash(m.group(1).lower(), m.group(2).lower())
            if n:
                out.append(n)
        return out
    # auto: longest patterns first so SHA-256 is never mistaken for MD5/SHA-1
    for m in re.findall(r"\b[a-fA-F0-9]{64}\b", s):
        n = normalize_hash("sha256", m)
        if n:
            out.append(n)
    for m in re.findall(r"\b[a-fA-F0-9]{40}\b", s):
        n = normalize_hash("sha1", m)
        if n:
            out.append(n)
    for m in re.findall(r"\b[a-fA-F0-9]{32}\b", s):
        n = normalize_hash("md5", m)
        if n:
            out.append(n)
    return out


def dedupe_obs(obs: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen: set = set()
    out = []
    for o in obs:
        k = f"{o['type']}:{o['value']}"
        if k not in seen:
            seen.add(k)
            out.append(o)
    return out


# -----------------------------------------------------------------------
# Extractors (built-in defaults + optional YAML override)
# -----------------------------------------------------------------------
DEFAULT_EXTRACTORS: Dict[str, Any] = {
    "version": 1,
    "include_defaults": True,
    "stop_on_match": False,
    "rules": [
        {
            "name": "generic_ips",
            "when": {},  # matches all alerts
            "extract": [{
                "type": "ip",
                "path_any": [
                    "data.srcip", "data.dstip",
                    "srcip", "dstip",
                    "data.source.ip", "data.destination.ip",
                    "data.source_ip", "data.destination_ip",
                    "data.client.ip", "data.server.ip",
                    "data.output_fields.fd.sip", "data.output_fields.fd.cip",
                    "data.win.eventdata.SourceIp", "data.win.eventdata.DestinationIp",
                ],
            }],
        },
        {
            "name": "generic_fqdn",
            "when": {},
            "extract": [
                {"type": "fqdn", "path_any": ["data.fqdn", "data.domain", "data.hostname"]},
            ],
        },
        {
            "name": "sysmon_event3_network",
            "when": {
                "decoder": "windows_eventchannel",
                "provider": "Microsoft-Windows-Sysmon",
                "event_id": "3",
            },
            "extract": [
                {"type": "ip",   "path": "data.win.eventdata.SourceIp"},
                {"type": "ip",   "path": "data.win.eventdata.DestinationIp"},
                {"type": "fqdn", "path": "data.win.eventdata.DestinationHostname"},
            ],
        },
        {
            "name": "sysmon_event22_dns",
            "when": {
                "decoder": "windows_eventchannel",
                "provider": "Microsoft-Windows-Sysmon",
                "event_id": "22",
            },
            "extract": [
                {"type": "fqdn", "path": "data.win.eventdata.QueryName"},
            ],
        },
        {
            "name": "sysmon_hashes_any",
            "when": {
                "decoder": "windows_eventchannel",
                "provider": "Microsoft-Windows-Sysmon",
            },
            "extract": [
                {"type": "hash", "path": "data.win.eventdata.Hashes", "mode": "sysmon_kv"},
            ],
        },
        {
            "name": "fim_syscheck_hashes",
            "when": {"groups_any": ["syscheck"]},
            "extract": [
                {"type": "sha256", "path_any": ["syscheck.sha256_after", "syscheck.sha256_before"]},
                {"type": "sha1",   "path_any": ["syscheck.sha1_after",   "syscheck.sha1_before"]},
                {"type": "md5",    "path_any": ["syscheck.md5_after",    "syscheck.md5_before"]},
            ],
        },
    ],
}


def match_when(alert: Dict[str, Any], when: Dict[str, Any]) -> bool:
    if not when:
        return True
    groups     = (alert.get("rule", {}) or {}).get("groups", []) or []
    groups_any = when.get("groups_any")
    if groups_any and not any(g in groups for g in as_list(groups_any)):
        return False
    decoder = when.get("decoder")
    if decoder and deep_get(alert, "decoder.name") != decoder:
        return False
    provider = when.get("provider")
    if provider and deep_get(alert, "data.win.system.providerName") != provider:
        return False
    event_id = when.get("event_id")
    if event_id is not None:
        got = deep_get(alert, "data.win.system.eventID")
        if got is None or str(got) != str(event_id):
            return False
    return True


def load_extractors() -> Dict[str, Any]:
    cfg = copy.deepcopy(DEFAULT_EXTRACTORS)  # [BUG-3] never mutate the module-level default
    if not yaml:
        return cfg
    try:
        with open(EXTRACTORS_FILE, "r", encoding="utf-8") as f:
            y = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return cfg
    except Exception as e:
        logger.warning("Cannot load extractors file=%s err=%s. Using defaults.", EXTRACTORS_FILE, str(e))
        return cfg
    include_defaults = bool(y.get("include_defaults", True))
    stop_on_match    = bool(y.get("stop_on_match", cfg.get("stop_on_match", False)))
    rules = y.get("rules", [])
    if not isinstance(rules, list):
        rules = []
    if include_defaults:
        return {
            "version": 1, "include_defaults": True, "stop_on_match": stop_on_match,
            "rules": (cfg.get("rules", []) or []) + rules,
        }
    return {"version": 1, "include_defaults": False, "stop_on_match": stop_on_match, "rules": rules}


def extract_observables(alert: Dict[str, Any], cfg: Dict[str, Any]) -> List[Dict[str, str]]:
    obs: List[Dict[str, str]] = []
    stop_on_match = bool(cfg.get("stop_on_match", False))
    for rule in cfg.get("rules", []) or []:
        when = rule.get("when", {}) or {}
        if not match_when(alert, when):
            continue
        for ex in rule.get("extract", []) or []:
            t    = str(ex.get("type", "")).strip().lower()
            mode = str(ex.get("mode", "auto")).strip().lower()
            paths: List[str] = []
            if "path" in ex:
                paths = [str(ex["path"])]
            elif "path_any" in ex:
                paths = [str(p) for p in (ex.get("path_any") or [])]
            values: List[str] = []
            for p in paths:
                for it in as_list(deep_get(alert, p)):
                    if isinstance(it, str) and it.strip():
                        values.append(it.strip())
            if t == "ip":
                for v in values:
                    if is_global_ip(v):
                        obs.append({"type": "ip", "value": v})
            elif t == "fqdn":
                for v in values:
                    fq = normalize_fqdn(v)
                    if fq:
                        obs.append({"type": "fqdn", "value": fq})
            elif t in ("md5", "sha1", "sha256"):
                for v in values:
                    n = normalize_hash(t, v)
                    if n:
                        obs.append(n)
            elif t == "hash":
                for v in values:
                    obs.extend(parse_hashes(v, mode=mode))
        if stop_on_match:
            break
    return dedupe_obs(obs)


# -----------------------------------------------------------------------
# Redis keys
# -----------------------------------------------------------------------
def k_dedupe(o: Dict[str, str]) -> str:
    return f"misp:dedupe:{o['type']}:{o['value']}"

def k_cache(o: Dict[str, str]) -> str:
    return f"misp:cache:{o['type']}:{o['value']}"

def k_retries(msg_id: str) -> str:
    return f"misp:retries:{msg_id}"


# -----------------------------------------------------------------------
# MISP REST query
# -----------------------------------------------------------------------
MispTypeFilter = Union[str, Dict[str, List[str]]]


def map_to_misp_type_filter(o_type: str) -> Optional[MispTypeFilter]:
    t = o_type.lower()
    if t == "ip":
        return {"OR": ["ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain|ip"]}
    if t == "fqdn":
        return {"OR": ["domain", "hostname"]}
    if t in ("md5", "sha1", "sha256"):
        return t
    return None


def misp_restsearch(
    session: requests.Session,
    value: str,
    type_filter: Optional[MispTypeFilter] = None,
    limit: Optional[int] = None,
    page: Optional[int] = None,
) -> List[Dict[str, Any]]:
    payload: Dict[str, Any] = {"returnFormat": "json", "value": value}
    if limit is not None and limit > 0:
        payload["limit"] = int(limit)
        payload["page"]  = int(page or 1)
    if type_filter is not None:
        payload["type"] = type_filter
    resp = session.post(
        f"{MISP_BASE_URL}/attributes/restSearch",
        headers={
            "Authorization": MISP_API_KEY,
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        },
        json=payload,
        verify=MISP_VERIFY,
        timeout=(MISP_TIMEOUT_CONNECT, MISP_TIMEOUT_READ),
    )
    resp.raise_for_status()
    data = resp.json()
    r = data.get("response")
    if isinstance(r, dict):
        attrs = r.get("Attribute")
        return [a for a in attrs if isinstance(a, dict)] if isinstance(attrs, list) else []
    if isinstance(r, list):
        return [a for a in r if isinstance(a, dict)]
    return []


def misp_query_value(
    session: requests.Session,
    value: str,
    otype: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Two-step query when MISP_FAST_LIMIT > 0 (default).
    Calls circuit_breaker.record_success() on clean return.
    Raises on error so the caller can call circuit_breaker.record_failure().
    """
    tf = map_to_misp_type_filter(otype) if otype else None
    if MISP_FAST_LIMIT > 0:
        quick = misp_restsearch(session, value=value, type_filter=tf,
                                limit=MISP_FAST_LIMIT, page=MISP_FAST_PAGE)
        if not quick:
            circuit_breaker.record_success()
            return []
        details = misp_restsearch(session, value=value, type_filter=tf,
                                  limit=max(MISP_MAX_ATTRS, 1), page=1)
        circuit_breaker.record_success()
        return details[:MISP_MAX_ATTRS]
    details = misp_restsearch(session, value=value, type_filter=tf,
                              limit=max(MISP_MAX_ATTRS, 1), page=1)
    circuit_breaker.record_success()
    return details[:MISP_MAX_ATTRS]


def slim_attrs(attrs: List[Dict[str, Any]], max_n: int) -> List[Dict[str, Any]]:
    return [
        {
            "event_id": a.get("event_id"),
            "category": a.get("category"),
            "type":     a.get("type"),
            "value":    a.get("value"),
            "to_ids":   a.get("to_ids"),
        }
        for a in attrs[:max_n]
    ]


# -----------------------------------------------------------------------
# Wazuh socket output
# -----------------------------------------------------------------------
def send_wazuh_event(payload: Dict[str, Any], agent: Optional[Dict[str, Any]]) -> None:
    try:
        msg      = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        logger.debug("send_wazuh_event payload=%s", msg)
        agent_id = str(agent.get("id") or "000") if agent else "000"
        if not agent or agent_id in ("", "000", "None"):
            line = f"1:misp:{msg}"
        else:
            agent_name = str(agent.get("name") or "")
            agent_ip   = str(agent.get("ip")   or "any")
            line = f"1:[{agent_id}] ({agent_name}) {agent_ip}->misp:{msg}"
        s = pysock.socket(pysock.AF_UNIX, pysock.SOCK_DGRAM)
        s.connect(WAZUH_QUEUE)
        s.send(line.encode("utf-8"))
        s.close()
    except Exception as e:
        logger.warning("send_wazuh_event failed: %s", str(e))


# -----------------------------------------------------------------------
# Redis stream helpers
# -----------------------------------------------------------------------
def ensure_group(r: redis.Redis) -> None:
    try:
        r.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        logger.info("Created consumer group=%s stream=%s", GROUP, STREAM)
    except redis.exceptions.ResponseError:
        pass


def xautoclaim(
    r: redis.Redis,
    min_idle_ms: int,
    start_id: str = "0-0",
    count: int = 200,
) -> Tuple[str, List[Tuple[str, Dict[str, str]]]]:
    try:
        claim_response = r.execute_command(
            "XAUTOCLAIM", STREAM, GROUP, CONSUMER,
            min_idle_ms, start_id, "COUNT", count,
        )
    except redis.exceptions.RedisError as error:
        logger.warning("XAUTOCLAIM failed: %s", error)
        return "0-0", []
    if not isinstance(claim_response, (list, tuple)) or len(claim_response) < 2:
        logger.warning("XAUTOCLAIM returned an unexpected response")
        return "0-0", []
    next_start_id = str(claim_response[0])
    messages = claim_response[1] if isinstance(claim_response[1], (list, tuple)) else []
    return next_start_id, [
        (message_id, fields)
        for message_id, fields in messages
        if isinstance(fields, dict)
    ]


def xautoclaim_scan(
    r: redis.Redis,
    min_idle_ms: int,
    count: int,
) -> Iterator[Tuple[str, Dict[str, str]]]:
    start_id = "0-0"
    while True:
        start_id, messages = xautoclaim(r, min_idle_ms, start_id, count)
        yield from messages
        if start_id == "0-0":
            return


def get_group_status(r: redis.Redis) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    ldid = stream_len = pending = None
    try:
        stream_len = r.xlen(STREAM)
    except Exception:
        pass
    try:
        pend = r.xpending(STREAM, GROUP)
        if isinstance(pend, dict):
            pending = pend.get("pending")
    except Exception:
        pass
    try:
        for g in (r.xinfo_groups(STREAM) or []):
            if isinstance(g, dict) and g.get("name") == GROUP:
                ldid = g.get("last-delivered-id")
                break
    except Exception:
        pass
    return ldid, stream_len, pending


def ack_message(r: redis.Redis, msg_id: str) -> None:
    r.xack(STREAM, GROUP, msg_id)
    try:
        r.delete(k_retries(msg_id))
    except redis.exceptions.RedisError as error:
        logger.warning("Retry cleanup failed msg_id=%s err=%s", msg_id, error)


def dlq_send(r: redis.Redis, msg_id: str, fields: Dict[str, str], reason: str, retries: int) -> None:
    """[FEAT-2] Write a permanently failed message to the dead-letter stream."""
    dlq_fields = dict(fields)
    dlq_fields.update({
        "dlq_reason":  reason,
        "dlq_retries": str(retries),
        "dlq_ts":      str(int(time.time())),
        "dlq_src_id":  msg_id,
    })
    r.xadd(DLQ_STREAM, dlq_fields)
    logger.warning("DLQ msg_id=%s retries=%d -> %s reason=%s",
                   msg_id, retries, DLQ_STREAM, reason)


# -----------------------------------------------------------------------
# Thread-safe counters
# -----------------------------------------------------------------------
class Counters:
    def __init__(self):
        self.lock        = threading.Lock()
        self.processed   = 0
        self.observables = 0
        self.matched     = 0
        self.unmatched   = 0
        self.misp_queries  = 0
        self.misp_errors   = 0
        self.exceptions    = 0
        self.dlq_total     = 0

    def add(self, processed=0, observables=0, matched=0, unmatched=0,
            misp_queries=0, misp_errors=0, exceptions=0, dlq=0):
        with self.lock:
            self.processed   += processed
            self.observables += observables
            self.matched     += matched
            self.unmatched   += unmatched
            self.misp_queries  += misp_queries
            self.misp_errors   += misp_errors
            self.exceptions    += exceptions
            self.dlq_total     += dlq

    def snapshot_and_reset(self) -> Tuple:
        with self.lock:
            snap = (
                self.processed, self.observables, self.matched, self.unmatched,
                self.misp_queries, self.misp_errors, self.exceptions, self.dlq_total,
            )
            self.processed = self.observables = self.matched = self.unmatched = 0
            self.misp_queries = self.misp_errors = self.exceptions = self.dlq_total = 0
            return snap


# -----------------------------------------------------------------------
# Core message processing (runs in worker threads)
# -----------------------------------------------------------------------
def process_message(
    r: redis.Redis,
    cfg: Dict[str, Any],
    msg_id: str,
    fields: Dict[str, str],
) -> Tuple[int, int, int, int, int, int, int, int]:
    """
    Returns: (processed, observables, matched, unmatched, misp_queries, misp_errors, exceptions, dlq)
    """
    raw = fields.get("alert")
    if not raw:
        logger.warning("Dropping message without alert field msg_id=%s", msg_id)
        ack_message(r, msg_id)
        return (1, 0, 0, 0, 0, 0, 1, 0)

    try:
        alert = json.loads(raw)
    except json.JSONDecodeError as error:
        logger.warning("Dropping invalid alert JSON msg_id=%s err=%s", msg_id, error)
        ack_message(r, msg_id)
        return (1, 0, 0, 0, 0, 0, 1, 0)
    if not isinstance(alert, dict):
        logger.warning("Dropping non-object alert JSON msg_id=%s", msg_id)
        ack_message(r, msg_id)
        return (1, 0, 0, 0, 0, 0, 1, 0)

    agent     = alert.get("agent") if isinstance(alert.get("agent"), dict) else None
    rule      = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    rule_desc = str(rule.get("description", ""))

    observables = extract_observables(alert, cfg)
    if TRACE:
        logger.info("TRACE msg=%s observables=%d %s", msg_id, len(observables), observables)

    if not observables:
        ack_message(r, msg_id)
        return (1, 0, 0, 0, 0, 0, 0, 0)

    matched: List[Dict[str, Any]]   = []
    unmatched: List[Dict[str, str]] = []
    misp_queries = misp_errors = 0
    session = get_session()

    for o in observables:
        # Short-window per-observable deduplication
        try:
            dedupe_key = k_dedupe(o)
            if (
                not r.set(dedupe_key, msg_id, nx=True, ex=DEDUP_TTL)
                and r.get(dedupe_key) != msg_id
                and r.get(k_retries(msg_id)) is None
            ):
                continue
        except redis.exceptions.RedisError as error:
            logger.warning("Dedupe unavailable msg_id=%s err=%s", msg_id, error)
            continue

        ck     = k_cache(o)
        cached = None
        try:
            cached = r.get(ck)
        except Exception:
            pass

        if cached is not None:
            if cached == "__MISS__":
                unmatched.append(o)
                continue
            try:
                matched.append({"observable": o, "misp": json.loads(cached)})
                continue
            except Exception:
                pass  # corrupted cache entry -- fall through to live query

        query_allowed, is_probe = circuit_breaker.admit_query()
        if not query_allowed:
            if TRACE:
                logger.info("TRACE msg=%s pending while circuit unavailable", msg_id)
            return (0, len(observables), len(matched), len(unmatched),
                    misp_queries, misp_errors, 0, 0)

        if is_probe:
            if TRACE:
                logger.info("TRACE msg=%s cb=half_open probing %s:%s",
                            msg_id, o["type"], o["value"])

        # Live MISP query
        try:
            misp_queries += 1
            attrs = misp_query_value(session, o["value"], o["type"])
            # record_success() called inside misp_query_value on clean return
        except Exception as e:
            misp_errors += 1
            circuit_breaker.record_failure()
            logger.warning("MISP error %s:%s err=%s cb=%s",
                           o["type"], o["value"], str(e), circuit_breaker.state)
            send_wazuh_event({"integration": "misp", "error": str(e), "observable": o}, agent)

            # [FEAT-2] Dead-letter queue: track retries per message
            if DLQ_MAX_RETRIES > 0:
                rk = k_retries(msg_id)
                try:
                    retries = int(r.incr(rk))
                    r.expire(rk, DLQ_RETRY_TTL_SEC)
                except redis.exceptions.RedisError as retry_error:
                    logger.error("Retry tracking failed msg_id=%s err=%s", msg_id, retry_error)
                    retries = 1

                if retries >= DLQ_MAX_RETRIES:
                    try:
                        dlq_send(r, msg_id, fields, reason=str(e), retries=retries)
                    except redis.exceptions.RedisError as dlq_error:
                        logger.error("DLQ write failed stream=%s err=%s", DLQ_STREAM, dlq_error)
                    else:
                        ack_message(r, msg_id)
                        return (1, len(observables), len(matched), len(unmatched),
                                misp_queries, misp_errors, 0, 1)
                else:
                    logger.info("MISP error msg_id=%s retry=%d/%d",
                                msg_id, retries, DLQ_MAX_RETRIES)
                if TRACE:
                    logger.info("TRACE msg=%s pending for DLQ retry", msg_id)
                return (0, len(observables), len(matched), len(unmatched),
                        misp_queries, misp_errors, 0, 0)

            if ACK_ON_MISP_ERROR:
                ack_message(r, msg_id)
                if TRACE:
                    logger.info("TRACE msg=%s ack_on_misp_error=1", msg_id)
                return (1, len(observables), len(matched), len(unmatched),
                        misp_queries, misp_errors, 0, 0)
            else:
                if TRACE:
                    logger.info("TRACE msg=%s ack_on_misp_error=0 no ack", msg_id)
                # processed=0: message was intentionally not acked and will be re-delivered
                return (0, len(observables), len(matched), len(unmatched),
                        misp_queries, misp_errors, 0, 0)
        finally:
            if is_probe:
                circuit_breaker.release_probe()

        if not attrs:
            try:
                r.set(ck, "__MISS__", ex=CACHE_MISS_TTL)
            except Exception:
                pass
            unmatched.append(o)
            continue

        slim = slim_attrs(attrs, MISP_MAX_ATTRS)
        try:
            r.set(ck, json.dumps(slim, ensure_ascii=False, separators=(",", ":")), ex=CACHE_HIT_TTL)
        except Exception:
            pass
        matched.append({"observable": o, "misp": slim})

    if TRACE:
        logger.info("TRACE msg=%s matched=%d unmatched=%d misp_q=%d misp_err=%d cb=%s",
                    msg_id, len(matched), len(unmatched), misp_queries, misp_errors,
                    circuit_breaker.state)

    if matched:
        first = matched[0]
        send_wazuh_event({
            "integration":           "misp",
            # [FEAT-5] Flat root-level fields for Wazuh rule $(field) interpolation.
            # Nested fields (matched[], source{}) are NOT resolvable in <description>
            # tags -- only top-level decoded keys work reliably.
            "misp_observable_value": first["observable"]["value"],
            "misp_observable_type":  first["observable"]["type"],
            "misp_event_id":         str(first["misp"][0].get("event_id", "")),
            "misp_category":         str(first["misp"][0].get("category", "")),
            "misp_ioc_type":         str(first["misp"][0].get("type", "")),
            "misp_source_rule":      rule_desc,
            "misp_match_count":      str(len(matched)),
            # Namespace nested data to avoid collisions with generic Wazuh fields.
            "misp_context": {
                "source": {
                    "rule_id":          deep_get(alert, "rule.id"),
                    "rule_description": rule_desc,
                    "decoder":          deep_get(alert, "decoder.name"),
                },
                "matched": matched,
            },
        }, agent)

    ack_message(r, msg_id)
    return (1, len(observables), len(matched), len(unmatched), misp_queries, misp_errors, 0, 0)


# -----------------------------------------------------------------------
# Worker thread
# -----------------------------------------------------------------------
def worker_loop(name: str, q: queue.Queue, r: redis.Redis,
                cfg_ref: Dict[str, Any], counters: Counters):
    logger.info("Thread %s started", name)
    while not stop_evt.is_set() or not q.empty():
        try:
            item = q.get(timeout=0.5)
        except queue.Empty:
            continue
        msg_id, fields = item
        try:
            res = process_message(r, cfg_ref["cfg"], msg_id, fields)
            counters.add(
                processed    = res[0],
                observables  = res[1],
                matched      = res[2],
                unmatched    = res[3],
                misp_queries = res[4],
                misp_errors  = res[5],
                exceptions   = res[6],
                dlq          = res[7],
            )
        except Exception as e:
            counters.add(exceptions=1)
            logger.error("Thread %s error msg_id=%s err=%s", name, msg_id, str(e))
        finally:
            q.task_done()
    # [FEAT-4] Properly close the thread-local HTTP session on shutdown
    close_session()
    logger.info("Thread %s stopped", name)


# -----------------------------------------------------------------------
# Main reader loop
# -----------------------------------------------------------------------
def main():
    if not MISP_BASE_URL or not MISP_API_KEY:
        raise SystemExit(
            "MISP_BASE_URL and MISP_API_KEY are required "
            "(set via /var/ossec/etc/misp_worker.env)"
        )

    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    ensure_group(r)

    cfg_ref  = {"cfg": load_extractors()}
    counters = Counters()

    logger.info(
        "Worker started consumer=%s stream=%s group=%s rules=%d threads=%d "
        "queue_max=%d trace=%s hb=%ds fast_limit=%s stream_maxlen=%s "
        "dlq_max_retries=%d cb_threshold=%d cb_reset=%ds",
        CONSUMER, STREAM, GROUP,
        len(cfg_ref["cfg"].get("rules", []) or []),
        WORKER_THREADS, QUEUE_MAX, str(TRACE), HEARTBEAT_SEC,
        str(MISP_FAST_LIMIT), str(STREAM_MAXLEN),
        DLQ_MAX_RETRIES, CB_OPEN_THRESHOLD, CB_RESET_SEC,
    )

    q: queue.Queue = queue.Queue(maxsize=QUEUE_MAX)

    threads = []
    for i in range(WORKER_THREADS):
        t = threading.Thread(
            target=worker_loop,
            args=(f"w{i+1}", q, r, cfg_ref, counters),
            daemon=True,
        )
        t.start()
        threads.append(t)

    # Reclaim any in-flight messages from a previous process instance
    if PROCESS_PENDING_ON_START:
        reclaimed_total = 0
        for msg_id, fields in xautoclaim_scan(r, min_idle_ms=0, count=500):
            while not stop_evt.is_set():
                try:
                    q.put((msg_id, fields), timeout=0.5)
                    reclaimed_total += 1
                    break
                except queue.Full:
                    continue
        if reclaimed_total:
            logger.info("Reclaimed pending on start: %d", reclaimed_total)

    last_hb    = time.time()
    last_claim = time.time()
    last_trim  = time.time()
    claim_cursor = "0-0"

    while not stop_evt.is_set():
        # Reload extractors on SIGHUP
        if reload_evt.is_set():
            cfg_ref["cfg"] = load_extractors()
            logger.info("Reloaded extractors rules=%d (file=%s)",
                        len(cfg_ref["cfg"].get("rules", []) or []), EXTRACTORS_FILE)
            reload_evt.clear()

        now = time.time()

        # Heartbeat log -- also reports circuit breaker state and DLQ counter
        if now - last_hb >= HEARTBEAT_SEC:
            ldid, stream_len, pending_cnt = get_group_status(r)
            snap = counters.snapshot_and_reset()
            logger.info(
                "HB stream_len=%s pending=%s last_delivered_id=%s qsize=%d cb=%s | "
                "window processed=%d obs=%d matched=%d unmatched=%d "
                "misp_q=%d misp_err=%d exc=%d dlq=%d",
                stream_len, pending_cnt, ldid, q.qsize(), circuit_breaker.state,
                snap[0], snap[1], snap[2], snap[3], snap[4], snap[5], snap[6], snap[7],
            )
            last_hb = now

        # [FEAT-1] Periodic stream trim
        if STREAM_MAXLEN > 0 and (now - last_trim >= STREAM_TRIM_INTERVAL_SEC):
            try:
                removed = r.xtrim(STREAM, maxlen=STREAM_MAXLEN, approximate=True)
                if removed and TRACE:
                    logger.info("TRACE stream_trim removed=%d maxlen=%d", removed, STREAM_MAXLEN)
            except Exception as e:
                logger.warning("stream trim failed: %s", e)
            last_trim = now

        # Periodic pending recovery waits until the circuit can accept work.
        if AUTOCLAIM_LOOP and (now - last_claim > 30):
            if circuit_breaker.recovery_ready():
                free_slots = QUEUE_MAX - q.qsize()
                if free_slots > 0:
                    claim_cursor, reclaimed = xautoclaim(
                        r,
                        min_idle_ms=AUTOCLAIM_IDLE_MS,
                        start_id=claim_cursor,
                        count=min(AUTOCLAIM_COUNT, free_slots),
                    )
                    for msg_id, fields in reclaimed:
                        try:
                            q.put((msg_id, fields), timeout=0.2)
                        except queue.Full:
                            break
            last_claim = now

        # Backpressure: only read when queue has room
        free_slots = QUEUE_MAX - q.qsize()
        if free_slots <= 0:
            time.sleep(0.05)
            continue

        count = min(READ_COUNT, free_slots)
        resp  = r.xreadgroup(GROUP, CONSUMER, {STREAM: ">"}, count=count, block=READ_BLOCK_MS)
        if not resp:
            continue

        _, messages = resp[0]
        for msg_id, fields in messages:
            while not stop_evt.is_set():
                try:
                    q.put((msg_id, fields), timeout=0.5)
                    break
                except queue.Full:
                    continue

    logger.info("Stopping reader; draining queue...")
    q.join()
    logger.info("Queue drained. Exiting.")


if __name__ == "__main__":
    main()
