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
# Version: 1.0
# License: AGPL v3.0 https://www.gnu.org/licenses/agpl-3.0.html


import os
import re
import json
import time
import signal
import logging
import threading
import queue
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional, Tuple, Union

import ipaddress
import requests
import redis

try:
    import yaml  # pyyaml
except Exception:
    yaml = None


# -----------------------------
# Env / config
# -----------------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
STREAM = os.getenv("REDIS_STREAM", "wazuh:misp:in")
GROUP = os.getenv("REDIS_GROUP", "misp")
CONSUMER = os.getenv("REDIS_CONSUMER", os.uname().nodename)

READ_COUNT = int(os.getenv("REDIS_READ_COUNT", "200"))
READ_BLOCK_MS = int(os.getenv("REDIS_BLOCK_MS", "1000"))

WORKER_THREADS = int(os.getenv("WORKER_THREADS", "8"))
QUEUE_MAX = int(os.getenv("QUEUE_MAX", "2000"))

DEDUP_TTL = int(os.getenv("DEDUP_TTL", "2"))
CACHE_HIT_TTL = int(os.getenv("CACHE_HIT_TTL", "3600"))
CACHE_MISS_TTL = int(os.getenv("CACHE_MISS_TTL", "600"))

# IMPORTANT: base host only (no /attributes/restSearch)
MISP_BASE_URL = os.getenv("MISP_BASE_URL", "").rstrip("/")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")
MISP_VERIFY_RAW = os.getenv("MISP_VERIFY", "1")
MISP_VERIFY: Any = False if MISP_VERIFY_RAW.lower() in ("0", "false", "no") else MISP_VERIFY_RAW
MISP_TIMEOUT_CONNECT = float(os.getenv("MISP_TIMEOUT_CONNECT", "0.5"))
MISP_TIMEOUT_READ = float(os.getenv("MISP_TIMEOUT_READ", "2.5"))

# How many attrs to keep when we do return details (hit)
MISP_MAX_ATTRS = int(os.getenv("MISP_MAX_ATTRS", "5"))

# Fast existence check: keep responses tiny (1 result is enough to know it matches)
MISP_FAST_LIMIT = int(os.getenv("MISP_FAST_LIMIT", "1"))
MISP_FAST_PAGE = int(os.getenv("MISP_FAST_PAGE", "1"))

# If you want always to fetch details directly, set MISP_FAST_LIMIT=0 (not recommended)
# If MISP_FAST_LIMIT > 0: we do a two-step query (fast check then details on hit)

WAZUH_QUEUE = os.getenv("WAZUH_QUEUE", "/var/ossec/queue/sockets/queue")

ACK_ON_MISP_ERROR = os.getenv("ACK_ON_MISP_ERROR", "1") in ("1", "true", "True")

PROCESS_PENDING_ON_START = os.getenv("PROCESS_PENDING_ON_START", "1") in ("1", "true", "True")
AUTOCLAIM_LOOP = os.getenv("AUTOCLAIM_LOOP", "0") in ("1", "true", "True")
AUTOCLAIM_IDLE_MS = int(os.getenv("AUTOCLAIM_IDLE_MS", "60000"))
AUTOCLAIM_COUNT = int(os.getenv("AUTOCLAIM_COUNT", "200"))

EXTRACTORS_FILE = os.getenv("EXTRACTORS_FILE", "/var/ossec/etc/misp_extractors.yml")

LOG_FILE = os.getenv("LOG_FILE", "/var/ossec/logs/misp_worker.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

HEARTBEAT_SEC = int(os.getenv("HEARTBEAT_SEC", "30"))
TRACE = os.getenv("TRACE", "0") in ("1", "true", "True")


# -----------------------------
# Logging
# -----------------------------
logger = logging.getLogger("misp_worker")
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
handler = RotatingFileHandler(LOG_FILE, maxBytes=20_000_000, backupCount=5, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(handler)


# -----------------------------
# Stop / reload handling
# -----------------------------
stop_evt = threading.Event()
reload_evt = threading.Event()


def _sigterm(_signo, _frame):
    stop_evt.set()


def _sighup(_signo, _frame):
    reload_evt.set()


signal.signal(signal.SIGTERM, _sigterm)
signal.signal(signal.SIGINT, _sigterm)
try:
    signal.signal(signal.SIGHUP, _sighup)
except Exception:
    pass


# -----------------------------
# Thread-local session (requests is NOT thread-safe)
# -----------------------------
_tls = threading.local()


def get_session() -> requests.Session:
    s = getattr(_tls, "session", None)
    if s is None:
        s = requests.Session()
        _tls.session = s
    return s


# -----------------------------
# Helpers: JSON access
# -----------------------------
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


# -----------------------------
# Observable validation
# -----------------------------
RE_FQDN = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_SYS_KV = re.compile(r"\b(MD5|SHA1|SHA256)=([A-Fa-f0-9]{32,64})\b")


def is_global_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s.strip())
        return ip.is_global
    except Exception:
        return False


def normalize_fqdn(s: str) -> Optional[str]:
    s = s.strip().strip(".").lower()
    if not s or len(s) > 253:
        return None
    if RE_FQDN.fullmatch(s):
        return s
    return None


def normalize_hash(t: str, v: str) -> Optional[Dict[str, str]]:
    vv = v.strip().lower()
    tt = t.strip().lower()
    if tt == "md5" and RE_MD5.fullmatch(vv):
        return {"type": "md5", "value": vv}
    if tt == "sha1" and RE_SHA1.fullmatch(vv):
        return {"type": "sha1", "value": vv}
    if tt == "sha256" and RE_SHA256.fullmatch(vv):
        return {"type": "sha256", "value": vv}
    return None


def parse_hashes(value: str, mode: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    s = value.strip()
    if not s:
        return out

    if mode == "sysmon_kv":
        for m in RE_SYS_KV.finditer(s):
            k = m.group(1).lower()
            hv = m.group(2).lower()
            n = normalize_hash(k, hv)
            if n:
                out.append(n)
        return out

    # auto
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
    seen = set()
    out = []
    for o in obs:
        k = f"{o['type']}:{o['value']}"
        if k in seen:
            continue
        seen.add(k)
        out.append(o)
    return out


# -----------------------------
# Extractors (defaults + YAML override)
# Only IP / FQDN / HASH
# -----------------------------
DEFAULT_EXTRACTORS = {
    "version": 1,
    "include_defaults": True,
    "stop_on_match": False,
    "rules": [
        {
            "name": "generic_ips",
            "when": {"groups_any": ["to_misp"]},
            "extract": [
                {
                    "type": "ip",
                    "path_any": [
                        "data.srcip", "data.dstip",
                        "srcip", "dstip",
                        "data.source.ip", "data.destination.ip",
                        "data.source_ip", "data.destination_ip",
                        "data.client.ip", "data.server.ip",
                        "data.win.eventdata.SourceIp", "data.win.eventdata.DestinationIp",
                    ],
                }
            ],
        },
        {
            "name": "generic_fqdn",
            "when": {"groups_any": ["to_misp"]},
            "extract": [
                {"type": "fqdn", "path_any": ["data.fqdn", "data.domain", "data.hostname"]},
            ],
        },
        {
            "name": "sysmon_event3_network",
            "when": {
                "groups_any": ["to_misp"],
                "decoder": "windows_eventchannel",
                "provider": "Microsoft-Windows-Sysmon",
                "event_id": "3",
            },
            "extract": [
                {"type": "ip", "path": "data.win.eventdata.SourceIp"},
                {"type": "ip", "path": "data.win.eventdata.DestinationIp"},
                {"type": "fqdn", "path": "data.win.eventdata.DestinationHostname"},
            ],
        },
        {
            "name": "sysmon_event22_dns",
            "when": {
                "groups_any": ["to_misp"],
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
                "groups_any": ["to_misp"],
                "decoder": "windows_eventchannel",
                "provider": "Microsoft-Windows-Sysmon",
            },
            "extract": [
                {"type": "hash", "path": "data.win.eventdata.Hashes", "mode": "sysmon_kv"},
            ],
        },
        {
            "name": "fim_syscheck_hashes",
            "when": {"groups_any": ["to_misp", "syscheck"]},
            "extract": [
                {"type": "sha256", "path_any": ["syscheck.sha256_after", "syscheck.sha256_before"]},
                {"type": "sha1", "path_any": ["syscheck.sha1_after", "syscheck.sha1_before"]},
                {"type": "md5", "path_any": ["syscheck.md5_after", "syscheck.md5_before"]},
            ],
        },
    ],
}


def match_when(alert: Dict[str, Any], when: Dict[str, Any]) -> bool:
    groups = (alert.get("rule", {}) or {}).get("groups", []) or []
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
    cfg = DEFAULT_EXTRACTORS

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
    stop_on_match = bool(y.get("stop_on_match", cfg.get("stop_on_match", False)))
    rules = y.get("rules", [])
    if not isinstance(rules, list):
        rules = []

    if include_defaults:
        return {
            "version": 1,
            "include_defaults": True,
            "stop_on_match": stop_on_match,
            "rules": (cfg.get("rules", []) or []) + rules,
        }

    return {
        "version": 1,
        "include_defaults": False,
        "stop_on_match": stop_on_match,
        "rules": rules,
    }


def extract_observables(alert: Dict[str, Any], cfg: Dict[str, Any]) -> List[Dict[str, str]]:
    obs: List[Dict[str, str]] = []
    stop_on_match = bool(cfg.get("stop_on_match", False))

    for rule in cfg.get("rules", []) or []:
        when = rule.get("when", {}) or {}
        if not match_when(alert, when):
            continue

        for ex in rule.get("extract", []) or []:
            t = str(ex.get("type", "")).strip().lower()
            mode = str(ex.get("mode", "auto")).strip().lower()

            paths: List[str] = []
            if "path" in ex:
                paths = [str(ex["path"])]
            elif "path_any" in ex:
                paths = [str(p) for p in (ex.get("path_any") or [])]

            values: List[str] = []
            for p in paths:
                v = deep_get(alert, p)
                for it in as_list(v):
                    if isinstance(it, str) and it.strip():
                        values.append(it.strip())

            if t == "ip":
                # Only global IPs
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


# -----------------------------
# Redis keys (cache/dedupe)
# -----------------------------
def k_dedupe(o: Dict[str, str]) -> str:
    return f"misp:dedupe:{o['type']}:{o['value']}"


def k_cache(o: Dict[str, str]) -> str:
    return f"misp:cache:{o['type']}:{o['value']}"


# -----------------------------
# MISP query (POST /attributes/restSearch)
# -----------------------------
MispTypeFilter = Union[str, Dict[str, List[str]]]


def map_to_misp_type_filter(o_type: str) -> Optional[MispTypeFilter]:
    """
    Patch: instead of forcing ip -> ip-src only, use OR filter over all IP-related types.
    Keep it narrow (few indexed types) to avoid performance penalties.
    """
    t = o_type.lower()

    if t == "ip":
        # Minimal: ["ip-src", "ip-dst"]
        # Extended (safe in most deployments): add composite types
        return {"OR": ["ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain|ip"]}

    if t == "fqdn":
        # Optional but recommended: many deployments store hostnames separately
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
    url = f"{MISP_BASE_URL}/attributes/restSearch"
    payload: Dict[str, Any] = {"returnFormat": "json", "value": value}

    # Paginazione / limit sono supportati (framework-friendly page/limit). :contentReference[oaicite:1]{index=1}
    if limit is not None and limit > 0:
        payload["limit"] = int(limit)
        payload["page"] = int(page or 1)

    # Type can be a string or {"OR":[...]} for multi-type filtering. :contentReference[oaicite:2]{index=2}
    if type_filter is not None:
        payload["type"] = type_filter

    r = session.post(
        url,
        headers={
            "Authorization": MISP_API_KEY,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json=payload,
        verify=MISP_VERIFY,
        timeout=(MISP_TIMEOUT_CONNECT, MISP_TIMEOUT_READ),
    )
    r.raise_for_status()
    data = r.json()

    resp = data.get("response")
    if isinstance(resp, dict):
        attrs = resp.get("Attribute")
        if isinstance(attrs, list):
            return [a for a in attrs if isinstance(a, dict)]
        return []
    if isinstance(resp, list):
        return [a for a in resp if isinstance(a, dict)]
    return []


def misp_query_value(session: requests.Session, value: str, otype: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Patched behavior:
      - Use an OR type filter for IP & FQDN to avoid missing ip-dst / hostname.
      - Use a fast existence check with limit=1, then (on hit) fetch details up to MISP_MAX_ATTRS.
    """
    tf = map_to_misp_type_filter(otype) if otype else None

    # Fast check (tiny response). If MISP_FAST_LIMIT <= 0, skip and fetch details directly.
    if MISP_FAST_LIMIT and MISP_FAST_LIMIT > 0:
        quick = misp_restsearch(
            session,
            value=value,
            type_filter=tf,
            limit=MISP_FAST_LIMIT,
            page=MISP_FAST_PAGE,
        )
        if not quick:
            return []

        # On hit, fetch details (limited) for enrichment.
        details = misp_restsearch(
            session,
            value=value,
            type_filter=tf,
            limit=max(MISP_MAX_ATTRS, 1),
            page=1,
        )
        return details[:MISP_MAX_ATTRS]

    # Legacy single-shot (not recommended in high-volume setups)
    details = misp_restsearch(session, value=value, type_filter=tf, limit=max(MISP_MAX_ATTRS, 1), page=1)
    return details[:MISP_MAX_ATTRS]


def slim_attrs(attrs: List[Dict[str, Any]], max_n: int) -> List[Dict[str, Any]]:
    out = []
    for a in attrs[:max_n]:
        out.append({
            "event_id": a.get("event_id"),
            "category": a.get("category"),
            "type": a.get("type"),
            "value": a.get("value"),
            "to_ids": a.get("to_ids"),
        })
    return out


# -----------------------------
# Wazuh output
# -----------------------------
def send_wazuh_event(payload: Dict[str, Any], agent: Optional[Dict[str, Any]]) -> None:
    try:
        msg = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if not agent or str(agent.get("id", "000")) in ("", "000", "None"):
            line = f"1:misp:{msg}"
        else:
            line = f"1:[{agent.get('id')}] ({agent.get('name','')}) {agent.get('ip','any')}->misp:{msg}"

        import socket as pysock
        s = pysock.socket(pysock.AF_UNIX, pysock.SOCK_DGRAM)
        s.connect(WAZUH_QUEUE)
        s.send(line.encode("utf-8"))
        s.close()
    except Exception as e:
        logger.warning("send_wazuh_event failed: %s", str(e))


# -----------------------------
# Redis stream ops
# -----------------------------
def ensure_group(r: redis.Redis) -> None:
    try:
        r.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        logger.info("Created consumer group=%s stream=%s", GROUP, STREAM)
    except redis.exceptions.ResponseError:
        pass


def xautoclaim(r: redis.Redis, min_idle_ms: int, count: int = 200) -> List[Tuple[str, Dict[str, str]]]:
    try:
        res = r.execute_command("XAUTOCLAIM", STREAM, GROUP, CONSUMER, min_idle_ms, "0-0", "COUNT", count)
        msgs = res[1] if isinstance(res, (list, tuple)) and len(res) >= 2 else []
        out = []
        for msg_id, fields in msgs:
            if isinstance(fields, dict):
                out.append((msg_id, fields))
        return out
    except Exception:
        return []


def get_group_status(r: redis.Redis) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    ldid = None
    stream_len = None
    pending = None
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
        groups = r.xinfo_groups(STREAM)
        if isinstance(groups, list):
            for g in groups:
                if isinstance(g, dict) and g.get("name") == GROUP:
                    ldid = g.get("last-delivered-id")
                    break
    except Exception:
        pass
    return ldid, stream_len, pending


# -----------------------------
# Counters (thread-safe)
# -----------------------------
class Counters:
    def __init__(self):
        self.lock = threading.Lock()
        self.processed = 0
        self.observables = 0
        self.matched = 0
        self.unmatched = 0
        self.misp_queries = 0
        self.misp_errors = 0
        self.exceptions = 0

    def add(self, processed=0, observables=0, matched=0, unmatched=0, misp_queries=0, misp_errors=0, exceptions=0):
        with self.lock:
            self.processed += processed
            self.observables += observables
            self.matched += matched
            self.unmatched += unmatched
            self.misp_queries += misp_queries
            self.misp_errors += misp_errors
            self.exceptions += exceptions

    def snapshot_and_reset(self):
        with self.lock:
            snap = (self.processed, self.observables, self.matched, self.unmatched,
                    self.misp_queries, self.misp_errors, self.exceptions)
            self.processed = self.observables = self.matched = self.unmatched = 0
            self.misp_queries = self.misp_errors = self.exceptions = 0
            return snap


# -----------------------------
# Processing (executed by worker threads)
# -----------------------------
def process_message(
    r: redis.Redis,
    cfg: Dict[str, Any],
    msg_id: str,
    fields: Dict[str, str],
) -> Tuple[int, int, int, int, int, int, int]:
    """
    Returns:
      processed, observables, matched, unmatched, misp_queries, misp_errors, exceptions
    """
    raw = fields.get("alert")
    if not raw:
        r.xack(STREAM, GROUP, msg_id)
        return (1, 0, 0, 0, 0, 0, 0)

    try:
        alert = json.loads(raw)
    except Exception:
        r.xack(STREAM, GROUP, msg_id)
        return (1, 0, 0, 0, 0, 0, 0)

    groups = (alert.get("rule", {}) or {}).get("groups", []) or []
    if "to_misp" not in groups:
        r.xack(STREAM, GROUP, msg_id)
        return (1, 0, 0, 0, 0, 0, 0)

    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else None
    rule_desc = str((alert.get("rule", {}) or {}).get("description", ""))

    observables = extract_observables(alert, cfg)
    if TRACE:
        logger.info("TRACE msg=%s observables=%d %s", msg_id, len(observables), observables)

    if not observables:
        r.xack(STREAM, GROUP, msg_id)
        return (1, 0, 0, 0, 0, 0, 0)

    matched: List[Dict[str, Any]] = []
    unmatched: List[Dict[str, str]] = []
    misp_queries = 0
    misp_errors = 0

    session = get_session()

    for o in observables:
        # short dedupe
        try:
            if not r.set(k_dedupe(o), "1", nx=True, ex=DEDUP_TTL):
                continue
        except Exception:
            continue

        ck = k_cache(o)

        cached = None
        try:
            cached = r.get(ck)
        except Exception:
            cached = None

        if cached:
            if cached == "__MISS__":
                unmatched.append(o)
                continue
            try:
                matched.append({"observable": o, "misp": json.loads(cached)})
                continue
            except Exception:
                pass

        # Query MISP
        try:
            misp_queries += 1
            attrs = misp_query_value(session, o["value"], o["type"])
        except Exception as e:
            misp_errors += 1
            logger.warning("MISP error for %s:%s err=%s", o["type"], o["value"], str(e))
            send_wazuh_event({"integration": "misp", "error": str(e), "observable": o}, agent)

            if ACK_ON_MISP_ERROR:
                r.xack(STREAM, GROUP, msg_id)
                if TRACE:
                    logger.info("TRACE msg=%s ack_on_misp_error=1 -> ack+return", msg_id)
                return (1, len(observables), len(matched), len(unmatched), misp_queries, misp_errors, 0)
            else:
                if TRACE:
                    logger.info("TRACE msg=%s ack_on_misp_error=0 -> return without ack", msg_id)
                return (1, len(observables), len(matched), len(unmatched), misp_queries, misp_errors, 0)

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
        logger.info("TRACE msg=%s matched=%d unmatched=%d misp_queries=%d misp_errors=%d",
                    msg_id, len(matched), len(unmatched), misp_queries, misp_errors)

    if matched:
        out = {
            "integration": "misp",
            "source": {
                "rule_id": deep_get(alert, "rule.id"),
                "rule_description": rule_desc,
                "decoder": deep_get(alert, "decoder.name"),
            },
            "matched": matched,
        }
        send_wazuh_event(out, agent)

    r.xack(STREAM, GROUP, msg_id)
    return (1, len(observables), len(matched), len(unmatched), misp_queries, misp_errors, 0)


# -----------------------------
# Worker thread loop
# -----------------------------
def worker_loop(name: str, q: queue.Queue, r: redis.Redis, cfg_ref: Dict[str, Any], counters: Counters):
    logger.info("Thread %s started", name)
    while not stop_evt.is_set() or not q.empty():
        try:
            item = q.get(timeout=0.5)
        except queue.Empty:
            continue

        msg_id, fields = item
        try:
            cfg = cfg_ref["cfg"]
            res = process_message(r, cfg, msg_id, fields)
            counters.add(
                processed=res[0],
                observables=res[1],
                matched=res[2],
                unmatched=res[3],
                misp_queries=res[4],
                misp_errors=res[5],
                exceptions=res[6],
            )
        except Exception as e:
            counters.add(processed=1, exceptions=1)
            logger.error("Thread %s error msg_id=%s err=%s", name, msg_id, str(e))
            try:
                # fail-safe: ack to avoid infinite pending build-up
                r.xack(STREAM, GROUP, msg_id)
            except Exception:
                pass
        finally:
            q.task_done()
    logger.info("Thread %s stopping", name)


# -----------------------------
# Main reader loop
# -----------------------------
def main():
    if not MISP_BASE_URL or not MISP_API_KEY:
        raise SystemExit("MISP_BASE_URL e MISP_API_KEY sono obbligatori (usa /var/ossec/etc/misp_worker.env)")

    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    ensure_group(r)

    cfg_ref = {"cfg": load_extractors()}
    logger.info(
        "Worker started MT consumer=%s stream=%s group=%s rules=%d threads=%d queue_max=%d trace=%s hb=%ds fast_limit=%s",
        CONSUMER, STREAM, GROUP, len(cfg_ref["cfg"].get("rules", []) or []),
        WORKER_THREADS, QUEUE_MAX, str(TRACE), HEARTBEAT_SEC, str(MISP_FAST_LIMIT)
    )

    q: queue.Queue = queue.Queue(maxsize=QUEUE_MAX)
    counters = Counters()

    # Start worker threads
    threads = []
    for i in range(WORKER_THREADS):
        t = threading.Thread(
            target=worker_loop,
            args=(f"w{i+1}", q, r, cfg_ref, counters),
            daemon=True,
        )
        t.start()
        threads.append(t)

    # Reclaim pending on start (safe because we keep inflight low)
    if PROCESS_PENDING_ON_START:
        reclaimed_total = 0
        while True:
            reclaimed = xautoclaim(r, min_idle_ms=0, count=500)  # reclaim all pending
            if not reclaimed:
                break
            for msg_id, fields in reclaimed:
                # enqueue with backpressure
                while not stop_evt.is_set():
                    try:
                        q.put((msg_id, fields), timeout=0.5)
                        reclaimed_total += 1
                        break
                    except queue.Full:
                        continue
        if reclaimed_total:
            logger.info("Reclaimed pending on start: %d", reclaimed_total)

    last_hb = time.time()
    last_claim = time.time()

    while not stop_evt.is_set():
        # Reload extractors on SIGHUP
        if reload_evt.is_set():
            cfg_ref["cfg"] = load_extractors()
            logger.info("Reloaded extractors rules=%d (file=%s)",
                        len(cfg_ref["cfg"].get("rules", []) or []), EXTRACTORS_FILE)
            reload_evt.clear()

        # Heartbeat
        now = time.time()
        if now - last_hb >= HEARTBEAT_SEC:
            ldid, stream_len, pending_cnt = get_group_status(r)
            snap = counters.snapshot_and_reset()
            logger.info(
                "HB stream_len=%s pending=%s last_delivered_id=%s qsize=%d | window processed=%d obs=%d matched=%d unmatched=%d misp_q=%d misp_err=%d exc=%d",
                stream_len, pending_cnt, ldid, q.qsize(),
                snap[0], snap[1], snap[2], snap[3], snap[4], snap[5], snap[6]
            )
            last_hb = now

        # Optional periodic autoclaim (OFF by default)
        if AUTOCLAIM_LOOP and (now - last_claim > 30):
            free_slots = QUEUE_MAX - q.qsize()
            if free_slots > 0:
                for msg_id, fields in xautoclaim(r, min_idle_ms=AUTOCLAIM_IDLE_MS, count=min(AUTOCLAIM_COUNT, free_slots)):
                    try:
                        q.put((msg_id, fields), timeout=0.2)
                    except queue.Full:
                        break
            last_claim = now

        # Backpressure: read only if we have free queue slots
        free_slots = QUEUE_MAX - q.qsize()
        if free_slots <= 0:
            time.sleep(0.05)
            continue

        count = min(READ_COUNT, free_slots)
        resp = r.xreadgroup(GROUP, CONSUMER, {STREAM: ">"}, count=count, block=READ_BLOCK_MS)
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

