# Contributing

Thanks for taking the time to contribute! This project aims to provide a fast, reliable MISP enrichment pipeline for Wazuh using a C forwarder + Redis Streams + a persistent Python worker.

By contributing, you agree that your contributions will be licensed under the same license as this repository (**GNU AGPL v3**), unless explicitly stated otherwise in writing.

---

## Table of contents

- [Ways to contribute](#ways-to-contribute)
- [Before you start](#before-you-start)
- [Repository layout](#repository-layout)
- [Development setup](#development-setup)
  - [Forwarder (C)](#forwarder-c)
  - [Worker (Python)](#worker-python)
- [Configuration & examples](#configuration--examples)
- [Testing](#testing)
- [Coding style](#coding-style)
- [Commit & PR guidelines](#commit--pr-guidelines)
- [Security](#security)

---

## Ways to contribute

- **Bug reports** (repro steps + logs + expected vs actual)
- **Features** (new observable extraction paths, better MISP matching options, performance improvements)
- **Docs improvements** (clarify install/config/troubleshooting)
- **CI improvements** (linting, smoke tests)
- **Packaging** (RPM/DEB, container images)

---

## Before you start

### 1) Search existing issues
Please search open/closed issues before filing a new one.

### 2) Make your change minimal
Prefer focused PRs that solve one thing well.

### 3) Keep secrets out of the repo
Never commit:
- real `MISP_API_KEY`
- internal hostnames/IPs
- production alert samples containing sensitive data

Use the files in `config/*.example` and `examples/*.json` as sanitized templates.

---

## Repository layout

Typical layout:

- `forwarder/` — C forwarder (reads Wazuh alert JSON file path and enqueues to Redis Stream)
- `worker/` — Python worker (extract IoCs, cache/dedupe, query MISP, emit to Wazuh queue)
- `systemd/` — service unit for the worker
- `config/` — example env and extractors files
- `examples/` — sanitized alert examples
- `docs/` — architecture/install/config/troubleshooting/tuning

---

## Development setup

You can develop on a normal Linux machine (you do not need a full Wazuh install for most unit/smoke work).
For end-to-end testing you’ll want a Wazuh Manager and Redis.

### Requirements

- Python 3.9+ recommended
- Redis 6.2+ recommended (for `XAUTOCLAIM`)
- GCC + hiredis headers for the forwarder

---

## Forwarder (C)

### Build

From `forwarder/`:

```bash
make
```

Or manually:

```bash
gcc -O2 -o custom-misp-forwarder src/custom-misp-forwarder.c -lhiredis
```

### Local smoke test

1. Start Redis locally
2. Run the forwarder against a sample alert file in `examples/`

```bash
./custom-misp-forwarder ../examples/alert_sysmon_event3.json
redis-cli XREVRANGE wazuh:misp:in + - COUNT 1
```

You should see a record containing field `alert`.

---

## Worker (Python)

### Setup a virtualenv

From `worker/`:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

### Run the worker locally (without Wazuh)

The worker can run without Wazuh, but it will attempt to emit to the Wazuh UNIX socket.
For local-only testing you can:
- point `WAZUH_QUEUE` to a dummy UNIX datagram socket you create for testing, or
- temporarily disable the emit step in a local branch (do not commit that), or
- run it on a Wazuh Manager host.

Use the example env file:

```bash
cp ../config/misp_worker.env.example ./misp_worker.env
# edit MISP_BASE_URL and MISP_API_KEY if you want real MISP calls
set -a; . ./misp_worker.env; set +a
python misp_worker.py
```

---

## Configuration & examples

### `config/misp_worker.env.example`
- must not contain real credentials
- should document every env var with short comments

### `config/misp_extractors.yml.example`
- only supports observables: `ip`, `fqdn`, `hash` (`md5`/`sha1`/`sha256`)
- keep examples small and realistic
- add new extraction paths here when introducing new default support

### `examples/*.json`
- must be sanitized (no user identifiers, internal domains, sensitive paths)
- keep alerts realistic enough to exercise extractors

---

## Testing

We aim for at least the following checks on PRs:

### 1) Basic syntax checks
- Python compile:
  ```bash
  python -m compileall worker/misp_worker.py
  ```
- C build:
  ```bash
  make -C forwarder
  ```

### 2) Lint (recommended)
If the repo includes a linter setup (e.g., ruff/flake8), run it:

```bash
./scripts/lint.sh
```

### 3) Functional smoke test (recommended)
- Start Redis
- Enqueue an example alert using the forwarder
- Run the worker with `TRACE=1` and verify:
  - observables are extracted
  - MISP query payloads are correct
  - cached hits/misses behave as expected

---

## Coding style

### Python
- Prefer clear, defensive code (this is a security pipeline).
- Avoid heavy dependencies.
- Keep observable handling strict: only IP (public), FQDN, and hashes.
- Any new env vars must be documented in:
  - `config/misp_worker.env.example`
  - `docs/CONFIG.md`

### C
- Forwarder must remain minimal:
  - never call MISP
  - never block Wazuh
  - keep allocations bounded and timeouts short

### Docs
- Prefer “copy-paste runnable” command blocks.
- Keep examples sanitized.

---

## Commit & PR guidelines

### Branching
- Use feature branches (e.g., `fix-misp-restsearch`, `docs-tuning`).

### Commit messages
- Use descriptive messages:
  - `fix(worker): use POST restSearch and searchall fallback`
  - `docs: add troubleshooting for pending messages`

### Pull requests
Include in the PR description:
- What changed and why
- How to test (commands)
- Any config changes (env vars / extractors)
- Backward compatibility notes

### Review expectations
PRs may be asked to:
- reduce scope
- add docs/tests
- improve safety (timeouts, validation, error handling)

---

## Security

If you believe you found a security vulnerability, please do **not** open a public issue.
Instead, follow the instructions in `SECURITY.md` (or open a private security advisory on GitHub if enabled).
