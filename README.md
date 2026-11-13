<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Commercial license](https://img.shields.io/badge/license-commercial%20available-informational)](NOTICE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab)](src/ompremote.py)

**English** · [简体中文](README.zh-CN.md)


A small, auditable **job channel that uses an SMB share as its control plane**: the controller
drops a signed+encrypted job into a folder, an agent on the target machine executes it and writes
back an encrypted result. Built for machines that have **no inbound network path and no outbound
internet**, but do have one writable file share.

No broker, no tunnel, no relay, no process injection, no driver. Files in, files out, with
authenticated encryption in between.


## Before you start: you need the share path

This repository contains **no share path, no hostnames, no keys** — they are site specific and a
wrong guess writes somewhere else. Ask the user for the UNC of the folder their machines can
already write (e.g. `\\server\share\_omp`), then pass `--hub` or set `OMP_REMOTE_HUB`.
Running without one stops with an explanation; that is the program asking you the same question.

Details: [docs/quickstart.md](docs/quickstart.md).

## Why

Factory/office machines often reach exactly one thing: a file server. What such a channel needs is
not speed but **attribution and integrity**: whoever can write the share must not be able to
execute code, whoever can read it must not see job bodies, and every action must be explainable
afterwards.

## How

```
controller (office)                        share                        agent (machine)
  src/ompremote.py  --- inbox/<id>.job.json + files/<id>.enc --->  omp-body.ps1
                    <-- out/<id>.result.json (encrypted) ---------  (poll, execute, report)
                    <-- state/hb.json (cleartext on purpose)
```

* Envelope `ah2`: AES-256-CBC/PKCS7 body + HMAC-SHA256 over a canonical string
  (id, kind, machine, ts, nonce, sha256(blob), timeout).
* Rejects on bad mac / ts outside ±900 s / replayed nonce / machine mismatch / missing blob.
* Results encrypted; a MAC mismatch is a refusal, never a best-effort parse.
* Beacon `state/hb.json` is written locally every second and stays **cleartext**, so watchdog,
  controller and humans judge health from one file.
* Watchdog (`omp-watch.cs`, compiled; `omp-watch.ps1` fallback) kills a body whose beacon stops
  moving and lets the launcher respawn it — a body blocked in an SMB call never exits, so
  "restart on exit" never fires.
* Keys: one master on the controller; each machine receives only its own HKDF seed, sealed at rest
  with DPAPI.

Protocol: [docs/protocol.md](docs/protocol.md). Keys: [docs/key-management.md](docs/key-management.md).

## Non-goals

- **Not a way to hide from IT.** The beacon, job list and audit log are readable on purpose.
- **No pivoting/relaying through other machines.**
- **No endpoint-security tampering**: no AV/EDR config edits, no whitelists from code, no
  injection, no kernel driver.
- No cloud dependency, no telemetry.

## Skills

Reusable operating manuals, one folder per skill — `README.md` is the human intro,
`SKILL.md` is what you hand to an agent. Index: [skills/README.md](skills/README.md).

| Skill | What it covers |
|---|---|
| [operator-access](skills/ompremote-operator-access/README.md) | per-person tokens: machine scope, allowed job kinds, expiry, audit |
| [share-channel-crypto](skills/ompremote-share-channel-crypto/README.md) | what to encrypt, what must stay readable, key hygiene and boundaries |
| [per-machine-key-migration](skills/ompremote-per-machine-key-migration/README.md) | one fleet key → per-machine HKDF seed + DPAPI, and four pitfalls |
| [bridge-selfheal](skills/ompremote-bridge-selfheal/README.md) | beacon on local disk, watchdog that kills a frozen body, duplicate instances |
| [sanitized-public-repo-release](skills/sanitized-public-repo-release/README.md) | turning an internal tool into a public repo without leaking anything |
| [github-license-recognition-and-dual-license](skills/github-license-recognition-and-dual-license/README.md) | which licenses GitHub recognises, and AGPL + commercial dual licensing |

## Try it

```bash
python src/ompremote.py selftest     # fake hub: run/exit/timeout/cwd/fetch/push/kill-switch/
                                     # duplicate-id/self-update/identity
```

## License

**Dual-licensed: AGPL-3.0-or-later, or a commercial license.**

- AGPL-3.0-or-later (default, in `LICENSE`): free for any use including commercial, provided
  you keep derivatives open — including offering source to users of a network service.
- Commercial license (401219981@qq.com): for closed-source use, internal deployment without
  AGPL obligations, or support.

See [LICENSE](LICENSE), [NOTICE](NOTICE) and [docs/licensing.md](docs/licensing.md).
