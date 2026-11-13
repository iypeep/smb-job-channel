<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# smb-job-channel

A small, auditable **job channel that uses an SMB share as its control plane**: the controller
drops a signed+encrypted job into a folder, an agent on the target machine executes it and writes
back an encrypted result. Built for machines that have **no inbound network path and no outbound
internet**, but do have one writable file share.

No broker, no tunnel, no relay, no process injection, no driver. Files in, files out, with
authenticated encryption in between.

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
