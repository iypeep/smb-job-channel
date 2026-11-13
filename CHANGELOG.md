<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Changelog

## v1.0.0 — 2026-11-13

First public release. Everything below has been running against a real fleet before this tag.

### Channel
- `ah2` job envelope: AES-256-CBC/PKCS7 body + HMAC-SHA256 over a canonical string
  (id, kind, machine, ts, nonce, sha256(blob), timeout).
- Rejection is explicit and logged: `bad mac`, `ts out of window`, `replayed nonce`,
  `not for this machine`, `blob missing`.
- Encrypted results, verified before parsing; `aborted_by_watchdog` for jobs killed mid-flight.
- Multi-root delivery (primary + mirror share): done-id registry makes duplicates no-ops and the
  second copy is deleted; `pending` counts only real work.

### Agent
- Local beacon `state/hb.json` written every second — the health signal never depends on the share.
- Watchdog with two implementations: `omp-watch.ps1` (PowerShell) and `omp-watch.cs` (compiled,
  no PowerShell host in the supervision path). Kills a frozen body's tree, launcher respawns it,
  restart budget 12/h.
- `O_EXCL` lock, plus a periodic ownership check so an orphan instance exits instead of racing.
- Payloads (`inbox/files/<id>.*`) deleted when the job completes — they used to accumulate.

### Keys
- Per-machine seeds: `seed(M) = HKDF-SHA256(master, "omp/seed/" + MACHINE)`, then
  `K_mac/K_enc = HKDF-SHA256(seed, "omp/job-*")`. One compromised machine exposes one machine.
- Seed sealed at rest with DPAPI (`CurrentUser`, falling back to `LocalMachine`); a copied
  `settings.ini` is useless elsewhere.
- Dual-key rotation window (`keygen --rotate` + `rotatekey`) and per-machine upgrade
  (`upgradekey`), both idempotent and verified from plaintext stdout, not from the result file.

### Operator access
- Per-person tokens with machine allowlist (fnmatch), allowed job kinds, expiry, and audit of
  denials; an operator token with no `machines` can reach nothing.
- Owner-only: key material, machine allowlist, and the fleet-wide pause (`policy/disabled.txt`).

### Docs
- `docs/protocol.md`, `docs/key-management.md`, `docs/licensing.md`.
- `skills/`: six reusable operating manuals (operator access, crypto, key migration, self-healing,
  release sanitising, license selection), each with a human `README.md` and an agent `SKILL.md`.

### Licence
AGPL-3.0-or-later, or a commercial licence for closed-source use (401219981@qq.com).
