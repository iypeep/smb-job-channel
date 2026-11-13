<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
# Wire format (`ah2`)

## 1. Job envelope — `machines/<M>/inbox/<id>.job.json`

```json
{"ah": 2, "id": "20260101-000000-abcd", "kind": "ps", "m": "MACHINE-001",
 "ts": 1794477291, "nonce": "<16 hex, CSPRNG>", "enc": "a256cbc-hmac256",
 "blob": "<id>.enc", "enc_res": 1, "timeout": 300, "mac": "<hex>"}
```

The script is not here: `inbox/files/<id>.enc` holds
`base64(IV ‖ AES-256-CBC(PKCS7(utf8(script))))`. A share reader learns id/kind/timing, not content.

### Canonical string to MAC

```
ah2|<id>|<kind>|<MACHINE upper>|<ts>|<nonce>|<sha256hex(blob text)>|<enc_res>|<timeout>
```

`timeout` is the empty string when absent; MAC = `HMAC-SHA256(K_mac, canon)` hex.

| Reject reason | Condition |
|---|---|
| `bad mac` | HMAC mismatch (wrong key, tampered field, wrong machine) |
| `ts out of window` | `\|now − ts\| > 900 s` |
| `replayed nonce` | nonce already in the local registry (last 2000) |
| `not for this machine` | `m` ≠ the body's claimed name |
| `blob missing` | `inbox/files/<id>.enc` unreadable |

Every rejection still writes a result (`status="rejected"`, `exit=97`).

## 2. Result — `machines/<M>/out/<id>.result.json`

```json
{"id": "…", "mac": "…", "enc": "a256cbc-hmac256", "blob": "base64(IV ‖ ciphertext)"}
```

Result MAC = `HMAC-SHA256(K_mac, "res|<id>|<b64 blob>")`. Decrypted JSON carries `id`, `status`,
`exit`, `duration_sec`, `_stdout`, `stderr_tail`. Statuses: `ok`, `error`, `timeout`, `partial`,
`rejected`, `bad_job`, `aborted_by_watchdog`.

## 3. Beacon — `machines/<M>/state/hb.json` (cleartext)

```json
{"pid": 1234, "ts": 1794477291, "iso": "2026-01-01T00:00:00", "loop": 42,
 "phase": "loop|claim|run|idle", "job_id": "", "job_kind": "", "jobs_done": 7, "hub_ok": true}
```

Cleartext is deliberate: watchdog, controller and humans judge health locally.

## 4. Directory layout

```
inbox/<id>.job.json      envelope
inbox/files/<id>.enc     encrypted script (deleted when the job completes)
inbox/push/<id>/…        pushed files (deleted with the job)
run/<id>.stdout.txt      streaming stdout
run/<id>.stderr.txt      streaming stderr
out/<id>.result.json     encrypted result
state/hb.json            beacon
state/watch.json         watchdog state (pid, restarts, last reason)
```

## 5. Failure semantics

| Situation | Behaviour |
|---|---|
| Body killed mid-job | lock settled at next start as `aborted_by_watchdog`, `exit=97`; never auto-retried |
| Share unavailable | 5 consecutive scan failures → body exits so the launcher restarts it clean |
| Two bodies on one box | `bridge.lock` (O_EXCL) decides; the loser exits |
| Job on several mirror roots | done-id registry no-ops the duplicate and deletes the copy |
| Beacon frozen | watchdog kills the tree; launcher respawns; budget 12/h, then backs off |

## 6. Compatibility

`ah=1` (legacy, unsigned) is accepted only when the body has no key and `ALLOW_LEGACY=1`.
Production should be sealed-only, otherwise anyone who can write the share can execute code.
