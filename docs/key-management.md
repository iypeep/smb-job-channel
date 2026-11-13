<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
# Key management

Publishing the method is fine; publishing a key is not. This is the method.

## 1. Derivation

```
master      32 random bytes, controller only (ctl/omp.key, 0600)
seed(M)     HKDF-SHA256(master, info="omp/seed/" + MACHINE_UPPER, L=32)   per machine
K_mac(M)    HKDF-SHA256(seed(M), info="omp/job-mac", L=32)
K_enc(M)    HKDF-SHA256(seed(M), info="omp/job-enc", L=32)
```

HKDF is RFC 5869 with a zero salt (32 bytes), single-block expand for a 32-byte output. The agent
computes `K_mac`/`K_enc` from its own seed; it never sees the master, so one compromised machine
exposes one machine.

Legacy scheme (kept for migration): `K_mac = SHA-256(master ‖ "omp-job-mac")` fleet-wide; a body
without `KEY_SCHEME=hkdf2` uses it.

## 2. At rest on the agent

```powershell
Add-Type -AssemblyName System.Security          # PS 5.1 does not auto-load it
$blob = [Security.Cryptography.ProtectedData]::Protect($seed, $null, 'CurrentUser')
Set-Content settings.ini ('PSK_PROTECTED=' + [Convert]::ToBase64String($blob))
Set-Content settings.ini 'KEY_SCHEME=hkdf2' -Append
```

Unprotect at startup: `CurrentUser` first, then `LocalMachine` (agents started by a SYSTEM task).
A `settings.ini` copied to another account/machine yields nothing.

**Never write an empty blob**: if `Protect` fails, abort the provisioning and keep the previous
key. A machine with no key material at all falls back to legacy so it stays reachable (and logs
loudly); a keyed machine still refuses unsigned jobs.

## 3. Controller side

`submit()` resolves the machine's scheme from its heartbeat (`key_scheme`) and seals with
`machine_keys(machine, scheme)`. Result decryption tries the machine's scheme first, then the
legacy one, so a result written before/after a migration still opens.

## 4. Rotation

```
keygen --rotate          master_v2 minted; master_v1 parked as omp.key.prev (controller only)
rotatekey --machines …   sealed job signed with v1 writes PSK=v2; body restarts
verify                   sealed ping with v2 answers ok; the old key must answer bad mac
promote                  shred omp.key.prev once the fleet reports the new generation
```

`upgradekey` does the same for v1 → per-machine seeds and is idempotent.

Two gotchas, each worth a canary:

1. **Verify from `run/<id>.stdout.txt`, not the result file** — during a key change a result may
   be undecryptable on the controller, and treating that as "refused" reports false failures.
2. **`sealed.txt` is a second gate** — a machine with `psk=true` and a new enough body still gets
   an *unsigned* job if it is not in the allowlist, and a sealed-only body answers
   `rejected: unsigned job refused`. Add the machine before blaming the key.

## 5. Non-negotiables

| Rule | Why |
|---|---|
| Master never on the share, in the repo, or inside a job body | the share is readable by colleagues/IT; a repo is forever |
| Encrypt bodies even on an "internal" share | SMB here is signed but not encrypted |
| Verify result MAC before parsing | a writable share means results can be planted |
| Reject loudly on mac/ts/nonce/machine mismatch | silent fallback turns a channel into an execution service |
| One key per machine | blast radius |
| Log the *fact* of every job (id, machine, kind, who) | attribution is the point |

## 6. What a share reader can still learn

Job ids/kinds, timings, sizes, machine names, heartbeat fields, and the agent scripts. That is
operational metadata, and it is what lets a human answer "what is this machine doing" without the
key. Do not "fix" this by encrypting the beacon.
