<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Quickstart

## 0. Before anything: get the share path from the user

This repository intentionally contains **no share path, no host name and no key**. They are site
specific, and a wrong guess silently writes to the wrong place.

Ask the user for:

| What | Example | Why |
|---|---|---|
| The share folder the machines can already **write** | `\\server\share\_omp` | it is the control plane; the agent cannot invent it |
| A machine name you are allowed to drive | `MACHINE-001` | this is the identity in the envelope, not the hostname |
| Whether you may run jobs at all (token/role) | operator / viewer | see `skills/ompremote-operator-access` |

If the command says `no hub configured`, that is the program asking you the same question.

## 1. Point the controller at it

```bash
# per command
python src/ompremote.py --hub '\\server\share\_omp' machines

# or once, per shell
set OMP_REMOTE_HUB=\\server\share\_omp        # Windows (cmd)
$env:OMP_REMOTE_HUB = '\\server\share\_omp'  # Windows (PowerShell)
export OMP_REMOTE_HUB=\\server\share\_omp     # bash
```

Optional second root (mirror share, same content): `--hub` stays primary, add the mirror in
`Hub.mirrors` or leave it out. Redundancy is optional.

## 2. First run, in order

```bash
python src/ompremote.py machines                 # who has ever checked in
python src/ompremote.py selftest                 # protocol test on a fake hub (no machines)
python src/ompremote.py ping MACHINE-001         # capability probe
python src/ompremote.py health MACHINE-001 --verbose
```

`machines` on an empty but reachable share prints nothing — the agent on the machine creates its
own folder on first start. If the share is reachable but empty, nothing is wrong yet.

## 3. Keys

There is no key in the repository. Generate one **on the controller only**:

```bash
python src/ompremote.py keygen                   # writes ctl/omp.key (never share it)
python src/ompremote.py secure --machines MACHINE-001   # provision the machine (legacy job)
```

Then move machines to per-machine seeds (`upgradekey`) once they report the new body version.
Details and pitfalls: [key-management.md](key-management.md).

## 4. What "works" looks like

```bash
python src/ompremote.py run MACHINE-001 -e 'Write-Output ("hi from " + $env:COMPUTERNAME)'
# --- MACHINE-001: ps ok exit=0 (1s) ---
# hi from MACHINE-001
```

If you get `rejected: bad mac` the keys differ (or the machine is in the allowlist but not the
key). If you get `rejected: unsigned job refused`, the machine is sealed-only and you are not in
`sealed.txt`. Both are explained in [key-management.md](key-management.md#4-rotation).
