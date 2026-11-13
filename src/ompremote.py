#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# -*- coding: utf-8 -*-
"""ompremote - remote control of factory machines over the TBZ public share.

The machines have no route to a model, so they do not think: `omp-body.ps1` on
the machine executes what we send and streams results back. The agent (me / omp)
stays on this box and only needs the share to reach them.

    python ompremote.py machines
    python ompremote.py ping MACHINE-003
    python ompremote.py run  MACHINE-003 -e "Get-Process | Select -First 5"
    python ompremote.py run  MACHINE-003 -f collect.ps1 --cwd "D:\\Debug" --timeout 600
    python ompremote.py fetch MACHINE-003 -p "D:\\Debug\\Log\\*.log" --dest .\\pulled
    python ompremote.py push  MACHINE-003 -s .\\tool.exe -d "C:\\Temp\\tool.exe"
    python ompremote.py tail  MACHINE-003 20261021-1530-ab12 --watch
    python ompremote.py ask   MACHINE-003 "…"      # only if that machine has omp + model access

Hub root: \\\\192.0.2.10\\share\\TBZ\\_omp
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime

# There is deliberately NO default share path in this repository: it is environment specific
# and publishing it would leak an internal path. The operator must supply it:
#   python src/ompremote.py --hub '\\server\share\_omp' machines
#   set OMP_REMOTE_HUB=\\server\share\_omp          (Windows)
#   export OMP_REMOTE_HUB=\\server\share\_omp       (bash)
# An agent should ASK THE USER for this path (the folder the machines can already write),
# never guess or reuse one found in a log.
DEFAULT_HUB = ""

# Mirrors of the same logical channel. Only one file server is reachable from the
# production VLANs, so redundancy today is share-level: if one share is locked, slow
# or full the machine keeps working through another. Add a host here the day a second
# server answers from the shop floor.
# Redundancy today is folder-level, and that is the honest ceiling: only
# 192.0.2.10 answers SMB from the production VLANs (measured 2026-11-07 by scanning
# 192.0.2.10/20 + 10.41.152.0/22 and probing shares - 192.0.2.10 has shares but the
# machines cannot route to it, and the other writable shares on .128 belong to other
# people's projects). A second root in our own share still covers the realistic
# failures: the tree deleted or ACL-locked by accident, or one folder filling up.
# When IT ever gives us a second server, append its UNC here - nothing else changes.
# Optional second root (a mirror share): same rule - supplied by the user, not hardcoded.
DEFAULT_MIRRORS: list[str] = []

HUB_ENV = "OMP_REMOTE_HUB"


def hub_env():
    """Hub override: OMP_REMOTE_HUB (long-standing), else OMP_HUB."""
    return (os.environ.get("OMP_REMOTE_HUB") or os.environ.get("OMP_HUB") or "").strip() or None


def load_psk():
    """Pre-shared key (32 bytes hex): OMP_PSK, else ctl\\omp.key. Never on the share."""
    env = os.environ.get("OMP_PSK", "").strip()
    raw = env
    if not raw:
        kf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "omp.key")
        if os.path.isfile(kf):
            raw = open(kf, "r", encoding="ascii").read().strip()
    if not raw:
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        die("omp.key / OMP_PSK is not valid hex")


def load_prev_psk():
    """Previous key, kept only while a rotation is in flight (ctl\\omp.key.prev)."""
    kf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "omp.key.prev")
    if not os.path.isfile(kf):
        return None
    raw = open(kf, "r", encoding="ascii").read().strip()
    try:
        return bytes.fromhex(raw)
    except ValueError:
        die("omp.key.prev is not valid hex")


PSK = load_psk()
SECRET = PSK is not None
K_MAC = hashlib.sha256(PSK + b"omp-job-mac").digest() if SECRET else None
K_ENC = hashlib.sha256(PSK + b"omp-job-enc").digest() if SECRET else None

# rotation: the fleet is moved machine by machine, so for a while some bodies only know the
# old key. Every seal/open therefore takes a key and falls back to the previous one.
def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 (salt = 32 zero bytes, as the spec prescribes for an empty salt)."""
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def machine_scheme(hub, machine: str) -> str:
    """'hkdf2' when the body reports the per-machine scheme, else the legacy fleet-wide one."""
    d = os.path.join(hub.root, "machines", machine, "state", "heartbeat.json")
    hb = read_json(d) or {}
    sch = str(hb.get("key_scheme") or "").strip().lower()
    return sch if sch else "v1"


def machine_keys(machine: str, scheme: str = "v1", which: str = "cur"):
    """(K_mac, K_enc) for one machine.

    hkdf2: seed = HKDF(master, "omp/seed/" + MACHINE); K_* = HKDF(seed, "omp/job-*").
    The machine only ever holds the seed, so one compromised box does not yield the master.
    """
    master = PSK if which == "cur" else PSK_PREV
    if master is None:
        die("no key for that direction (rotation needs both omp.key and omp.key.prev)")
    m = machine.upper().encode("utf-8")
    if scheme == "hkdf2":
        seed = hkdf_sha256(master, b"omp/seed/" + m, 32)
        return hkdf_sha256(seed, b"omp/job-mac", 32), hkdf_sha256(seed, b"omp/job-enc", 32)
    return (hashlib.sha256(master + b"omp-job-mac").digest(),
            hashlib.sha256(master + b"omp-job-enc").digest())


PSK_PREV = load_prev_psk()
K_MAC_PREV = hashlib.sha256(PSK_PREV + b"omp-job-mac").digest() if PSK_PREV else None
K_ENC_PREV = hashlib.sha256(PSK_PREV + b"omp-job-enc").digest() if PSK_PREV else None
ROTATED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rotated.txt")


def _aes():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    return Cipher, algorithms, modes, padding


def aes_encrypt(key, plain: bytes) -> str:
    """AES-256-CBC/PKCS7 -> base64(IV || ciphertext). Matches Protect-Bytes in the body."""
    Cipher, algorithms, modes, padding = _aes()
    pad = padding.PKCS7(128).padder()
    data = pad.update(plain) + pad.finalize()
    iv = os.urandom(16)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    data = enc.update(data) + enc.finalize()
    return base64.b64encode(iv + data).decode("ascii")


def aes_decrypt(key, b64: str) -> bytes:
    Cipher, algorithms, modes, padding = _aes()
    raw = base64.b64decode(b64)
    iv, ct = raw[:16], raw[16:]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    data = dec.update(ct) + dec.finalize()
    un = padding.PKCS7(128).unpadder()
    return un.update(data) + un.finalize()


def seal_job(jid, kind, machine, body, timeout=None, enc_res=1, key="cur", scheme=None):
    """Wrap the real job body into a signed, encrypted envelope.

    key="cur" is the live key, key="prev" the one a not-yet-rotated body still has.
    """
    k_mac, k_enc = machine_keys(machine, scheme or "v1", key)
    if k_enc is None:
        die("no key for that direction (rotation needs both omp.key and omp.key.prev)")
    ts = int(time.time())
    nonce = binascii.hexlify(os.urandom(8)).decode()
    blob = aes_encrypt(k_enc, json.dumps(body, ensure_ascii=False).encode("utf-8"))
    sha = hashlib.sha256(blob.encode("ascii")).hexdigest()
    to_s = "" if timeout is None else str(int(timeout))
    canon = "|".join(["ah2", jid, kind, machine.upper(), str(ts), nonce, sha, str(int(enc_res)), to_s])
    mac = hmac.new(k_mac, canon.encode("utf-8"), hashlib.sha256).hexdigest()
    env = {"ah": 2, "id": jid, "kind": kind, "m": machine, "ts": ts, "nonce": nonce,
           "enc": "a256cbc-hmac256", "blob": jid + ".enc", "enc_res": int(enc_res),
           "mac": mac}
    if timeout is not None:
        env["timeout"] = int(timeout)
    return env, blob


def _ver_tuple(v: str):
    """'2.5.1-556eb55f' -> (2, 5, 1); a build suffix must not truncate the comparison."""
    out = []
    for part in (v or "").split("."):
        m = re.match(r"\d+", part.strip())
        if not m:
            break
        out.append(int(m.group(0)))
    return tuple(out)


def machine_body_version(hub, machine: str) -> str:
    for r in hub.roots():
        d = read_json(os.path.join(r, "machines", machine, "state", "heartbeat.json")) or {}
        v = str(d.get("body_version") or "").strip()
        if v:
            return v
    return ""


def seal_list():
    """ctl/sealed.txt = machine names cleared for sealed jobs ('ALL' unlocks the fleet)."""
    f = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sealed.txt")
    if not os.path.isfile(f):
        return set()
    return {l.strip().upper() for l in read_text(f).splitlines() if l.strip() and not l.strip().startswith("#")}


def can_seal(hub, machine: str) -> bool:
    """Seal only for bodies that understand envelopes (>= 2.5.0).

    A 2.4.0 body would see an envelope as a job with no script and answer bad_job,
    so the decision has to follow what the machine actually reports.
    """
    if not SECRET or os.environ.get("OMP_LEGACY") == "1":
        return False
    allow = seal_list()
    if "ALL" not in allow and machine.upper() not in allow:
        return False
    v = _ver_tuple(machine_body_version(hub, machine))
    if not (v and v >= (2, 5, 0)):
        return False
    # the machine must actually report a key: a body that has the new code but no PSK
    # yet rejects a sealed job ("no PSK") - that is how provisioning gets stuck.
    for r in hub.roots():
        hb = read_json(os.path.join(r, "machines", machine, "state", "heartbeat.json")) or {}
        if hb.get("psk") is True:
            return True
    return False


def open_result_blob(data, jid, machine=None):
    """Decrypt a result file written by the body when ENC_RESULTS is on."""
    if not isinstance(data, dict) or data.get("enc") != "a256cbc-hmac256":
        return data
    if not SECRET:
        die(f"result of {jid} is encrypted but no omp.key/OMP_PSK is configured")
    blob = data.get("blob", "")
    keys = []
    if machine:
        # a result can predate a scheme change, so try both derivations and both generations
        for scheme in ("hkdf2", "v1"):
            for which in ("cur", "prev"):
                if which == "prev" and PSK_PREV is None:
                    continue
                try:
                    keys.append(machine_keys(machine, scheme, which))
                except SystemExit:
                    pass
    keys.append((K_MAC, K_ENC))
    if K_ENC_PREV is not None:
        keys.append((K_MAC_PREV, K_ENC_PREV))
    for k_mac, k_enc in keys:
        if k_enc is None:
            continue
        want = hmac.new(k_mac, ("res|" + jid + "|" + blob).encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(want, str(data.get("mac", ""))):
            return json.loads(aes_decrypt(k_enc, blob).decode("utf-8-sig"))
    die(f"result of {jid} failed its integrity check - do not trust it")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLE_SRC = os.path.join(REPO, "bridge")
ANCHOR_CLI = os.path.join(r"E:\Desktop", "anchor-cli", "AnchorHub", "ctl", "bin", "anchor.mjs")
BOM = b"\xef\xbb\xbf"


# --------------------------------------------------------------------- basics
def log(msg: str = "") -> None:
    print(msg, flush=True)


def die(msg: str, code: int = 1):
    print("ERROR: " + msg, file=sys.stderr, flush=True)
    sys.exit(code)


def norm_machine(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-]", "_", name).upper()


def resolve_machine(hub: "Hub", token: str) -> str:
    """Accept an exact folder name, or a hostname/prefix that maps to exactly one folder.

    Cloned machines share %COMPUTERNAME%, so v2.4.0 bodies split them into
    <COMPUTERNAME>-<fp4> folders. Anything ambiguous is an error - never a guess.
    """
    raw = (token or "").strip()
    if not raw:
        die("no machine given")
    name = norm_machine(raw)
    hub.check()
    mdir = os.path.join(hub.root, "machines")
    if os.path.isdir(os.path.join(mdir, name)):
        return name
    cands = []
    if os.path.isdir(mdir):
        for d in sorted(os.listdir(mdir)):
            full = os.path.join(mdir, d)
            if not os.path.isdir(full):
                continue
            if d.startswith(name):
                cands.append(d)
                continue
            ident = read_json(os.path.join(full, "state", "identity.json")) or {}
            hb = read_json(os.path.join(full, "state", "heartbeat.json")) or {}
            for h in (ident.get("hostname"), hb.get("hostname")):
                if h and norm_machine(str(h)) == name:
                    cands.append(d)
                    break
    if len(cands) == 1:
        log(f"(machine {raw} -> {cands[0]})")
        return cands[0]
    if not cands:
        die(f"no such machine: {raw}")
    die("ambiguous machine %s - candidates: %s" % (raw, ", ".join(sorted(set(cands)))))


def read_text(path: str) -> str:
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return ""
    if raw.startswith(BOM):
        return raw[3:].decode("utf-8", "replace")
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def write_bytes(path: str, data: bytes, retries: int = 4) -> None:
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    last = None
    for i in range(retries):
        try:
            with open(path, "wb") as f:
                f.write(data)
            if os.path.getsize(path) == len(data):
                return
            last = "short write"
        except OSError as exc:
            last = str(exc)
        time.sleep(0.4 * (i + 1))
    die(f"cannot write {path}: {last}")


def write_text(path: str, text: str) -> None:
    write_bytes(path, text.encode("utf-8"))


def read_json(path: str):
    try:
        return json.loads(read_text(path))
    except Exception:
        return None


def sha1_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha1(data).hexdigest()


class Hub:
    def __init__(self, root: str):
        self.root = root.rstrip("\\/")
        self.mirrors = []

    def roots(self):
        """Primary first, then every configured mirror (deduped)."""
        out = []
        for r in [self.root] + list(self.mirrors):
            r = r.rstrip("\\/")
            if r and r not in out:
                out.append(r)
        return out

    def live_roots(self):
        out = []
        for r in self.roots():
            try:
                if os.path.isdir(os.path.join(r, "machines")):
                    out.append(r)
            except OSError:
                pass
        return out

    def m(self, machine: str, *parts: str) -> str:
        return os.path.join(self.root, "machines", machine, *parts)

    def check(self) -> None:
        if not os.path.isdir(self.root):
            die(f"hub not reachable: {self.root}  - check the path and that this box can reach the share")

    def ensure_root(self) -> None:
        """Create the hub tree if the share itself is reachable (first-run bootstrap)."""
        parent = os.path.dirname(self.root)
        if not os.path.isdir(parent):
            die(f"share not reachable: {parent}")
        for d in (self.root, os.path.join(self.root, "machines"),
                  os.path.join(self.root, "bundle"), os.path.join(self.root, "policy")):
            os.makedirs(d, exist_ok=True)

    def ensure(self, machine: str) -> None:
        for sub in ("inbox", os.path.join("inbox", "files"), os.path.join("inbox", "push"),
                    "run", "out", "state"):
            os.makedirs(self.m(machine, sub), exist_ok=True)


# --------------------------------------------------------------------- jobs
def new_job_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + "%04x" % random.getrandbits(16)


def submit(hub: Hub, machine: str, job: dict, payload: bytes | None = None,
           payload_name: str | None = None, push_files: dict | None = None,
           key: str = "cur", scheme: str | None = None) -> str:
    """Drop a job into the inbox of every reachable root.

    With a PSK the routing fields are signed and the body (script/target/args) is
    AES-encrypted, so a write on the share alone cannot execute anything. The same
    job id goes to all roots: the body dedupes by id, so a mirror never double-runs.
    """
    hub.check()
    jid = job.get("id") or new_job_id()
    job["id"] = jid
    job["created_at"] = datetime.now().isoformat(timespec="seconds")

    roots = hub.live_roots() or [hub.root]

    if can_seal(hub, machine) and not job.get("_legacy"):
        kind = str(job.get("kind", "ps")).lower()
        body = {k: v for k, v in job.items()
                if k not in ("ah", "id", "created_at", "file", "kind", "timeout", "_legacy")}
        if payload is not None:
            body["code"] = payload.decode("utf-8-sig", "replace")
        env, blob = seal_job(jid, kind, machine, body, timeout=job.get("timeout"), key=key,
                             scheme=scheme or machine_scheme(hub, machine))
        for r in roots:
            try:
                h = Hub(r)
                h.ensure(machine)
                write_bytes(h.m(machine, "inbox", "files", env["blob"]), blob.encode("ascii"))
                # push payloads are files, not secrets of the envelope: they still have to
                # land in inbox\push\<id>\ or Invoke-PushJob reports "no target"
                for name, data in (push_files or {}).items():
                    write_bytes(h.m(machine, "inbox", "push", jid, name), data)
                path = h.m(machine, "inbox", jid + ".job.json")
                tmp = path + ".tmp"
                write_text(tmp, json.dumps(env, ensure_ascii=False, indent=1))
                os.replace(tmp, path)
            except OSError as exc:
                log(f"  (mirror {r} skipped: {exc})")
        return jid

    job.setdefault("ah", 1)
    job.pop("_legacy", None)
    for r in roots:
        try:
            h = Hub(r)
            h.ensure(machine)
            if payload is not None:
                name = payload_name or (jid + ".ps1")
                job["file"] = name
                write_bytes(h.m(machine, "inbox", "files", name), payload)
            if push_files:
                for name, data in push_files.items():
                    write_bytes(h.m(machine, "inbox", "push", jid, name), data)
            path = h.m(machine, "inbox", jid + ".job.json")
            tmp = path + ".tmp"
            write_text(tmp, json.dumps(job, ensure_ascii=False, indent=1))
            os.replace(tmp, path)
        except OSError as exc:
            log(f"  (mirror {r} skipped: {exc})")
    return jid


def _result_verdict(path: str, jid: str, machine: str | None = None) -> dict:
    """The result dict, decrypting an enc_res envelope when the key is on this box.

    SystemExit is caught too: open_result_blob() calls die() when no key matches, and this
    helper only wants a "cannot read it yet" answer (used by find_result / replay detection).
    """
    verdict = read_json(path) or {}
    if "status" in verdict:
        return verdict
    try:
        return open_result_blob(verdict, jid, machine=machine)
    except (Exception, SystemExit):
        return {}


def _is_replay_reject(verdict: dict) -> bool:
    return (str(verdict.get("status")) == "rejected"
            and "nonce" in str(verdict.get("error", "")).lower())


def find_result(hub: Hub, machine: str, jid: str):
    """Return (root, result_path), preferring a real verdict over a mirror-side rejection.

    submit() fans a job out to every root, and a body that already ran it can only answer
    the second copy with `rejected / replayed nonce`. That copy used to win this lookup, so
    a perfectly good run was reported as exit=97 with no output.
    """
    replay = None
    for r in hub.roots():
        cand = Hub(r).m(machine, "out", jid + ".result.json")
        try:
            if not os.path.isfile(cand):
                continue
        except OSError:
            continue
        if _is_replay_reject(_result_verdict(cand, jid, machine)):
            if replay is None:
                replay = (r, cand)
            continue
        return r, cand
    return replay if replay else (None, None)


def wait_job(hub: Hub, machine: str, jid: str, timeout: int = 1900, follow: bool = True,
             show: bool = True) -> dict:
    res_path = hub.m(machine, "out", jid + ".result.json")
    err_path = hub.m(machine, "run", jid + ".stderr.txt")
    out_path = hub.m(machine, "run", jid + ".stdout.txt")
    started = time.time()
    seen = {"err": 0, "out": 0}
    nudged = False
    found_root = None
    replay_since = None
    while True:
        root, cand = find_result(hub, machine, jid)
        if cand:
            if _is_replay_reject(_result_verdict(cand, jid, machine)):
                # the real answer is probably still on its way from the other root
                if replay_since is None:
                    replay_since = time.time()
                if time.time() - replay_since < 30:
                    cand = None
        if cand:
            res_path = cand
            found_root = root
            out_path = Hub(root).m(machine, "run", jid + ".stdout.txt")
            err_path = Hub(root).m(machine, "run", jid + ".stderr.txt")
            break
        if follow:
            for key, path in (("err", err_path), ("out", out_path)):
                txt = read_text(path)
                if len(txt) > seen[key]:
                    chunk = txt[seen[key]:].strip()
                    if chunk:
                        for line in chunk.replace("\r", "").split("\n"):
                            log("  | " + line)
                    seen[key] = len(txt)
        if not nudged and time.time() - started > 8:
            nudged = True
            log(f"  (queued on {machine}; the body polls every few seconds)")
        if time.time() - started > timeout:
            die(f"gave up waiting for {jid}; it may still be running - see: tail {machine} {jid}", 3)
        time.sleep(1.5)

    # the machine often cannot delete on the share; we can, so tidy up after it.
    # A faned-out job leaves a copy on every root, so clean all of them.
    for root in hub.roots():
        rh = Hub(root)
        for leftover in (os.path.join(rh.m(machine, "inbox"), jid + ".job.json"),
                         os.path.join(rh.m(machine, "inbox"), jid + ".job.json.opt"),
                         os.path.join(rh.m(machine, "inbox"), jid + ".cancel")):
            try:
                if os.path.isfile(leftover):
                    os.remove(leftover)
            except OSError:
                pass

    res = open_result_blob(read_json(res_path) or {}, jid, machine=machine)
    res["_jid"] = jid
    where = found_root or hub.root
    wh = Hub(where)
    res["_stdout"] = read_text(wh.m(machine, "out", jid + ".stdout.txt")) or \
        read_text(wh.m(machine, "run", jid + ".stdout.txt"))
    res["_stderr"] = read_text(wh.m(machine, "run", jid + ".stderr.txt"))
    if show:
        print_result(res, machine)
    return res


def print_result(res: dict, machine: str) -> None:
    status = res.get("status")
    log("")
    log(f"--- {machine}: {res.get('kind', 'job')} {status} exit={res.get('exit')} "
        f"({res.get('duration_sec')}s) ---")
    out = (res.get("_stdout") or "").strip()
    if out:
        log(out)
    elif res.get("kind") in ("fetch", "push", "kill", "ping"):
        log(json.dumps({k: res.get(k) for k in ("files", "failed", "skipped", "written", "capabilities", "error")
                        if res.get(k) not in (None, [], "")}, ensure_ascii=False, indent=1))
    else:
        log("(no stdout)")
    tail = (res.get("stderr_tail") or "").strip()
    if tail and status not in ("ok", "partial"):
        log("")
        log("--- stderr tail ---")
        log(tail)


# ----------------------------------------------------------------- commands
def cmd_machines(hub: Hub, args) -> None:
    hub.check()
    mdir = os.path.join(hub.root, "machines")
    if not os.path.isdir(mdir):
        die("no machine has ever checked in - deploy + bootstrap the body first")
    rows = []
    hosts = {}
    for m in sorted(os.listdir(mdir)):
        if not os.path.isdir(os.path.join(mdir, m)):
            continue  # the roster index and other notes live next to the folders
        hb = read_json(os.path.join(mdir, m, "state", "heartbeat.json")) or {}
        state, age = "NEVER", "-"
        if hb.get("now"):
            try:
                age_s = (datetime.now() - datetime.fromisoformat(hb["now"])).total_seconds()
                age = "%.0fs" % age_s
                state = "ONLINE" if age_s < 60 else ("STALE" if age_s < 600 else "OFFLINE")
            except ValueError:
                pass
        ident = read_json(os.path.join(mdir, m, "state", "identity.json")) or {}
        host = str(ident.get("hostname") or hb.get("hostname") or "-")
        fp = str(ident.get("fp") or "-")[:6]
        ips = [str(x) for x in (ident.get("ips") or [])]
        ip = next((x for x in ips if x.startswith("10.22.")), (ips[0] if ips else "-"))
        hosts[host] = hosts.get(host, 0) + 1
        rows.append((m, host, ip, fp, state, age, str(hb.get("pending", "-")), str(hb.get("jobs_done", "-")),
                     str(hb.get("user") or "-"), str(hb.get("body_version") or "-")))
    header = ("MACHINE", "HOST", "IP", "FP", "STATE", "BEAT", "QUEUE", "DONE", "USER", "BODY")
    allr = [header] + rows
    w = [max(len(str(r[i])) for r in allr) for i in range(len(header))]
    log("  ".join(h.ljust(x) for h, x in zip(header, w)))
    for r in rows:
        log("  ".join(str(c).ljust(x) for c, x in zip(r, w)))
    dupes = {h: c for h, c in hosts.items() if c > 1}
    if dupes:
        log("")
        for h, c in sorted(dupes.items()):
            legacy = [r[0] for r in rows if r[1] == h and r[3] == "-"]
            if legacy:
                log(f"NOTE: {c} folders report host {h}; no identity.json in: {', '.join(legacy)}"
                    "  -> that machine still runs a pre-2.4.0 body")
            else:
                log(f"NOTE: {c} folders report host {h} - expected after v2.4.0 (same PC name, different fingerprint)")


def cmd_identity(hub: Hub, args) -> None:
    """Show what a machine folder actually is: hostname, fingerprint, claim time."""
    m = resolve_machine(hub, args.machine)
    base = os.path.join(hub.root, "machines", m, "state")
    ident = read_json(os.path.join(base, "identity.json")) or {}
    hb = read_json(os.path.join(base, "heartbeat.json")) or {}
    if not ident and not hb:
        die(f"no identity.json and no heartbeat under {m}")
    log("folder   : " + m)
    log("hostname : " + str(ident.get("hostname") or hb.get("hostname") or "-"))
    fp = str(ident.get("fp") or "-")
    log("fp       : " + fp + ("" if fp != "-" else "   (pre-2.4.0 body: no fingerprint yet)"))
    log("claimed  : " + str(ident.get("claimed_at") or "-"))
    log("body     : " + str(hb.get("body_version") or "-") + "  pid=" + str(hb.get("pid") or "-"))
    log("beat     : " + str(hb.get("now") or "-") + "  phase=" + str(hb.get("phase") or "-"))
    for k in ("ips", "macs"):
        vals = ident.get(k) or []
        if vals:
            log(" %-8s: %s" % (k, ", ".join(str(x) for x in vals)))
    hist = ident.get("fp_history") or []
    if len(hist) > 1:
        log(" fp hist : " + ", ".join(str(x) for x in hist))


def cmd_ping(hub: Hub, args) -> None:
    machine = resolve_machine(hub, args.machine)
    jid = submit(hub, machine, {"kind": "ping", "note": "capability probe"})
    res = wait_job(hub, machine, jid, timeout=300, follow=False, show=False)
    print_result(res, machine)
    if res.get("status") != "ok":
        sys.exit(4)


WATCH_FIELDS = ("pid", "version", "checked_at", "stale_sec", "healthy", "reason", "last_ok",
                "last_reason", "last_restart_at", "beacon_age_sec", "launcher_pid")


def watch_state(base: str, hb: dict):
    """(state dict, age in seconds, source) - heartbeat first, legacy watchdog.json second.

    watchdog 1.1.0 / body 2.6.0 stopped publishing `<hub>\\machines\\<M>\\state\\watchdog.json`:
    the hidden `powershell -ExecutionPolicy Bypass -Command` child that wrote it is what
    endpoint security flags (Huorong 系统加固: 利用 PowerShell 执行可疑脚本), and blocking it
    froze that file while the body kept beating. The same fields now ride in the heartbeat's
    `watch` member. Machines still on older builds only have watchdog.json, and on those the
    file may be stale for exactly that reason - hence the LEGACY-FROZEN flag below.
    """
    w = hb.get("watch") or {}
    if w:
        age = None
        if w.get("checked_at"):
            try:
                age = int((datetime.now() - datetime.fromisoformat(w["checked_at"])).total_seconds())
            except ValueError:
                age = None
        if age is None and w.get("beacon_age_sec") is not None:
            age = w.get("beacon_age_sec")
        return w, age, "heartbeat"
    p = os.path.join(base, "watchdog.json")
    wd = read_json(p) or {}
    if not wd:
        return {}, None, "none"
    age = None
    try:
        age = int((datetime.now() - datetime.fromtimestamp(os.path.getmtime(p))).total_seconds())
    except OSError:
        pass
    return wd, age, "watchdog.json"


def cmd_health(hub: Hub, args) -> None:
    """One-line verdict per machine: is the body making progress, and is the watchdog alive?"""
    hub.check()
    mdir = os.path.join(hub.root, "machines")
    if not os.path.isdir(mdir):
        die("no machine has ever checked in")
    machines = [resolve_machine(hub, args.machine)] if args.machine else sorted(os.listdir(mdir))
    bad = 0
    for m in machines:
        if not os.path.isdir(os.path.join(mdir, m)):
            continue  # notes/rosters live next to the machine folders (e.g. _机台标记.csv)
        base = os.path.join(mdir, m, "state")
        hb = read_json(os.path.join(base, "heartbeat.json")) or {}
        w, w_age, src = watch_state(base, hb)
        body_age = None
        if hb.get("now"):
            try:
                body_age = int((datetime.now() - datetime.fromisoformat(hb["now"])).total_seconds())
            except ValueError:
                body_age = None
        restarts = w.get("restarts", hb.get("watchdog_restarts", "-"))
        flags = []
        if hb.get("psk") is False:
            flags.append("NO-KEY(v2 migration incomplete)")
        if hb.get("key_error"):
            flags.append("KEY-ERR")
        if body_age is None:
            flags.append("NO-BEAT")
        elif body_age < -300:
            # the machine clock runs ahead: every freshness number here is suspect, and
            # sealed jobs die on ts skew (canon tolerance is +-900s)
            flags.append("CLOCK-SKEW:%+ds" % -body_age)
        elif body_age >= 120:
            flags.append("BODY-STALE")
        if src == "none":
            flags.append("NO-WATCH")
        else:
            stale_at = max(120, int(w.get("stale_sec") or 120) * 2)
            if w_age is not None and w_age > stale_at:
                flags.append("WATCH-STALE:%ds" % w_age)
            if w.get("healthy") is False:
                flags.append("WATCH-UNHEALTHY:" + str(w.get("reason") or "?"))
            if not w.get("body_alive", True) and body_age is not None and body_age < 120:
                flags.append("BODY-GONE")
            if src == "watchdog.json" and w_age is not None and w_age > 600:
                flags.append("WATCH-LEGACY-FROZEN")
        verdict = "OK" if not flags else "ATTENTION"
        if flags:
            bad += 1
        log("%-22s %-10s beat=%-6s phase=%-8s job=%-18s restarts=%-3s pend=%-3s watch=%-13s %s" % (
            m, verdict,
            ("%ds" % body_age) if body_age is not None else "-",
            str(hb.get("phase") or w.get("body_phase") or "-"),
            str(hb.get("job_id") or w.get("body_job") or "-"),
            restarts, hb.get("pending", "-"),
            (("%ds/%s" % (w_age, "hb" if src == "heartbeat" else "wd")) if w_age is not None else src),
            ",".join(flags) if flags else "watchdog alive"))
        if args.verbose:
            for k in ("body_version", "key_scheme", "key_scope", "key_error",
                      "watchdog_pid", "heartbeat_file", "local_root"):
                if hb.get(k) not in (None, ""):
                    log("    %-16s %s" % (k, hb[k]))
            for k in WATCH_FIELDS:
                if w.get(k) not in (None, ""):
                    log("    watch.%-13s %s" % (k, w[k]))
    if bad and args.strict:
        sys.exit(6)


def cmd_run(hub: Hub, args) -> None:
    machine = resolve_machine(hub, args.machine)
    kind = args.kind or ("cmd" if args.file and args.file.lower().endswith((".cmd", ".bat")) else "ps")
    payload = None
    if args.file:
        if not os.path.isfile(args.file):
            die("no such script: " + args.file)
        payload = open(args.file, "rb").read()
        if not payload.startswith(BOM):
            payload = BOM + payload          # PS 5.1 misreads UTF-8 Chinese without a BOM
        payload_name = os.path.basename(args.file)
    elif args.code:
        payload = BOM + args.code.replace("\\n", "\n").encode("utf-8")
        payload_name = None
    else:
        die("run needs -f <script> or -e <powershell code>")

    job = {"kind": kind, "cwd": args.cwd, "timeout": args.timeout, "note": args.note}
    if args.args:
        job["args"] = args.args
    if args.env:
        env = {}
        for pair in args.env:
            if "=" not in pair:
                die("--env wants NAME=VALUE: " + pair)
            k, v = pair.split("=", 1)
            env[k] = v
        job["env"] = env
    jid = submit(hub, machine, job, payload=payload, payload_name=payload_name)
    log(f"job {jid} -> {machine} ({kind})")
    if args.no_wait:
        return
    res = wait_job(hub, machine, jid, timeout=args.wait_timeout or (args.timeout + 120),
                   follow=not args.quiet)
    if res.get("status") != "ok":
        sys.exit(4)


LS_SNIPPET = r"""$p = '@PATH@'
if (-not (Test-Path $p)) { Write-Output ('NO-SUCH-PATH ' + $p); exit 2 }
$items = @(Get-ChildItem -Path $p -Force -ErrorAction SilentlyContinue)
Write-Output ('DIR ' + $p + '  (' + $items.Count + ' entries)')
foreach ($i in ($items | Sort-Object LastWriteTime -Descending | Select-Object -First @TOP@)) {
  $kind = 'F'; if ($i.PSIsContainer) { $kind = 'D' }
  $size = ''; if (-not $i.PSIsContainer) { $size = $i.Length }
  Write-Output ($kind + "`t" + $i.LastWriteTime.ToString('yyyy-MM-dd HH:mm') + "`t" + $size + "`t" + $i.Name)
}
"""


def cmd_ls(hub: Hub, args) -> None:
    """List a remote directory (newest first)."""
    machine = resolve_machine(hub, args.machine)
    body = LS_SNIPPET.replace('@PATH@', args.path.replace("'", "''")).replace('@TOP@', str(args.top))
    jid = submit(hub, machine, {"kind": "ps", "timeout": 180, "note": "ls " + args.path},
                 payload=BOM + body.encode("utf-8"))
    res = wait_job(hub, machine, jid, timeout=300, follow=False, show=False)
    out = (res.get("_stdout") or "")
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 4:
            log("%s  %-16s %10s  %s" % (parts[0], parts[1], parts[2], parts[3]))
        elif line.strip():
            log(line)
    if res.get("status") != "ok":
        die("ls failed: " + str(res.get("status")), 4)


def cmd_fetch(hub: Hub, args) -> None:
    machine = resolve_machine(hub, args.machine)
    job = {"kind": "fetch", "patterns": args.pattern, "max_mb": args.max_mb, "timeout": args.timeout,
           "note": "fetch " + " ".join(args.pattern)}
    jid = submit(hub, machine, job)
    log(f"job {jid} -> {machine} (fetch {len(args.pattern)} pattern(s))")
    res = wait_job(hub, machine, jid, timeout=args.wait_timeout or (args.timeout + 300),
                   follow=not args.quiet, show=False)
    remote_dir = hub.m(machine, "out", jid + ".files")
    manifest = read_text(hub.m(machine, "out", jid + ".manifest.tsv"))
    if not manifest.strip():
        die("no manifest came back (see result above)", 4)
    dest = args.dest or os.path.join(REPO, "pulled", machine, jid)
    os.makedirs(dest, exist_ok=True)
    ok = bad = skipped = 0
    for line in manifest.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        rel, size, digest = parts
        if size in ("MISS", "FAIL", "SKIP-BIG"):
            log(f"  {size:>8s}  {rel}")
            skipped += 1
            continue
        src = os.path.join(remote_dir, rel)
        dst = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(dst) or dest, exist_ok=True)
        try:
            shutil.copyfile(src, dst)
        except OSError as exc:
            log(f"  ! copy failed {rel}: {exc}")
            bad += 1
            continue
        local = sha1_file(dst)
        if digest and local != digest.lower():
            log(f"  ! sha1 mismatch {rel} remote={digest[:12]} local={local[:12]}")
            bad += 1
        else:
            ok += 1
    log(f"fetched {ok} file(s) -> {dest}   mismatched={bad} skipped={skipped}")
    if bad:
        sys.exit(6)


def sha1_file(path: str) -> str:
    import hashlib
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_push(hub: Hub, args) -> None:
    machine = resolve_machine(hub, args.machine)
    if not os.path.isfile(args.source):
        die("no such file: " + args.source)
    data = open(args.source, "rb").read()
    name = os.path.basename(args.source)
    jid = submit(hub, machine, {"kind": "push", "target": args.target, "timeout": args.timeout},
                 push_files={name: data})
    log(f"job {jid} -> {machine} (push {name}, {len(data)} bytes)")
    res = wait_job(hub, machine, jid, timeout=args.wait_timeout or (args.timeout + 120),
                   follow=False, show=False)
    print_result(res, machine)
    if res.get("status") != "ok":
        sys.exit(4)
    written = (res.get("written") or [{}])[0]
    if written.get("sha1") and written["sha1"].lower() != sha1_bytes(data):
        die("sha1 mismatch after copy on the machine", 6)
    log("verified sha1 " + (written.get("sha1", "?")[:12]))


def cmd_ask(hub: Hub, args) -> None:
    machine = resolve_machine(hub, args.machine)
    job = {"kind": "omp", "prompt": args.prompt, "mode": args.mode, "continue": args.cont,
           "cwd": args.cwd, "model": args.model, "timeout": args.timeout, "approval": args.approval,
           "max_time": args.max_time}
    jid = submit(hub, machine, job)
    log(f"job {jid} -> {machine} (omp)")
    res = wait_job(hub, machine, jid, timeout=args.wait_timeout or (args.timeout + 180),
                   follow=not args.quiet, show=False)
    print_result(res, machine)
    if res.get("status") != "ok":
        sys.exit(4)


def cmd_jobs(hub: Hub, args) -> None:
    machine = resolve_machine(hub, args.machine)
    hub.check()
    for sub in ("inbox", "run", "out"):
        d = hub.m(machine, sub)
        if not os.path.isdir(d):
            continue
        files = sorted([f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f))])
        log(f"[{sub}] {len(files)}")
        for f in files[-15:]:
            p = os.path.join(d, f)
            log("  %-44s %9d  %s" % (f, os.path.getsize(p),
                                     datetime.fromtimestamp(os.path.getmtime(p)).strftime("%m-%d %H:%M:%S")))


def cmd_tail(hub: Hub, args) -> None:
    machine = resolve_machine(hub, args.machine)
    paths = [("result", hub.m(machine, "out", args.job + ".result.json")),
             ("stdout", hub.m(machine, "run", args.job + ".stdout.txt")),
             ("stderr", hub.m(machine, "run", args.job + ".stderr.txt"))]
    seen = {k: 0 for k, _ in paths}
    while True:
        for k, p in paths:
            txt = read_text(p)
            if len(txt) > seen[k]:
                log(f"--- {k} ---")
                log(txt[seen[k]:].rstrip())
                seen[k] = len(txt)
        if os.path.isfile(paths[0][1]):
            if not args.watch:
                break
            log("(finished)")
            break
        if not args.watch:
            break
        time.sleep(2)


def cmd_prune(hub: Hub, args) -> None:
    """Remove inbox job files that already have a result (machine may not be allowed to)."""
    machine = resolve_machine(hub, args.machine)
    hub.check()
    inbox = hub.m(machine, "inbox")
    out = hub.m(machine, "out")
    if not os.path.isdir(inbox):
        log("nothing to prune")
        return
    removed = kept = 0
    for fn in sorted(os.listdir(inbox)):
        if not fn.endswith(".job.json"):
            continue
        jid = fn[:-len(".job.json")]
        if os.path.isfile(os.path.join(out, jid + ".result.json")):
            try:
                os.remove(os.path.join(inbox, fn))
                removed += 1
            except OSError:
                kept += 1
        else:
            kept += 1
    # payloads: the machine used to leave inbox\files\<id>.* behind forever, so finished
    # job scripts (and the key-provisioning one, which carries PSK=) stayed readable on the
    # share. Bodies delete their own from 2.6.4; this cleans what older builds left.
    files_dir = hub.m(machine, "inbox", "files")
    purged = 0
    if os.path.isdir(files_dir):
        for fn in list(os.listdir(files_dir)):
            jid = fn.split(".", 1)[0]
            if os.path.isfile(os.path.join(out, jid + ".result.json")):
                try:
                    os.remove(os.path.join(files_dir, fn))
                    purged += 1
                except OSError:
                    pass

    # stale claim locks from bodies that could not delete on this share
    run_dir = hub.m(machine, "run")
    dropped = 0
    if os.path.isdir(run_dir):
        for fn in os.listdir(run_dir):
            if not fn.endswith(".lock"):
                continue
            fp = os.path.join(run_dir, fn)
            if os.path.isfile(os.path.join(out, fn[:-len(".job.json.lock")] + ".result.json")) \
               and time.time() - os.path.getmtime(fp) > 3600:
                try:
                    os.remove(fp)
                    dropped += 1
                except OSError:
                    pass
    log(f"pruned {removed} job file(s), {purged} payload(s); finished job file(s); {kept} left in inbox; {dropped} stale lock(s) dropped")


def cmd_rfid(hub: Hub, args) -> None:
    """Remote control of rfidmon.exe on a machine (record / pause / stop / status / tail)."""
    machine = resolve_machine(hub, args.machine)
    hub.check()
    d = hub.m(machine, "rfid")
    os.makedirs(d, exist_ok=True)
    action = args.action

    if action in ("record", "pause", "stop"):
        write_text(os.path.join(d, "control.json"), json.dumps({"mode": action}) + "\n")
        if action == "stop":
            log("stop requested - the monitor exits on its next cycle")
            return
        time.sleep(4)
        st = read_json(os.path.join(d, "status.json")) or {}
        log(f"{machine}: mode={st.get('mode')} state={st.get('state')} connected={st.get('connected')} "
            f"tags_total={st.get('tags_total')} distinct={st.get('distinct_epcs')}")
        if action == "pause":
            log("reader released - the packaging app can take the LLRP session back")
        return

    if action == "status":
        st = read_json(os.path.join(d, "status.json"))
        if not st:
            die("no status.json yet - is the monitor running? (rfid start)", 3)
        beat = st.get("now", "")
        age = "-"
        try:
            age = "%.0fs" % (datetime.now() - datetime.fromisoformat(beat)).total_seconds()
        except Exception:
            pass
        log(f"machine   : {machine}")
        log(f"reader    : {st.get('ip')}   connected={st.get('connected')}   state={st.get('state')}")
        log(f"mode      : {st.get('mode')}   (record = holding the LLRP session)")
        log(f"tags      : total={st.get('tags_total')}  distinct_epcs={st.get('distinct_epcs')}  "
            f"last_poll={st.get('tags_last_poll')}  polls={st.get('polls')}")
        log(f"last_tag  : {st.get('last_tag_at') or '-'}")
        log(f"heartbeat : {beat}  (age {age})")
        if st.get("last_error"):
            log(f"last_error: {st['last_error']}")
        return

    if action == "tail":
        txt = read_text(os.path.join(d, "live.txt")).strip()
        if not txt:
            die("live.txt is empty - nothing read yet", 3)
        for line in txt.splitlines()[-args.n:]:
            log(line)
        return

    if action == "records":
        path = os.path.join(d, "records-" + datetime.now().strftime("%Y%m%d") + ".jsonl")
        if not os.path.isfile(path):
            die("no records file for today on the hub", 3)
        lines = read_text(path).strip().splitlines()
        rows = []
        for ln in lines[-args.n:]:
            try:
                rows.append(json.loads(ln))
            except Exception:
                continue
        for r in rows:
            log("%s  %-26s %-18s ant%s  %s dBm  x%s" % (r.get("t", "")[11:], r.get("epc", ""),
                                                       r.get("ascii", ""), r.get("ant"), r.get("rssi"), r.get("seen")))
        log(f"({len(lines)} record(s) today)")
        return

    if action == "start":
        starter = os.path.join(REPO, "jobs", "rfidmon-start.ps1")
        if not os.path.isfile(starter):
            die("missing helper: " + starter)
        payload = open(starter, "rb").read()
        if not payload.startswith(BOM):
            payload = BOM + payload
        jid = submit(hub, machine, {"kind": "ps", "timeout": 180}, payload=payload)
        log(f"launch job {jid} -> {machine}")
        wait_job(hub, machine, jid, timeout=300, follow=False, show=True)
        return

    die("unknown rfid action: " + action)


def cmd_cancel(hub: Hub, args) -> None:
    machine = resolve_machine(hub, args.machine)
    write_text(hub.m(machine, "inbox", args.job + ".cancel"), "cancel\n")
    log(f"cancel flag dropped for {args.job}")


def cmd_kill(hub: Hub, args) -> None:
    machine = resolve_machine(hub, args.machine)
    job = {"kind": "kill", "pid": args.pid, "name": args.name}
    jid = submit(hub, machine, job)
    res = wait_job(hub, machine, jid, timeout=180, follow=False)
    if res.get("status") != "ok":
        sys.exit(4)


def cmd_stopall(hub: Hub, args) -> None:
    hub.check()
    flag = os.path.join(hub.root, "policy", "disabled.txt")
    if args.off:
        if os.path.isfile(flag):
            os.remove(flag)
        log("all bodies resumed")
        return
    os.makedirs(os.path.dirname(flag), exist_ok=True)
    write_text(flag, "disabled at " + datetime.now().isoformat(timespec="seconds") + "\n")
    log("all bodies paused (no new job runs until: stopall --off)")


def cmd_deploy(hub: Hub, args) -> None:
    hub.ensure_root()
    bundle = os.path.join(hub.root, "bundle")
    os.makedirs(bundle, exist_ok=True)
    for root, _dirs, files in os.walk(BUNDLE_SRC):
        for fn in sorted(files):
            src = os.path.join(root, fn)
            rel = os.path.relpath(src, BUNDLE_SRC)
            if os.path.basename(rel).lower() == "omp.exe" and not args.include_omp:
                continue
            dst = os.path.join(bundle, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)
            log(f"published {rel} ({os.path.getsize(src)} bytes)")
    import re as _re
    body_src = open(os.path.join(BUNDLE_SRC, "omp-body.ps1"), "rb").read()
    m = _re.search(rb"\$BodyVersion\s*=\s*'([0-9]+\.[0-9]+\.[0-9]+[^']*)'", body_src)
    sem = m.group(1).decode() if m else "0.0.0"
    ver = sem + "-" + hashlib.sha1(body_src).hexdigest()[:8]
    write_text(os.path.join(bundle, "version.txt"), ver + "\n")
    log("published body version " + ver + " (bodies self-update from this)")
    log("bundle ready: " + bundle)


def cmd_bootstrap(hub: Hub, args) -> None:
    machine = resolve_machine(hub, args.machine)
    unc = os.path.join(hub.root, "bundle", "install.ps1")
    script = ("$s = '" + unc + "'; "
              "if (-not (Test-Path $s)) { Write-Output ('MISSING ' + $s); exit 2 }; "
              "Start-Process -FilePath 'powershell.exe' -ArgumentList ('-NoProfile','-ExecutionPolicy','Bypass','-File','\"' + $s + '\"','-Silent') -WindowStyle Hidden; "
              "Write-Output ('launched ' + $s)\n")
    log("anchor exec " + machine + " -- <launch installer>")
    if args.dry_run:
        log(script)
        return
    if not os.path.isfile(ANCHOR_CLI):
        die("anchor CLI not found: " + ANCHOR_CLI + "\nrun the installer on the machine by hand instead:\n  "
            + unc)
    env = dict(os.environ, AH_ALLOW_DEFAULT_ROOT="1")
    r = subprocess.run(["node", ANCHOR_CLI, "exec", machine, "--mode", "full", "--timeout", "60", "--", script],
                       cwd=os.path.dirname(os.path.dirname(os.path.dirname(ANCHOR_CLI))),
                       env=env, capture_output=True, text=True, errors="replace")
    log((r.stdout or "").strip()[:3000])
    if r.returncode != 0:
        log((r.stderr or "").strip()[:1500])
        die("anchor exec failed (exit %d)" % r.returncode, 5)


# ------------------------------------------------------------------ selftest
class _NS:
    def __init__(self, **kw):
        self.__dict__.update(kw)


ROTATE_PS = r"""
# Move this machine to the new PSK, then take the body down so it reloads settings.ini.
$cands = @()
try { $cands += (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Definition))) } catch { }
$cands += (Get-Location).Path
try {
  $cands += @(Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Caches') -Directory -ErrorAction SilentlyContinue |
              ForEach-Object { $_.FullName })
} catch { }
$local = $cands | Where-Object { $_ -and (Test-Path (Join-Path $_ 'settings.ini')) } | Select-Object -First 1
if (-not $local) { 'ERR settings.ini not found'; exit 1 }
$psk = '__PSK__'
if ($psk.Length -ne 64) { 'ERR key length ' + $psk.Length; exit 1 }
$cfg = Join-Path $local 'settings.ini'
$keep = @()
if (Test-Path $cfg) { $keep = @(Get-Content -Path $cfg) }
$keep = @($keep | Where-Object { $_ -notmatch '^(?i)PSK\s*=' })
$keep += ('PSK=' + $psk)
Set-Content -Path $cfg -Value $keep -Encoding ASCII
'rotated ' + $local
# The job runs in a CHILD powershell (runs\<id>\task.ps1), so $PID is not the body. Kill the
# body by the pid it publishes, then let the launcher bring up a process that reads the new key.
$bodyPid = 0
try { $bodyPid = [int]((Get-Content (Join-Path $local 'bridge.lock') -Raw).Trim().Split(' ')[0]) } catch { }
if ($bodyPid -le 0) {
  try { $bodyPid = [int]((Get-Content (Join-Path $local 'state\hb.json') -Raw | ConvertFrom-Json).pid) } catch { }
}
'body pid ' + $bodyPid
if ($bodyPid -gt 0) {
  Start-Process -FilePath 'cmd.exe' -ArgumentList ('/c ping -n 3 127.0.0.1 >nul & taskkill /PID ' + $bodyPid + ' /T /F') -WindowStyle Hidden | Out-Null
} else { 'ERR body pid not found' }
"""


def _ps_verify(hub, machine, key, timeout=90, scheme=None):
    """Did that body accept a job sealed with this key?

    Judged from the plaintext stdout file, not from the encrypted result: during a key/scheme
    change a result can legitimately be undecryptable on the controller side, and treating
    "cannot read the answer" as "the body refused" made migration report false failures.
    """
    jid = submit(hub, machine, {"kind": "ps", "timeout": 30},
                 payload=b"Write-Output ('verify-ok')", key=key, scheme=scheme)
    deadline = time.time() + timeout
    while time.time() < deadline:
        for root in hub.roots():
            h = Hub(root)
            txt = read_text(h.m(machine, "run", jid + ".stdout.txt")) or ""
            if "verify-ok" in txt:
                return True
            res_path = h.m(machine, "out", jid + ".result.json")
            if os.path.isfile(res_path):
                verdict = _result_verdict(res_path, jid, machine)
                status = str(verdict.get("status") or "")
                if status in ("rejected", "bad_job"):
                    return False
                if status:
                    return True
                # executed, but the result cannot be decrypted here: still "accepted"
                return True
        time.sleep(1.5)
    return False


PROVISION_V2_PS = r"""
# v2 key provisioning: this machine gets its OWN seed (never the fleet master), sealed at rest
# with DPAPI so a copied settings.ini is useless on another box/account.
$seedHex = '__SEED__'
if ($seedHex.Length -ne 64) { 'ERR seed length ' + $seedHex.Length; exit 1 }
$cands = @()
try { $cands += (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Definition))) } catch { }
$cands += (Get-Location).Path
try {
  $cands += @(Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Caches') -Directory -ErrorAction SilentlyContinue |
              ForEach-Object { $_.FullName })
} catch { }
$local = $cands | Where-Object { $_ -and (Test-Path (Join-Path $_ 'settings.ini')) } | Select-Object -First 1
if (-not $local) { 'ERR settings.ini not found'; exit 1 }

$seed = New-Object byte[] 32
for ($i = 0; $i -lt 32; $i++) { $seed[$i] = [Convert]::ToByte($seedHex.Substring($i * 2, 2), 16) }
try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { }
$blob = $null
try {
  $blob = [System.Security.Cryptography.ProtectedData]::Protect(
    $seed, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
} catch { 'ERR dpapi protect failed: ' + $_.Exception.Message; exit 1 }
if (-not $blob -or $blob.Length -lt 32) { 'ERR empty dpapi blob - leaving the old key in place'; exit 1 }

$cfg = Join-Path $local 'settings.ini'
$keep = @()
if (Test-Path $cfg) { $keep = @(Get-Content -Path $cfg) }
$keep = @($keep | Where-Object { $_ -notmatch '^(?i)(PSK|PSK_PROTECTED|KEY_SCHEME|ALLOW_LEGACY|ENC_RESULTS)\s*=' })
$keep += ('PSK_PROTECTED=' + [Convert]::ToBase64String($blob))
$keep += 'KEY_SCHEME=hkdf2'
$keep += 'ALLOW_LEGACY=0'
$keep += 'ENC_RESULTS=1'
Set-Content -Path $cfg -Value $keep -Encoding ASCII
'scheme v2 installed at ' + $local

$bodyPid = 0
try { $bodyPid = [int]((Get-Content (Join-Path $local 'bridge.lock') -Raw).Trim().Split(' ')[0]) } catch { }
if ($bodyPid -le 0) {
  try { $bodyPid = [int]((Get-Content (Join-Path $local 'state\hb.json') -Raw | ConvertFrom-Json).pid) } catch { }
}
'body pid ' + $bodyPid
if ($bodyPid -gt 0) {
  Start-Process -FilePath 'cmd.exe' -ArgumentList ('/c ping -n 3 127.0.0.1 >nul & taskkill /PID ' + $bodyPid + ' /T /F') -WindowStyle Hidden | Out-Null
} else { 'ERR body pid not found' }
"""


def cmd_upgradekey(hub: Hub, args) -> None:
    """Move machines from the fleet-wide key to per-machine seeds (HKDF) sealed with DPAPI.

    Idempotent: a machine already reporting key_scheme=hkdf2 is skipped. The provisioning job is
    sealed with whatever scheme the machine uses *now* (v1 or hkdf2), so it works mid-migration.
    """
    if not SECRET:
        die("no ctl/omp.key")
    hub.check()
    machines = [resolve_machine(hub, m.strip()) for m in (getattr(args, "machines", None) or "").split(",") if m.strip()]
    if args.all:
        machines = sorted(d for d in os.listdir(os.path.join(hub.root, "machines"))
                          if os.path.isdir(os.path.join(hub.root, "machines", d)) and not d.startswith("_"))
    if not machines:
        die("give --machines A,B or --all")

    ok, skipped, failed = [], [], []
    for m in machines:
        _hb = read_json(os.path.join(hub.root, "machines", m, "state", "heartbeat.json")) or {}
        _ver = _ver_tuple(str(_hb.get("body_version") or ""))
        if _ver < (2, 7, 3):
            # a body older than 2.7.3 does not understand PSK_PROTECTED/KEY_SCHEME and would go
            # keyless; wait for its self-update instead
            log(f"  waiting for body 2.7.3+ : {m} ({_hb.get('body_version')})")
            failed.append(m)
            continue
        if machine_scheme(hub, m) == "hkdf2" and _hb.get("psk") and _ps_verify(hub, m, "cur", scheme="hkdf2"):
            log(f"  already v2: {m}")
            skipped.append(m)
            continue
        seed = hkdf_sha256(PSK, b"omp/seed/" + m.upper().encode("utf-8"), 32).hex()

        # recovery path: a body with NO key material accepts unsigned jobs (2.7.3+), which is
        # the only way to reach a machine whose PSK_PROTECTED came out empty. Restore a plain
        # key first, then convert it to DPAPI in the normal pass below.
        hb = read_json(os.path.join(hub.root, "machines", m, "state", "heartbeat.json")) or {}
        if not hb.get("psk"):
            log(f"  {m}: no usable key - repairing with an unsigned job (legacy window)")
            repair = PROVISION_V2_PS.replace("__SEED__", seed).replace(
                "$keep += ('PSK_PROTECTED=' + [Convert]::ToBase64String($blob))",
                "$keep += ('PSK_PROTECTED=' + [Convert]::ToBase64String($blob))\n$keep += ('PSK=' + $seedHex)")
            jid = submit(hub, m, {"kind": "ps", "timeout": 120, "_legacy": True},
                         payload=repair.encode("utf-8"), key="cur")
            try:
                wait_job(hub, m, jid, timeout=args.timeout, follow=False, show=False)
            except SystemExit:
                pass
            time.sleep(6)
            hb = read_json(os.path.join(hub.root, "machines", m, "state", "heartbeat.json")) or {}
            log(f"  {m}: after repair psk={hb.get('psk')} scheme={hb.get('key_scheme')}")

        script = PROVISION_V2_PS.replace("__SEED__", seed)
        done = False
        for attempt in (1, 2):
            jid = submit(hub, m, {"kind": "ps", "timeout": 120}, payload=script.encode("utf-8"))
            try:
                wait_job(hub, m, jid, timeout=args.timeout, follow=False, show=False)
            except SystemExit:
                pass
            # wait for the restarted body to publish the new scheme, then verify sealed-v2
            deadline = time.time() + 45
            while time.time() < deadline:
                if machine_scheme(hub, m) == "hkdf2":
                    break
                time.sleep(2)
            if machine_scheme(hub, m) == "hkdf2" and _ps_verify(hub, m, "cur", scheme="hkdf2"):
                done = True
                break
            log(f"  {m}: not on v2 yet (attempt {attempt}) - retrying")
        (ok if done else failed).append(m)
        log(f"  {'v2 ok ' if done else 'FAILED'} {m}")
    log(f"v2 ok {len(ok)}, skipped {len(skipped)}, failed {len(failed)}")
    if failed:
        log('re-run for the failures:  python ctl/ompremote.py upgradekey --machines "' + ",".join(failed) + '"')
        sys.exit(3)


def cmd_rotatekey(hub: Hub, args) -> None:
    """Move every machine onto ctl/omp.key, delivered inside a sealed job signed by the old key.

    Run `keygen --rotate` first (it parks the old key as omp.key.prev). Machines still on the
    old key can only be reached with it, so the provisioning job is sealed with 'prev' and the
    verification ping with 'cur'.
    """
    if not SECRET or K_ENC_PREV is None:
        die("rotatekey needs both ctl/omp.key (new) and ctl/omp.key.prev (old): run keygen --rotate first")
    hub.check()
    machines = [resolve_machine(hub, m.strip()) for m in (getattr(args, "machines", None) or "").split(",") if m.strip()]
    if args.all:
        machines = sorted(d for d in os.listdir(os.path.join(hub.root, "machines"))
                          if os.path.isdir(os.path.join(hub.root, "machines", d)) and not d.startswith("_"))
    if not machines:
        die("give --machines A,B or --all")

    script = ROTATE_PS.replace("__PSK__", PSK.hex())
    ok, failed = [], []
    for m in machines:
        if _ps_verify(hub, m, "cur"):
            log(f"  already on the new key: {m}")
            ok.append(m)
            continue
        done = False
        for attempt in (1, 2):
            jid = submit(hub, m, {"kind": "ps", "timeout": 120}, payload=script.encode("utf-8"), key="prev")
            try:
                wait_job(hub, m, jid, timeout=args.timeout, follow=False, show=False)
            except SystemExit:
                pass                       # the body kills itself at the end of the script
            time.sleep(4)
            if _ps_verify(hub, m, "cur"):
                # housekeeping: payload leftovers are deleted by the body, but old builds keep them
                try:
                    for root in hub.roots():
                        fl = Hub(root).m(m, "inbox", "files")
                        if os.path.isdir(fl):
                            for fn in os.listdir(fl):
                                if fn.startswith(jid):
                                    os.remove(os.path.join(fl, fn))
                except OSError:
                    pass
                done = True
                break
            log(f"  {m}: still answering with the old key (attempt {attempt}) - retrying")
        (ok if done else failed).append(m)
        log(f"  {'rotated' if done else 'FAILED '} {m}")
        with open(ROTATED, "w", encoding="utf-8") as f:
            f.write("\n".join(ok) + ("\n" if ok else ""))
    log(f"rotated {len(ok)}/{len(machines)}" + (f", failed: {failed}" if failed else ""))
    if failed:
        log("re-run for the failures:  python ctl/ompremote.py rotatekey --machines \"" + ",".join(failed) + "\"")
        sys.exit(3)
    log("all machines accept the new key; you may delete ctl/omp.key.prev once you are sure")


def cmd_keygen(hub: Hub, args) -> None:
    """Create or show the pre-shared key that seals jobs and results."""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "omp.key")
    if args.rotate:
        if not os.path.isfile(p):
            die("nothing to rotate: no ctl/omp.key")
        prev = p + ".prev"
        try:
            if os.path.isfile(prev):
                os.remove(prev)
            os.replace(p, prev)
        except OSError as e:
            die(f"cannot park the old key: {e}")
        key = binascii.hexlify(os.urandom(32)).decode()
        with open(p, "w", encoding="ascii", newline="\n") as f:
            f.write(key + "\n")
        log(f"old key parked at {prev}")
        log(f"wrote {p}  fingerprint: {hashlib.sha256(bytes.fromhex(key)).hexdigest()[:16]}")
        log("now move the fleet over:  python ctl/ompremote.py rotatekey --all")
        return
    if os.path.isfile(p) and not args.force:
        log(f"key already exists: {p}  (use --force to rotate)")
        log(f"fingerprint: {hashlib.sha256(PSK).hexdigest()[:16]}")
        return
    key = binascii.hexlify(os.urandom(32)).decode()
    with open(p, "w", encoding="ascii", newline="\n") as f:
        f.write(key + "\n")
    log(f"wrote {p}")
    log(f"fingerprint: {hashlib.sha256(bytes.fromhex(key)).hexdigest()[:16]}")
    log("now push it to the field:  python ctl/ompremote.py secure <machine> --all")


def submit_one(hub, root, machine, job, payload=None):
    """Queue a job on ONE root only (used to split the key across two paths)."""
    jid = job.get("id") or new_job_id()
    job["id"] = jid
    job.setdefault("ah", 1)
    job["created_at"] = datetime.now().isoformat(timespec="seconds")
    h = Hub(root)
    h.ensure(machine)
    if payload is not None:
        name = jid + ".ps1"
        job["file"] = name
        write_bytes(h.m(machine, "inbox", "files", name), payload)
    path = h.m(machine, "inbox", jid + ".job.json")
    tmp = path + ".tmp"
    write_text(tmp, json.dumps(job, ensure_ascii=False, indent=1))
    os.replace(tmp, path)
    return jid


def wait_any(hub, roots, machine, jid, timeout=180):
    h = Hub(roots)
    h.mirrors = []
    return wait_job(h, machine, jid, timeout=timeout, show=False)


PROVISION_PS = """
# Write the bridge settings. $psk comes from the job (split mode: from hk-a.txt + hk-b.txt).
$local = (Get-Location).Path
$psk = '__PSK__'
if (-not $psk) {
  $a = Join-Path $local 'hk-a.txt'; $b = Join-Path $local 'hk-b.txt'
  if (-not (Test-Path $a) -or -not (Test-Path $b)) { 'ERR missing key halves (run secure again)'; exit 1 }
  $psk = ((Get-Content $a -Raw).Trim() + (Get-Content $b -Raw).Trim())
  Remove-Item $a, $b -Force -ErrorAction SilentlyContinue
}
if ($psk.Length -ne 64) { 'ERR key length ' + $psk.Length; exit 1 }
$cfg = Join-Path $local 'settings.ini'
$keep = @()
if (Test-Path $cfg) { $keep = @(Get-Content -Path $cfg) }
$keep = @($keep | Where-Object { $_ -notmatch '^(?i)(PSK|HUBS|ALLOW_LEGACY|ENC_RESULTS)\\s*=' })
$keep += ('PSK=' + $psk)
$keep += 'HUBS=__HUBS__'
$keep += ('ALLOW_LEGACY=__LEGACY__')
$keep += 'ENC_RESULTS=1'
Set-Content -Path $cfg -Value $keep -Encoding ASCII
@"
__HUBLINES__
"@ | Set-Content -Path (Join-Path $local 'hubs.txt') -Encoding ASCII
'sealed: key installed; mirrors=' + '__NROOTS__'
"""


def cmd_secure(hub: Hub, args) -> None:
    """Install the PSK + hub mirrors on machines.

    The key itself cannot ride a sealed job (the body has no key yet), and the share is
    SMB-signed but NOT encrypted - so it is split in half and each half is queued on a
    different root. Snatching one path gives a 128-bit-unknown key half, not a signing key.
    """
    if not SECRET:
        die("no ctl/omp.key - run: python ctl/ompremote.py keygen")
    machines = [resolve_machine(hub, args.machine)] if args.machine else []
    if args.all:
        machines = sorted(d for d in os.listdir(os.path.join(hub.root, "machines"))
                          if os.path.isdir(os.path.join(hub.root, "machines", d)) and not d.startswith("_"))
    if not machines:
        die("give a machine name or --all")
    roots = [r for r in hub.roots() if os.path.isdir(os.path.join(r, "machines"))]
    if len(roots) < 2:
        log("NOTE: only one reachable root - the key is delivered undivided")
    psk = PSK.hex()
    legacy = "0" if args.lock_legacy else "1"
    script = (PROVISION_PS.replace("__PSK__", "" if args.split else psk)
              .replace("__HUBS__", ";".join(roots))
              .replace("__LEGACY__", legacy)
              .replace("__NROOTS__", str(len(roots)))
              .replace("__HUBLINES__", "\n".join(roots)))
    for m in machines:
        if args.split and len(roots) >= 2:
            # step 0: teach the body about the mirror root (the paths are not secret).
            # Without this a half queued on the mirror would sit there unread, because the
            # body only scans the roots listed in its own hubs.txt.
            jh = submit_one(hub, roots[0], m, {"kind": "ps", "timeout": 60},
                            payload=("Set-Content -Path (Join-Path (Get-Location).Path 'hubs.txt') "
                                     "-Value @('" + "','".join(roots) + "') -Encoding ASCII; 'hubs'").encode("utf-8"))
            wait_any(hub, roots[0], m, jh, timeout=args.timeout)
            deadline = time.time() + 90
            while time.time() < deadline:
                hb = read_json(os.path.join(roots[0], "machines", m, "state", "heartbeat.json")) or {}
                if any(str(r).rstrip("\\/") == str(roots[1]).rstrip("\\/") or r == roots[1] for r in (hb.get("hubs") or [])):
                    break
                time.sleep(3)
            ja = submit_one(hub, roots[0], m, {"kind": "ps", "timeout": 60},
                            payload=("Set-Content -Path (Join-Path (Get-Location).Path 'hk-a.txt') -Value '"
                                     + psk[:32] + "' -Encoding ASCII -NoNewline; 'A'").encode("utf-8"))
            wait_any(hub, roots[0], m, ja, timeout=args.timeout)
            jb = submit_one(hub, roots[1], m, {"kind": "ps", "timeout": 60},
                            payload=("Set-Content -Path (Join-Path (Get-Location).Path 'hk-b.txt') -Value '"
                                     + psk[32:] + "' -Encoding ASCII -NoNewline; 'B'").encode("utf-8"))
            wait_any(hub, roots[1], m, jb, timeout=args.timeout)
        jid = submit(hub, m, {"kind": "ps", "timeout": 90, "_legacy": True}, payload=script.encode("utf-8"))
        log(f"  provision -> {m} ({jid})")
        try:
            r = wait_job(hub, m, jid, timeout=args.timeout, show=False)
            log("    " + (r.get("_stdout") or "").strip()[:120])
        except SystemExit:
            log(f"  WARNING: {m} did not answer in time")
    if not args.no_restart:
        log("")
        cmd_restart(hub, _NS(machine=args.machine, all=args.all, no_wait=False, timeout=args.timeout))
    if args.lock_legacy:
        log("")
        log("machines now refuse unsigned jobs. Verify: run <m> -e 1  (sealed) and drop a")
        log("hand-written job.json into their inbox - it must come back status=rejected.")


RESTART_PS = """
# detached: kill the body a few seconds from now; its launcher starts a fresh one that
# reloads settings.ini (PSK, mirrors, policy). Never touches the production software.
$inner = 'Start-Sleep -Seconds 4; ' + \
  'Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and ' + \
  '($_.CommandLine -like ''*omp-body.ps1*'' -or $_.CommandLine -like ''*omp-body.ps1*'') } | ' + \
  'ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }'
Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList @('-NoProfile','-Command',$inner) | Out-Null
'body will reload settings in ~4s'
"""


def cmd_restart(hub: Hub, args) -> None:
    """Restart the body so it re-reads settings.ini (launcher brings it back)."""
    machines = [resolve_machine(hub, args.machine)] if args.machine else []
    if args.all:
        machines = sorted(d for d in os.listdir(os.path.join(hub.root, "machines"))
                          if os.path.isdir(os.path.join(hub.root, "machines", d)) and not d.startswith("_"))
    if not machines:
        die("give a machine name or --all")
    for m in machines:
        jid = submit(hub, m, {"kind": "ps", "timeout": 60}, payload=RESTART_PS.encode("utf-8"))
        log(f"  restart -> {m} ({jid})")
        if not args.no_wait:
            try:
                wait_job(hub, m, jid, timeout=args.timeout, show=False)
            except SystemExit:
                log(f"  WARNING: {m} did not answer in time")





def cmd_selftest(hub: Hub, args) -> None:
    """Prove the whole protocol on this box: fake share, real scripts, no model."""
    root = args.root or os.path.join(tempfile.gettempdir(), "ompremote-selftest")
    if os.path.isdir(root):
        shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    th = Hub(root)
    machine = "SELFTEST"
    th.ensure(machine)
    local = os.path.join(root, "local")
    os.makedirs(local)
    results = []

    def record(name, ok, detail=""):
        results.append((name, bool(ok), detail))
        log(("PASS  " if ok else "FAIL  ") + name + ("   " + detail if detail else ""))

    shutil.copyfile(os.path.join(BUNDLE_SRC, "omp-body.ps1"), os.path.join(local, "omp-body.ps1"))
    import re as _re
    _src = open(os.path.join(BUNDLE_SRC, "omp-body.ps1"), "rb").read()
    _m = _re.search(rb"\$BodyVersion\s*=\s*'([0-9]+\.[0-9]+\.[0-9]+[^']*)'", _src)
    _sem = _m.group(1).decode() if _m else "0.0.0"
    _ver = _sem + "-" + hashlib.sha1(_src).hexdigest()[:8]
    os.makedirs(os.path.join(root, "bundle"), exist_ok=True)
    shutil.copyfile(os.path.join(BUNDLE_SRC, "omp-body.ps1"), os.path.join(root, "bundle", "omp-body.ps1"))
    write_text(os.path.join(root, "bundle", "version.txt"), _ver + "\n")
    write_text(os.path.join(local, "body-version.txt"), _ver + "\n")
    write_text(os.path.join(local, "hub.txt"), root + "\n")
    write_text(os.path.join(local, "settings.ini"), "MODEL=\nEXTRA_ARGS=--no-title\n")

    proc = subprocess.Popen(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", os.path.join(local, "omp-body.ps1"),
         "-Hub", root, "-Machine", machine, "-PollSec", "1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)
    try:
        deadline = time.time() + 40
        while time.time() < deadline and not os.path.isfile(th.m(machine, "state", "heartbeat.json")):
            time.sleep(0.5)
        hb = read_json(th.m(machine, "state", "heartbeat.json")) or {}
        record("body starts and beats", hb.get("machine") == machine, "body=" + str(hb.get("body_version")))
        record("sysinfo written", os.path.isfile(th.m(machine, "state", "sysinfo.json")))

        # 1. inline powershell, with Chinese + exit code
        jid = submit(th, machine, {"kind": "ps"}, payload=BOM + "Write-Output '中文输出 OK'\r\nWrite-Output ('pwd=' + (Get-Location).Path)\r\nexit 0\r\n".encode("utf-8"))
        res = wait_job(th, machine, jid, timeout=180, follow=False, show=False)
        record("run -e: powershell executes", res.get("status") == "ok" and "中文输出 OK" in res["_stdout"],
               "status=%s out=%r" % (res.get("status"), res["_stdout"][:40]))

        # 2. exit code propagates
        jid = submit(th, machine, {"kind": "ps"}, payload=BOM + b"Write-Output 'bye'\r\nexit 7\r\n")
        res = wait_job(th, machine, jid, timeout=180, follow=False, show=False)
        record("exit code propagates", res.get("exit") == 7 and res.get("status") == "error",
               "exit=%s status=%s" % (res.get("exit"), res.get("status")))

        # 3. timeout kill
        jid = submit(th, machine, {"kind": "ps", "timeout": 4}, payload=BOM + b"Start-Sleep -Seconds 60\r\n")
        res = wait_job(th, machine, jid, timeout=180, follow=False, show=False)
        record("timeout kills the task", res.get("status") == "timeout" and res.get("timed_out") is True,
               "status=%s" % res.get("status"))

        # 4. cwd is respected
        work = os.path.join(root, "workdir")
        os.makedirs(work, exist_ok=True)
        jid = submit(th, machine, {"kind": "ps", "cwd": work}, payload=BOM + b"Write-Output (Get-Location).Path\r\n")
        res = wait_job(th, machine, jid, timeout=180, follow=False, show=False)
        record("cwd is honoured", work.lower() in (res["_stdout"] or "").lower(), res["_stdout"].strip()[:60])

        # 5. fetch round trip
        os.makedirs(os.path.join(root, "logs"), exist_ok=True)
        for i in range(3):
            with open(os.path.join(root, "logs", "m%d.log" % i), "wb") as f:
                f.write((("line %d\n" % i) * 200).encode())
        jid = submit(th, machine, {"kind": "fetch", "patterns": [os.path.join(root, "logs", "*.log")], "max_mb": 50})
        res = wait_job(th, machine, jid, timeout=240, follow=False, show=False)
        manifest = read_text(th.m(machine, "out", jid + ".manifest.tsv"))
        got = len([l for l in manifest.splitlines() if l.count("\t") == 2 and "FAIL" not in l and "MISS" not in l])
        record("fetch copies files + manifest", res.get("status") == "ok" and got == 3, "files=%s" % got)

        # 6. push round trip, sha1 verified
        payload = os.urandom(120000)
        target = os.path.join(root, "incoming", "blob.bin")
        jid = submit(th, machine, {"kind": "push", "target": target}, push_files={"blob.bin": payload})
        res = wait_job(th, machine, jid, timeout=240, follow=False, show=False)
        ok = os.path.isfile(target) and sha1_file(target) == sha1_bytes(payload)
        record("push lands the exact bytes", res.get("status") == "ok" and ok)

        # 7. env + args plumbing
        jid = submit(th, machine, {"kind": "ps", "env": {"FOO": "bar"}, "args": "-X yz"},
                     payload=BOM + b'Write-Output ("env=" + $env:FOO + " args=$args")\r\n')
        res = wait_job(th, machine, jid, timeout=180, follow=False, show=False)
        record("env/args reach the script", "env=bar" in (res["_stdout"] or ""), res["_stdout"].strip()[:60])

        # 8. kill switch
        os.makedirs(os.path.join(root, "policy"), exist_ok=True)
        write_text(os.path.join(root, "policy", "disabled.txt"), "test\n")
        jid = submit(th, machine, {"kind": "ps"}, payload=BOM + b"Write-Output 'paused'\r\n")
        time.sleep(6)
        record("kill switch pauses the body", not os.path.isfile(th.m(machine, "out", jid + ".result.json")))
        os.remove(os.path.join(root, "policy", "disabled.txt"))

        # 9. a job id must never execute twice (share ACLs break rename-based claims)
        counter = os.path.join(root, "counter.txt")
        dup_payload = BOM + ('Add-Content -Path "%s" -Value tick\r\n' % counter).encode("utf-8")
        dup_id = "20261021-000000-dead"
        submit(th, machine, {"id": dup_id, "kind": "ps"}, payload=dup_payload)
        first = wait_job(th, machine, dup_id, timeout=180, follow=False, show=False)
        time.sleep(2)
        submit(th, machine, {"id": dup_id, "kind": "ps"}, payload=dup_payload)   # same id again
        time.sleep(8)
        ticks = read_text(counter).count("tick")
        record("duplicate job id is not re-executed", first.get("status") == "ok" and ticks == 1,
               "status=%s ticks=%d" % (first.get("status"), ticks))

        # 10. self-update: publish a newer version and watch the body swap itself in
        sentinel = "9.9.9-selftest" + "\n"
        shutil.copyfile(os.path.join(BUNDLE_SRC, "omp-body.ps1"), os.path.join(root, "bundle", "omp-body.ps1"))
        write_text(os.path.join(root, "bundle", "version.txt"), sentinel)
        updated = False
        for _ in range(45):
            time.sleep(2)
            hb2 = read_json(th.m(machine, "state", "heartbeat.json")) or {}
            if str(hb2.get("body_version", "")).startswith("9.9.9"):
                updated = True
                break
        record("self-update swaps in the published body", updated,
               "body_version=" + str((read_json(th.m(machine, "state", "heartbeat.json")) or {}).get("body_version")))
        if updated:
            jid9 = submit(th, machine, {"kind": "ps"}, payload=BOM + b"Write-Output 'after-update-ok'\r\n")
            res9 = wait_job(th, machine, jid9, timeout=240, follow=False, show=False)
            record("updated body still executes jobs", res9.get("status") == "ok" and "after-update-ok" in (res9["_stdout"] or ""),
                   res9.get("status", ""))

        # 11. omp kind (optional)
        if args.with_omp:
            jid = submit(th, machine, {"kind": "omp", "prompt": "Reply with exactly: BODY-OK", "timeout": 240,
                                       "model": args.model})
            res = wait_job(th, machine, jid, timeout=400, follow=False, show=False)
            record("omp job kind works when a model is reachable",
                   res.get("status") == "ok" and "BODY-OK" in (res["_stdout"] or ""),
                   "status=%s out=%r" % (res.get("status"), (res["_stdout"] or "")[:40]))
        # 12. identity is recorded even when the name was pinned on the command line
        ident = read_json(th.m(machine, "state", "identity.json")) or {}
        record("identity fingerprint is recorded",
               ident.get("name") == machine and len(str(ident.get("fp") or "")) >= 6,
               "name=%s fp=%s" % (ident.get("name"), ident.get("fp")))

        # 13. two hosts sharing a COMPUTERNAME must not share a hub folder (v2.4.0)
        clash_root = os.path.join(root, "clash-hub")
        real_host = norm_machine(os.environ.get("COMPUTERNAME", "host"))
        claim_dir = os.path.join(clash_root, "machines", real_host, "state")
        os.makedirs(claim_dir, exist_ok=True)
        write_text(os.path.join(claim_dir, "identity.json"),
                   '{"ah":1,"name":"%s","fp":"DEADBEEF","hostname":"%s","fp_history":["DEADBEEF"]}'
                   % (real_host, real_host))
        clash_local = os.path.join(root, "clash-local")
        os.makedirs(clash_local, exist_ok=True)
        shutil.copyfile(os.path.join(BUNDLE_SRC, "omp-body.ps1"), os.path.join(clash_local, "omp-body.ps1"))
        write_text(os.path.join(clash_local, "hub.txt"), clash_root + "\n")
        proc2 = subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", os.path.join(clash_local, "omp-body.ps1"),
             "-Hub", clash_root, "-PollSec", "1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=0x08000000)
        split = ""
        try:
            deadline = time.time() + 60
            while time.time() < deadline:
                try:
                    dirs = os.listdir(os.path.join(clash_root, "machines"))
                except OSError:
                    dirs = []
                split = next((d for d in dirs if d.startswith(real_host + "-")), "")
                if split:
                    break
                time.sleep(0.5)
            record("same COMPUTERNAME gets a suffixed folder", bool(split), "folder=" + (split or "-"))
            if split:
                si = read_json(os.path.join(clash_root, "machines", split, "state", "identity.json")) or {}
                record("the split folder carries its own fingerprint",
                       len(str(si.get("fp") or "")) >= 6 and si.get("fp") != "DEADBEEF",
                       "fp=" + str(si.get("fp")))
        finally:
            try:
                proc2.kill()
            except Exception:
                pass

    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-WmiObject Win32_Process -Filter \"Name='powershell.exe'\" | "
                        "Where-Object { $_.CommandLine -like '*ompremote-selftest*' } | "
                        "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"],
                       capture_output=True)

    failed = [r for r in results if not r[1]]
    log("")
    log(f"selftest: {len(results) - len(failed)}/{len(results)} passed   (hub kept at {root})")
    if failed:
        for n, _ok, d in failed:
            log("  FAIL " + n + ("  " + d if d else ""))
        sys.exit(10)


# --------------------------------------------------------------------- main
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ompremote", description="remote control of factory machines over TBZ")
    p.add_argument("--hub", default=os.environ.get("OMP_REMOTE_HUB", DEFAULT_HUB))
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("machines", help="who is alive")
    s.set_defaults(func=cmd_machines)

    s = sub.add_parser("identity", help="what a machine folder is (hostname, fingerprint, claim time)")
    s.add_argument("machine")
    s.set_defaults(func=cmd_identity)

    s = sub.add_parser("ping", help="ask a machine to report its capabilities")
    s.add_argument("machine")
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_ping)

    s = sub.add_parser("run", help="run a script on a machine and wait for the output")
    s.add_argument("machine")
    s.add_argument("-e", "--code", default=None, help="inline PowerShell (use \\n for newlines)")
    s.add_argument("-f", "--file", default=None, help="local script file to upload and run")
    s.add_argument("--kind", default=None, choices=["ps", "cmd"], help="script dialect")
    s.add_argument("--cwd", default=None)
    s.add_argument("--args", default=None, help="arguments appended to the script")
    s.add_argument("--env", action="append", default=None, help="NAME=VALUE, repeatable")
    s.add_argument("--timeout", type=int, default=900)
    s.add_argument("--wait-timeout", type=int, default=0)
    s.add_argument("--note", default="")
    s.add_argument("--no-wait", action="store_true")
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("ls", help="list a directory on a machine (newest first)")
    s.add_argument("machine")
    s.add_argument("-p", "--path", required=True)
    s.add_argument("--top", type=int, default=40)
    s.set_defaults(func=cmd_ls)

    s = sub.add_parser("fetch", help="copy files from a machine (sha1 verified)")
    s.add_argument("machine")
    s.add_argument("-p", "--pattern", action="append", required=True)
    s.add_argument("--dest", default=None)
    s.add_argument("--max-mb", type=int, default=2000)
    s.add_argument("--timeout", type=int, default=1800)
    s.add_argument("--wait-timeout", type=int, default=0)
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_fetch)

    s = sub.add_parser("push", help="copy one file to a machine (sha1 verified)")
    s.add_argument("machine")
    s.add_argument("-s", "--source", required=True)
    s.add_argument("-d", "--target", required=True)
    s.add_argument("--timeout", type=int, default=1800)
    s.add_argument("--wait-timeout", type=int, default=0)
    s.set_defaults(func=cmd_push)

    s = sub.add_parser("ask", help="drive an omp installed on that machine (needs model access there)")
    s.add_argument("machine")
    s.add_argument("prompt")
    s.add_argument("-c", "--cont", action="store_true")
    s.add_argument("--cwd", default=None)
    s.add_argument("--model", default=None)
    s.add_argument("--mode", default="text", choices=["text", "json"])
    s.add_argument("--approval", default="yolo", choices=["yolo", "write", "always-ask"])
    s.add_argument("--max-time", default=None)
    s.add_argument("--timeout", type=int, default=1800)
    s.add_argument("--wait-timeout", type=int, default=0)
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_ask)

    s = sub.add_parser("health", help="self-healing verdict: body progress + watchdog state")
    s.add_argument("machine", nargs="?", default=None)
    s.add_argument("--verbose", action="store_true")
    s.add_argument("--strict", action="store_true", help="exit 6 when any machine needs attention")
    s.set_defaults(func=cmd_health)

    s = sub.add_parser("jobs", help="inbox/run/out listing for a machine")
    s.add_argument("machine")
    s.set_defaults(func=cmd_jobs)

    s = sub.add_parser("tail", help="print or follow a job's files")
    s.add_argument("machine")
    s.add_argument("job")
    s.add_argument("--watch", action="store_true")
    s.set_defaults(func=cmd_tail)

    s = sub.add_parser("rfid", help="control the on-machine LLRP monitor (record/pause/stop/status/tail/records/start)")
    s.add_argument("machine")
    s.add_argument("action", choices=["start", "record", "pause", "stop", "status", "tail", "records"])
    s.add_argument("-n", type=int, default=20)
    s.set_defaults(func=cmd_rfid)

    s = sub.add_parser("prune", help="delete inbox files whose job already has a result")
    s.add_argument("machine")
    s.set_defaults(func=cmd_prune)

    s = sub.add_parser("cancel", help="stop a running job")
    s.add_argument("machine")
    s.add_argument("job")
    s.set_defaults(func=cmd_cancel)

    s = sub.add_parser("kill", help="terminate a process on the machine")
    s.add_argument("machine")
    s.add_argument("--pid", type=int, default=None)
    s.add_argument("--name", default=None)
    s.set_defaults(func=cmd_kill)

    s = sub.add_parser("stopall", help="pause every body on the share")
    s.add_argument("--off", action="store_true")
    s.set_defaults(func=cmd_stopall)

    s = sub.add_parser("deploy", help="publish bridge files to the hub")
    s.add_argument("--include-omp", action="store_true")
    s.set_defaults(func=cmd_deploy)

    s = sub.add_parser("bootstrap", help="install/start the body on a machine via AnchorHub")
    s.add_argument("machine")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_bootstrap)

    s = sub.add_parser("keygen", help="create the pre-shared key that seals jobs/results")
    s.add_argument("--rotate", action="store_true", help="park the old key as omp.key.prev and mint a new one")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("upgradekey", help="move machines to per-machine HKDF seeds (DPAPI at rest)")
    s.add_argument("--machines", default=None)
    s.add_argument("--all", action="store_true")
    s.add_argument("--timeout", type=int, default=180)
    s.set_defaults(func=cmd_upgradekey)

    s = sub.add_parser("rotatekey", help="move machines onto ctl/omp.key (old key must be in omp.key.prev)")
    s.add_argument("--machines", default=None)
    s.add_argument("--all", action="store_true")
    s.add_argument("--timeout", type=int, default=180)
    s.set_defaults(func=cmd_rotatekey)

    s = sub.add_parser("secure", help="install the PSK + hub mirrors on machines (sealed job)")
    s.add_argument("machine", nargs="?")
    s.add_argument("--all", action="store_true", help="every machine folder on the hub")
    s.add_argument("--lock-legacy", action="store_true", help="also set ALLOW_LEGACY=0")
    s.add_argument("--timeout", type=int, default=180)
    s.add_argument("--no-restart", action="store_true", help="leave the running body alone")
    s.add_argument("--split", dest="split", action="store_true", default=False,
                   help="send the key in two halves over two roots (needs the mirror known)")
    s.set_defaults(func=cmd_secure)

    s = sub.add_parser("restart", help="restart the body so it reloads settings.ini")
    s.add_argument("machine", nargs="?")
    s.add_argument("--all", action="store_true")
    s.add_argument("--no-wait", action="store_true")
    s.add_argument("--timeout", type=int, default=120)
    s.set_defaults(func=cmd_restart)

    s = sub.add_parser("selftest", help="end-to-end protocol test on this box")
    s.add_argument("--root", default=None)
    s.add_argument("--with-omp", action="store_true")
    s.add_argument("--model", default="deepseek/deepseek-flash")
    s.set_defaults(func=cmd_selftest)

    return p


def require_hub(cli_value: str | None) -> str:
    """Return the hub root or stop with an instruction the operator/agent can act on."""
    root = (cli_value or "").strip() or hub_env() or ""
    if not root:
        die(
            "no hub configured.\n"
            "Ask the user for the share path their machines can already write\n"
            "(a UNC such as \\\\server\\share\\_omp, or a mounted path), then either:\n"
            "  python src/ompremote.py --hub \'\\\\server\\share\\_omp\' machines\n"
            "  set OMP_REMOTE_HUB=//server/share/_omp\n"
            "  export OMP_REMOTE_HUB=//server/share/_omp\n"
            "Nothing is hardcoded here on purpose: the path is site specific."
        )
    return root


def main() -> None:
    args = build_parser().parse_args()
    hub = Hub(require_hub(args.hub))
    hub.mirrors = [m for m in DEFAULT_MIRRORS if m.rstrip("\\/") != hub.root]
    args.func(hub, args)


if __name__ == "__main__":
    main()