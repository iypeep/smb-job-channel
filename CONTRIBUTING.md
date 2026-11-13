<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Contributing

Thanks for wanting to improve this. Two rules, both short.

## 1. Sign-off and CLA

Every commit needs a `Signed-off-by:` line (`git commit -s`), and by submitting a pull request you
agree to the following:

1. **You wrote it**, or you have the right to submit it, and you are not violating anyone's
   copyright or an employer's IP agreement.
2. **License grant to the maintainer.** You grant Benedict Tang a perpetual, worldwide,
   non-exclusive, royalty-free, irrevocable copyright and patent license to use, reproduce,
   modify, distribute and **relicense** your contribution — including under a commercial license.
3. **License to everyone else.** Your contribution is made available to the public under
   AGPL-3.0-or-later, the project's default license.
4. **No warranty.** Contributions are provided "as is", without warranty of any kind.

Point 2 is what makes dual licensing possible: without the right to relicense, the maintainer
could not offer a commercial license covering your code. If you cannot agree to it, please open
an issue instead of a pull request.

## 2. Scope

Welcome: protocol/robustness fixes, Windows/PS 5.1 compatibility, tests, documentation,
performance, portability.

**Not accepted** (they will be closed):

- anything that hides this channel from endpoint security, IT, or audit logs;
- relaying/pivoting traffic through third-party machines, process injection, or kernel drivers;
- changing or disabling security software configuration.

The design keeps the beacon, job list and audit readable on purpose — see
[docs/protocol.md](docs/protocol.md) and [docs/key-management.md](docs/key-management.md).

## 3. Before you open a PR

```bash
python src/ompremote.py selftest      # protocol end-to-end on a fake hub
python -m py_compile src/ompremote.py src/ompweb.py
```

Keep the SPDX header in every file you touch, and do not add identifiers of your own
infrastructure (share paths, hostnames, keys) to the code or docs.
