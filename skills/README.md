<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Skills

可复用的操作手册（每份一个目录：`README.md` 是给人看的介绍，`SKILL.md` 是给 agent 执行的正文）。

| Skill | 用途 |
|---|---|
| [ompremote-operator-access](ompremote-operator-access/README.md) | 机队接入：每人一个 token、机台与作业类型白名单、到期与审计 |
| [ompremote-per-machine-key-migration](ompremote-per-machine-key-migration/README.md) | 全队一把钥 → 每机 HKDF seed + DPAPI，含四个实测坑 |
| [sanitized-public-repo-release](sanitized-public-repo-release/README.md) | 内部工具开源前的白名单导出、清洗、残留扫描与回验 |
| [github-license-recognition-and-dual-license](github-license-recognition-and-dual-license/README.md) | GitHub 认哪些许可、如何做 AGPL + 商业双许可 |
| [ompremote-share-channel-crypto](ompremote-share-channel-crypto/README.md) | 共享盘通道的加密设计、密钥卫生与运营边界 |
| [ompremote-bridge-selfheal](ompremote-bridge-selfheal/README.md) | 本地心跳、杀卡死进程的看护、双实例互杀与自愈验证 |

## 约定

- 每份 skill 只写**方法**，不写具体机台/IP/密钥；
- 涉及权限的 skill 一律以「负责人保留吊销权」为前提；
- 不包含任何规避终端安全、跳板中继、注入类内容。

许可：AGPL-3.0-or-later，闭源商用需另行授权（见根目录 `NOTICE`）。
