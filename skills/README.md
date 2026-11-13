<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Skills

可复用的操作手册（每份一个目录：`README.md` 是给人看的介绍，`SKILL.md` 是给 agent 执行的正文）。

| Skill | 用途 |
|---|---|
| [ompremote-operator-access](ompremote-operator-access/README.md) | 给除机队负责人外的同事/agent 使用共享盘作业通道时的权限模型与操作规矩。 |
| [ompremote-per-machine-key-migration](ompremote-per-machine-key-migration/README.md) | 把机队从全队一把 PSK 迁到每机 HKDF seed + DPAPI 的实操步骤与四个坑。 |
| [sanitized-public-repo-release](sanitized-public-repo-release/README.md) | 把带生产数据的内部工具做成可公开仓库的清洗流程与检查清单。 |
| [github-license-recognition-and-dual-license](github-license-recognition-and-dual-license/README.md) | GitHub 许可证识别范围、许可选型，以及 AGPL + 商业双许可的切换步骤。 |
| [ompremote-share-channel-crypto](ompremote-share-channel-crypto/README.md) | # 共享盘作业通道：加密与密钥卫生

适用于"控制端往 SMB 共享投作业文件 → 机台执行 → 结果写回共享"这类通道 |
| [ompremote-bridge-selfheal](ompremote-bridge-selfheal/README.md) | # 自治代理：心跳、看护与自愈

适用于"机台上跑一个轮询代理，靠共享盘收发作业"的场景。真正的事故不是"进程崩了"，而 |

## 约定

- 每份 skill 只写**方法**，不写具体机台/IP/密钥；
- 涉及权限的 skill 一律以「负责人保留吊销权」为前提；
- 不包含任何规避终端安全、跳板中继、注入类内容。

许可：AGPL-3.0-or-later，闭源商用需另行授权（见根目录 `NOTICE`）。
