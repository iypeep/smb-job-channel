<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# 共享盘通道：operator 接入

**什么时候用**：你不是机队负责人，但需要在机台上跑查询/拉日志；或者你在写一个替别人操作机台的 agent。

**核心**：机队有一把 master 私钥，只在负责人机器上；operator 拿的是 token，经网关（HTTP）间接用密钥。
token 决定四件事：能碰哪些机台、能下发哪类作业、什么时候失效、出问题能不能被追溯。

**给出/使用权限时的默认值**：operator 不写 `machines` 就等于"零权限"。这是故意的——宁可让人来申请，
也不要一次手滑把整队开出去。

**边界**：不复制私钥、不自己另建控制端、不做跳板中转、不改终端安全配置。

---

**怎么用**：把 `SKILL.md` 交给你的 agent（例如「读 skills/ompremote-operator-access/SKILL.md 并按它执行」），或自己当 checklist 过一遍。
