<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# 共享盘通道：加密与密钥卫生

**什么时候用**：你在设计/评审一个"共享盘投作业"的通道，需要判断加密够不够、密钥会不会漏、出问题能不能解释。

**一句话**：加密只解决"内容不被读"，不解决"谁干的"；可审计面（心跳、作业清单）必须保持可读。

**不要**：把心跳也加密、做跳板中转、改终端安全配置。

---

**怎么用**：把 `SKILL.md` 交给你的 agent（例如「读 skills/ompremote-share-channel-crypto/SKILL.md 并按它执行」），或自己当 checklist 过一遍。
