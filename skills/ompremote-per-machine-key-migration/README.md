<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# 每机密钥迁移（全队一把 PSK → HKDF seed + DPAPI）

**什么时候用**：机队还在用一把全队共用的预共享密钥，你想让"一台机被拷走 = 只泄露这一台"。

**做什么**：控制端持唯一 master，用 `HKDF-SHA256(master, "omp/seed/"+机台名)` 为每台机派生 seed；
机台只拿到自己的 seed，落盘前用 DPAPI（`CurrentUser`，必要时回退 `LocalMachine`）封装。

**四个实测坑**（都写进正文）：
1. PowerShell 5.1 不自动加载 `System.Security`，`Protect` 返回空 → 写出空 blob 并把明文钥删掉，机台变"无钥"；
2. 因此 body 必须有"完全无钥时回退 legacy"的自救路径，否则远程再也进不去；
3. 验证要看明文 stdout，不要看结果文件（换钥过程中结果可能暂时解不开）；
4. 解密用的元组顺序、以及"机台白名单"是第二道闸，都可能造成假失败。

---

**怎么用**：把 `SKILL.md` 交给你的 agent（例如「读 skills/ompremote-per-machine-key-migration/SKILL.md 并按它执行」），或自己当 checklist 过一遍。
