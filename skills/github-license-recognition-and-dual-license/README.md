<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# GitHub 许可证识别与双许可

**什么时候用**：想让仓库显示 License 徽章、又想让"商用要授权"；或者纠结 AGPL/GPL/MPL/Apache 怎么选。

**事实**：GitHub 只识别 `choosealicense.com` 那 47 个（≈ OSI/FSF 清单）。PolyForm、Business Source、
Elastic、CC-BY-NC 都不在里面 → 一律显示 `NOASSERTION`。而且这 47 个**全部允许商用**——OSI 的定义禁止按用途限制。

**所以**："非商用免费 + 商用授权" 与 "被识别" 只能二选一，或者走 **AGPL + 商业双许可**：
闭源商用要么接受 AGPL（衍生与网络服务都要开源），要么来买商业许可。

---

**怎么用**：把 `SKILL.md` 交给你的 agent（例如「读 skills/github-license-recognition-and-dual-license/SKILL.md 并按它执行」），或自己当 checklist 过一遍。
