<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Commercial license](https://img.shields.io/badge/license-commercial%20available-informational)](NOTICE)

[English](README.md) · **简体中文**

# smb-job-channel（共享盘作业通道）

用 **SMB 共享盘当控制面**的小型作业通道：控制端把一个**已签名并加密**的作业文件投到目录里，
目标机上的代理执行它，再把**加密结果**写回。适用于那种"没有入站网络、也没有外网，但有一个可写共享盘"
的机器（产线机台、隔离网段的工控机等）。

没有 broker、没有隧道、没有中转、不做进程注入、不装驱动。文件进、文件出，中间是带认证的加密。

## 为什么需要它

这类机器往往只能访问一样东西：一台文件服务器。它们需要的不是吞吐，而是**可归因 + 可校验**：

- 能写共享盘的人，不能因此让机器执行任意代码；
- 能读共享盘的人，不能读到作业内容与执行结果；
- 事后必须能回答"谁在什么时候对哪台机器做了什么"。

## 工作原理

```
控制端（办公机）                            共享盘                         代理（机台）
  src/ompremote.py  --- inbox/<id>.job.json + files/<id>.enc --->  omp-body.ps1
                    <-- out/<id>.result.json（加密）---------------（轮询、执行、回写）
                    <-- state/hb.json（故意保持明文）
```

- 信封 `ah2`：作业体 AES-256-CBC/PKCS7，签名 HMAC-SHA256 覆盖规范串
  （id、kind、机台、时间戳、nonce、sha256(密文)、超时）；
- 拒绝条件：MAC 不符 / 时间戳超出 ±900 秒 / nonce 重放 / 投错机台 / 密文缺失；
- 结果同样加密；MAC 不符一律拒收，绝不"尽力解析"；
- 心跳 `state/hb.json` 每秒钟写一次且**保持明文**——看护、控制端、人都靠它判断健康；
- 看护（`omp-watch.cs` 编译版，`omp-watch.ps1` 兜底）发现心跳停了就杀进程并让启动器重拉：
  body 卡在 SMB 调用里是不会退出的，"退出才重启"永远不触发；
- 密钥：控制端持唯一 master，每台机只拿到**自己那份** HKDF seed，落盘用 DPAPI 封装。

协议细节见 [docs/protocol.md](docs/protocol.md)，密钥方案见 [docs/key-management.md](docs/key-management.md)。

## 明确不做的事

- **不是用来对 IT 隐藏的**：心跳、作业清单、审计日志故意保持可读；
- **不做跳板/中继**：不用别的机器转发流量；
- **不改终端安全**：不动杀软/EDR 配置、不写白名单、不注入、不装驱动；
- 没有云端依赖，没有遥测。

## Skills（可复用手册）

每个目录一份：`README.md` 给人看（这份做什么、什么时候用），`SKILL.md` 给 agent 执行。
索引：[skills/README.md](skills/README.md)。

| Skill | 内容 |
|---|---|
| [operator-access](skills/ompremote-operator-access/README.md) | 每人一个 token：机台范围、可下发类型、到期、审计 |
| [share-channel-crypto](skills/ompremote-share-channel-crypto/README.md) | 该加密什么、什么必须保持可读、密钥卫生与边界 |
| [per-machine-key-migration](skills/ompremote-per-machine-key-migration/README.md) | 全队一把钥 → 每机 HKDF seed + DPAPI，含四个坑 |
| [bridge-selfheal](skills/ompremote-bridge-selfheal/README.md) | 本地心跳、杀卡死进程的看护、双实例互杀 |
| [sanitized-public-repo-release](skills/sanitized-public-repo-release/README.md) | 内部工具开源前的清洗与检查清单 |
| [github-license-recognition-and-dual-license](skills/github-license-recognition-and-dual-license/README.md) | GitHub 认哪些许可、AGPL + 商业双许可怎么落 |

## 快速自测（不需要机台）

```bash
python src/ompremote.py selftest   # 假 hub：run/退出码/超时/工作目录/fetch/push/Kill Switch/
                                   # 重复 id/自更新/身份认领
```

## 许可

**双许可：AGPL-3.0-or-later，或商业许可。**

- AGPL-3.0-or-later（默认，见 `LICENSE`）：任何用途都可用，包括商业用途；但衍生作品必须同样开源，
  通过网络对外提供服务时也要向使用者提供完整源码；
- 商业许可（401219981@qq.com）：闭源使用、不想承担 AGPL 义务、或需要支持时使用。

贡献前请读 [CONTRIBUTING.md](CONTRIBUTING.md)（需要 sign-off 与 CLA 授权，双许可才有意义）。
