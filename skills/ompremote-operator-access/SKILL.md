<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# 使用别人的 smb-job-channel 机队（operator 视角）

这条 skill 给**除机队负责人之外的人/agent**用：你要通过 smb-job-channel 在产线机台上跑命令、拉文件，
但**密钥、策略、吊销权都在负责人手里**。先读这份，再动手。

## 0. 先确认你是不是 operator

| 角色 | 拿得到什么 | 能做什么 |
|---|---|---|
| **owner（负责人）** | `ctl\omp.key`、`ctl\sealed.txt`、`ctl\mobile\tokens.json`、公盘写权限 | 一切；只有他能轮换密钥、改机器白名单、发/吊销 token |
| operator | 一个 token（形如 `op-xxxx`），经网关用 | 在他被授权的机器上跑 `ps` / `ls` / `fetch` / 看结果 |
| viewer | 只读 token | 只看机台列表与心跳，不能下发作业 |

**不要**问负责人要 `omp.key`，也不要在自己机器上 copy 一份 `ctl\` 去直连公盘。理由：
1. 密钥是**唯一**能把作业投进机台的凭据；扩散即等于把整队交出去；
2. 负责人靠 token 文件做吊销，直连会绕过吊销和审计；
3. 公盘上所有机台的 `state\` 都是明文，你直接写 job 会留下无法归因的痕迹。

## 1. 申请（一次，写给负责人）

```
机器：MACHINE-001, MACHINE-00X      # 要具体，不接受"全部"
作业类型：ps, ls, fetch                      # 不要 push/kill/omp，除非确实需要
用途：查 XXX 站位的 Ng 日志 / 拉 SCADA 配置
到期：2026-12-31
```

负责人在 `ctl\mobile\tokens.json` 加一条（这是他的文件，别自己改）：

```json
{"token": "op-8f3c...", "name": "张三", "role": "operator",
 "machines": ["MACHINE-001", "MACHINE-00X-*"],
 "kinds": ["ps", "ls", "fetch", "job"],
 "expires": "2026-12-31"}
```

- `machines` 支持 `fnmatch` 通配；**空数组 = 一台都不许**（默认就是这个，防止手滑放出全队）。
- `kinds` 里 `push`（推文件）、`kill`（结束进程）、`omp`（在机台上驱动 omp）默认不给。
- `expires` 到了当天 23:59 之后即失效，网关返回 401。

## 1.5 公盘路径由负责人提供，不要猜

控制端需要那个"机台能写的共享目录"的 UNC。它不在仓库里，也不该从日志/旧命令里翻出来复用。
向负责人要，然后用 `--hub` 或 `OMP_REMOTE_HUB` 传入；命令报 `no hub configured` 就是在问这个。

## 2. 用网关（推荐，手机/办公机都行）

网关跑在**负责人那台办公机**上（能访问公盘 + 在 HQ_Office 内）：

```bash
python ctl\mobile\ompweb.py --port 8787
# 浏览器打开 http://<办公机WLAN IP>:8787/ ，用 token 登录（cookie，12 小时）
```

接口（都要登录）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/me` | 你的名字/角色 |
| GET | `/api/machines` | 机台列表 + 心跳年龄 + 是否密封 |
| POST | `/api/run` | `{"machine":"...","code":"...","kind":"ps"}` 下发一段 PowerShell |
| GET | `/api/job?machine=..&id=..` | 取作业输出 |
| GET | `/api/audit` | 仅负责人：最近 300 条审计 |

被拒时的返回（照做，不要绕过）：
- `403 没有 <machine> 的权限` → 找负责人加机器，不要换台机重试；
- `403 没有 <kind> 类作业的权限` → 说明这次操作超出授权范围；
- `401 令牌已过期` → 找负责人换新 token；
- `429` → 40 次/分限流，等一下。

## 3. 在机台上做事的规矩

1. **只读优先**：先 `Get-Content` / `Get-ChildItem` / `Get-Process`，别一上来就改。
2. **不碰生产上位机进程**：不要 `Stop-Process` 掉带 `Debug`/`SCADA`/`Laser` 的进程；确需重启先问负责人。
3. **不留垃圾**：不要往机台写临时文件；要落盘就落到 `$env:TEMP` 并在同一次作业里删掉。
4. **作业是异步的**：`/api/run` 只是投递，结果用 `/api/job` 取；别在原地 sleep 等。
5. **不要自己修"通道问题"**（心跳停、作业超时）：先报给负责人。他手上有 `health`、
   `probe-watch-procs.ps1`、`stage-watch-exe.ps1` 这些工具；你自己动手容易把看护/密钥搞坏。

## 4. 排查用的安全动作（不需要额外授权）

```powershell
# 机台是否在跑、看护是否新鲜（返回的是明文，方便你看）
Get-Content "<install>\state\watch.json" -Raw
# 最近一轮心跳
Get-Content "<install>\state\hb.json" -Raw
# 不要在机台上打印任何 PSK / settings.ini 的 PSK 行
```

## 5. 边界（负责人明确写死的）

- **不做跳板/中继**：不要用一台机台去连另一台机台转发流量，也不要借别人的电脑当代理。
- **不加密"给别人看的东西"**：机台心跳/审计保持明文，可读性就是可追责性。
- **不擅自轮换密钥**：`keygen --rotate` / `rotatekey` 是负责人动作，做错会让整队掉线。

## 6. 出事怎么办

| 现象 | 你的动作 |
|---|---|
| 作业 `rejected: bad mac` | 你的 token 没问题，是通道在轮换密钥；等 1 分钟重投，仍失败就报负责人 |
| 作业 `aborted_by_watchdog` | 机台 body 被重启过；重投一次，别连投五次 |
| 心跳年龄很大 | 机台离线或时钟偏；报负责人，不要尝试"修" |
| 你误跑了危险命令 | **立刻**告诉负责人（他会看 audit.jsonl），不要试图清理痕迹 |
