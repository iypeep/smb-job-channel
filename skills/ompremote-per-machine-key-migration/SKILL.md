<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# smb-job-channel：把机队从"全队一把钥"迁到"每机密钥 + DPAPI"（v2）

## 契约（迁移后）

| 位置 | 内容 |
|---|---|
| `ctl\omp.key` | 唯一 master（32B），只在办公机 |
| 派生 | `seed(M) = HKDF-SHA256(master, "omp/seed/" + MACHINE_UPPER)` |
| 机台 `settings.ini` | `PSK_PROTECTED=<DPAPI blob>` + `KEY_SCHEME=hkdf2`，**无明文 `PSK`** |
| 机台派生 | `K_mac/K_enc = HKDF-SHA256(seed, "omp/job-mac"|"omp/job-enc")`（PS 里要自己实现 RFC 5869） |
| 心跳 | `key_scheme` / `key_scope`(CurrentUser|LocalMachine) / `key_error` |

控制器侧同样的派生，所以**不需要为每台机存 key 文件**；机台只持 seed → 拿一台不等于拿全队。

## 命令

```bash
python ctl\ompremote.py upgradekey --machines <M>          # 先单台
python ctl\rotate_fleet.py 6 120 upgradekey                # 全队并发块（第 3 个参数是子命令）
python ctl\ompremote.py health <M> --verbose               # key_scheme/key_scope，NO-KEY 标记
```

`upgradekey` 可重入：已 `hkdf2` 且 `psk=true` 的机台直接跳过。机台版本门：`body_version >= 2.7.3`，
更老的 body 不认识 `PSK_PROTECTED`/`KEY_SCHEME`，会跳过并提示等自更新（**别硬推，会把旧 body 变无钥**）。

## 四个实测坑（按出现顺序）

1. **PS 5.1 不自动加载 `System.Security`**：`[System.Security.Cryptography.ProtectedData]` 类型解析失败，
   `Protect` 返回 `$null`，脚本继续写成 `PSK_PROTECTED=`（空）并删掉明文 `PSK` → 机台**无钥**，
   密封作业全被拒，且没有作业通道可以救。
   修：`Add-Type -AssemblyName System.Security`；`Protect` 后校验长度，**失败就保留旧钥直接 exit 1**。
2. **无钥机台要有自救**：body 从 2.7.3 起，若既无 `PSK` 也无 `PSK_PROTECTED`，强制允许 legacy 明文作业
   （否则远程永远进不去），并写 `NO KEY ...` 日志。有钥机台仍严格拒收明文作业（`ALLOW_LEGACY=0` 不受影响）。
   `upgradekey` 发现 `psk=false` 会先投明文修复作业（写 seed），再走正常 DPAPI 下发。
3. **验证别读结果文件**：换钥/换 scheme 的窗口期结果可能暂时解不开，把"解不开"当"被拒绝"会造成假失败。
   改成投 `Write-Output ('verify-ok')`，看 `run\<id>.stdout.txt`（明文）里有没有 `verify-ok`。
4. **解密的元组顺序**：`machine_keys()` 返回 `(K_mac, K_enc)`，而历史代码里候选列表是 `(K_enc, K_mac)`；
   混用会 MAC 用错钥 → 报 "failed its integrity check"，但用正确的钥解同一个文件是好的。
   排查手法：手工读结果 json，对两个 scheme 各算一次 `HMAC(K_mac, "res|"+jid+"|"+blob)` 比对。

## 验证

```bash
python ctl\ompremote.py health --verbose        # 应全为 hkdf2 + CurrentUser，无 NO-KEY/KEY-ERR
# 端到端：在已迁移机台上跑一条作业，确认 stdout 正常回显
python ctl\ompremote.py run <M> -e 'Write-Output "v2-e2e"'
```

再抽查机台的 `settings.ini`：应只有 `PSK_PROTECTED=`，没有 `PSK=`；`state\hb.json` 的 `key_error` 为空。

## 失败/回滚

| 现象 | 处置 |
|---|---|
| 某台 `psk=false` 且 `allow_legacy=true` | 直接再跑 `upgradekey --machines <M>`（走明文修复路径） |
| `key_error` 非空（DPAPI 解不开） | 看 `key_scope`；机台 body 若由 SYSTEM 计划任务启动而 blob 是 CurrentUser，会落到 LocalMachine 尝试；仍失败则用明文修复作业重写 |
| 想整体退回 v1 | `keygen --rotate` + `rotatekey --all`，机台重新拿到全队钥（明文 `PSK=`），再删 `KEY_SCHEME` |

## 与"共享盘不稳"的关系

迁移期间会出现大量并发 SMB 往返。实测公盘曾经整体不可达（`ping` 100% 丢包、`Test-Path` 为 False），
此时 `upgradekey` 会报 `hub not reachable`；**机台侧是安全的**（settings 写完的会自己重启生效），
网络恢复后重跑一次即可，命令可重入。
