<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# GitHub 许可证识别 + AGPL 双许可切换（实测流程）

适用：要把自研工具挂到 GitHub，先确认「GitHub 会不会点亮 License 徽章」，再在
「开源但商用要谈」和「禁止商用」之间做选择，并把许可落到每个文件。

## 1. 事实：徽章只认那 47 个

GitHub 的 License 识别来自 `licensee`，数据源就是 `choosealicense.com`：

```bash
git clone --depth 1 https://github.com/github/choosealicense.com
ls choosealicense/_licenses        # 47 个 .txt，就是"能被识别"的全集
```

- 全集里 **没有** PolyForm、Business Source（`bsl-1.0` 是 Boost，不是 Business）、Elastic、CC-BY-NC。
  用这些 → 仓库页显示 **`NOASSERTION`**，"License" 侧栏不分类。
- 全集里 **每一个都允许商用** —— OSI 定义禁止 field-of-use 限制。所以「能被识别」与
  「禁止商用 / 商用须授权」在单一许可证里**不可能同时成立**。
- 能商用、但要"逼商用方来谈"的只有靠 copyleft 的摩擦：GPL-3.0（分发触发）或
  **AGPL-3.0（网络服务也触发，§13）**，再配商业双许可。
- 想要"内部商用也要付费"，任何版权许可都做不到：内部使用通常不算分发，只能靠合同/不公开。

## 2. 选型一分钟表

| 目的 | 选 | 徽章 |
|---|---|---|
| 广泛采用、只要署名 | MIT / Apache-2.0（企业更认专利条款） | ✅ |
| 改了必须回流（文件级） | MPL-2.0 | ✅ |
| 衍生作品必须开源 | GPL-3.0 | ✅ |
| 连 SaaS 都要开源，闭源商用来买授权 | **AGPL-3.0-or-later + 商业许可** | ✅ |
| 就是禁止商用 | PolyForm Noncommercial 1.0.0 | ❌ NOASSERTION |
| 先限几年再自动放开 | BUSL-1.1 | ❌ |

## 3. 切到 AGPL 双许可（可照抄）

```bash
# 1) 取官方文本（choosealicense 的 .txt 带 YAML frontmatter，必须剥掉）
python - <<'PY'
raw=open("choosealicense/_licenses/agpl-3.0.txt",encoding="utf-8").read()
body=raw.split("---",2)[2].lstrip("\n") if raw.startswith("---") else raw
open("LICENSE","w",encoding="utf-8",newline="").write(body)
PY

# 2) 逐文件改 SPDX（md 用 HTML 注释；json 用 "_license" 字段）
#    sed -i 's/PolyForm-Noncommercial-1.0.0/AGPL-3.0-or-later/g' 命中所有文件

# 3) NOTICE 写双许可：AGPL 免费（含商用，但衍生/网络服务须开源）+ 商业许可联系方式

# 4) README 末节 + docs/licensing.md 用表格写清"哪种用法走哪条"

# 5) 提交推送（github 直连不稳时加 -c http.version=HTTP/1.1）
git -c http.version=HTTP/1.1 push -u origin main
```

**建仓/推送（无 gh、无 PAT 时）**

```bash
TOK=$(printf "protocol=https\nhost=github.com\n\n" | git credential fill | sed -n 's/^password=//p')
curl -sS -X POST -H "Authorization: Bearer $TOK" -H "Accept: application/vnd.github+json" \
  https://api.github.com/user/repos \
  -d '{"name":"<repo>","private":false,"description":"…"}'
# 然后 git remote add origin https://github.com/<user>/<repo>.git && git push
```

**回验（必须做）**

```bash
curl -sS -H "Authorization: Bearer $TOK" https://api.github.com/repos/<user>/<repo> \
 | python -c "import sys,json;d=json.load(sys.stdin);print((d.get('license') or {}).get('spdx_id'))"
# 期望 AGPL-3.0；PolyForm 时期这里是 NOASSERTION。识别有几秒延迟 → 失败重试 2~3 次，每次隔 8s。
```

## 4. 双许可的法律前提（别忽略）

- 你必须**拥有全部版权**才可另售商业许可。接受外部 PR 就要 `CONTRIBUTING.md` 要求签 **CLA**；
  只做 DCO（`Signed-off-by`）时，商业许可对他人贡献部分会有瑕疵。
- AGPL 不禁止商用：内部自用一般不触发；对外分发或对外提供网络服务才触发 §13（须向用户提供完整对应源码）。
  这条建议让法务确认一次。
- 换许可后，历史提交仍是旧许可（已发布版本按当时的许可），新版本按新许可——这是正常且合法的。

## 5. 环境坑（这台机器实测）

- `>/dev/null` 在这个 shell 会报「系统找不到指定的路径」——**不要用重定向**，用 `python -c` 吞输出或直接容忍输出。
- 刚写过的文件偶发 `PermissionError`（DLP/占用）：`os.chmod(p,0o666)` 后写 `p+".tmp"` 再 `os.replace`。
- `raw.githubusercontent.com` 可能 DNS 不通，但 `github.com`（git）和 `api.github.com` 通 —— 回验走 API，不要走 raw。
- 含中文的 `.ps1`/`.md` 写回用 `encoding="utf-8"`/`utf-8-sig` + `newline=""`，别让 CRLF 转换混进 diff。
