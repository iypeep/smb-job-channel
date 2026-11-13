<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# 内部工具 → 可公开仓库

**什么时候用**：手上有个能跑的工具，想开源/公开，但它沾了生产数据、内网地址、密钥，或者有不想公开的实现细节。

## 1. 白名单导出，不要"整个目录删一删"

复制**源码 + 文档**到你控制的另一个目录，而不是在原目录上做清理。原目录里永远有你忘掉的东西
（抓取下来的样本、日志、数据库 dump、构建产物、`.venv`）。

## 2. 三类必须清掉的东西

| 类别 | 例子 | 处理 |
|---|---|---|
| 基础设施标识 | 内网 IP、共享盘 UNC、主机名、域账号 | 统一替换成文档保留地址（`192.0.2.10`、`\fileserver\share`） |
| 业务标识 | 机台编号、工位名、客户名、项目代号 | 换成 `MACHINE-001` 这类占位符 |
| 凭据与运行态 | 私钥、token、审计日志、抓取的配置 | **不要导出**（不是替换，是不进仓） |

## 3. 逐文件加 SPDX

每个源码/文档第一行：`SPDX-License-Identifier: <id>`（md 用 `<!-- -->`，json 用字段）。
好处：许可跟着文件走，别人整段复制也带着条款。

## 4. 残留扫描必须 0 命中

不要只 grep 你替换过的东西。至少覆盖：

```bash
grep -rniE "10\.[0-9]+\.[0-9]+\.[0-9]+|[A-Z]:\\Users|\\[a-z0-9.-]+\|@[a-z0-9.-]+\.(com|cn)"
grep -rniE "token|secret|password|BEGIN .*PRIVATE KEY"
```

再加一份"业务词表"（机台/工位/客户/项目代号）逐词 grep —— 这一遍最容易漏。

## 5. 许可与 NOTICE

`LICENSE` 用官方全文（别手抄），`NOTICE` 写版权行 + 双许可/例外说明；
GitHub 只认 `choosealicense.com` 那 47 个（PolyForm/BUSL/Elastic 会显示 `NOASSERTION`）。

## 6. 推送与回验

```bash
git init && git add -A && git commit -m "feat: initial import"
# 没有 gh：用 git 凭据里的 token 走 API 建仓，再 push
curl -X POST -H "Authorization: Bearer $TOK" https://api.github.com/user/repos      -d '{"name":"my-tool","private":false}'
git push -u origin main
```

回验三件事：`GET /repos/<o>/<r>` 的 `private`、`license.spdx_id`、`git/trees/<branch>?recursive=1`
的文件清单里没有敏感路径。**推送前**把这些都跑一遍，推送后只做只读核对。
