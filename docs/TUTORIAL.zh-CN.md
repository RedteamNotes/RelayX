# RelayX 完整离线教程

本教程使用 `examples/tutorial` 中的离线 fixture，走完一条完整的
RelayX workflow。它适合培训、文档、CI smoke test 和 runbook 开发。教程不会
扫描网络、不会中继凭据，也不会触发 source-side coercion。

正式迁移到授权 lab 或演练环境前，建议先用本教程理解 RelayX result model、
evidence、uncertainty、OPSEC gate、route metadata、remediation control、
enterprise output 和 controlled execution audit record。

## 场景

教程模拟一个小型企业评估：

- `jump01.redteamnotes.com`：带 WebClient、Spooler capability metadata 和
  Ligolo route 的授权 source。
- `sqlagent01.redteamnotes.com`：带 MSSQL outbound-auth capability metadata
  和 P2P route 的授权 source。
- `filesrv01.redteamnotes.com`：SMB signing not required 的示例路径。
- `ca01.redteamnotes.com`：需要 EPA calibration 的 AD CS Web Enrollment
  HTTP NTLM 路径。
- `dc01.redteamnotes.com`：LDAP/LDAPS 保守 signing 和 CBT 解释示例。
- `sql01.redteamnotes.com`：带 TDS-wrapped TLS 与 CBT evidence 的 MSSQL
  SSPI 路径，EPA enforcement 仍保持保守判断。

目标不是证明利用，而是展示 RelayX 如何记录证据、剩余不确定性、OPSEC gate、
route metadata、修复控制、enterprise output 和受控执行审计记录。

## 文件

| 文件 | 用途 |
| --- | --- |
| `examples/tutorial/targets.txt` | 迁移到 live lab 时可替换的 target list。 |
| `examples/tutorial/scope.txt` | 覆盖教程 host 和 CIDR 的 scope 示例。 |
| `examples/tutorial/sources.json` | Source capability 与 route/pivot metadata。 |
| `examples/tutorial/baseline-result.json` | 用于 diff 示例的小型 baseline result。 |
| `examples/tutorial/sample-result.json` | 本教程使用的完整离线 result。 |

`sample-result.json` 是标准 RelayX result file，可用于任何接受 `--result`
或 positional result 参数的命令。

## 预检查

在仓库根目录运行：

```bash
relayx -V
relayx -q help workflows
relayx -q help getting-started
relayx discover epa
relayx -q quality-gate -C .
```

知道任务但不确定命令时，用 discovery：

```bash
relayx discover epa
relayx discover jsonl
relayx discover route --group Route/Pivot
```

拿到 result file 后，用 `next` 获取具体下一步命令：

```bash
relayx next --result examples/tutorial/sample-result.json
relayx next --result examples/tutorial/sample-result.json --path-id PX-0001
```

可选 shell completion：

```bash
relayx completion zsh > /tmp/relayx.zsh
relayx completion bash > /tmp/relayx.bash
relayx completion fish > /tmp/relayx.fish
```

验证教程 fixture：

```bash
relayx -q schema validate -k result examples/tutorial/sample-result.json
relayx -q schema validate -k result examples/tutorial/baseline-result.json
```

期望结果是 `valid: true` 且没有 error。

也可以使用 `relayx console` 在同一个 result 上重复分析。Console 会记住
result、path、OPSEC policy 和 scope，并调用与脚本化 workflow 相同的 guarded
CLI handler。默认 human-readable help 和 console 输出会使用 ANSI 分色；需要
纯文本时使用 `--no-color` 或 `NO_COLOR` 环境变量。

```bash
relayx -q console --result examples/tutorial/sample-result.json --path-id PX-0001 --opsec-policy strict
relayx --no-color -q console --result examples/tutorial/sample-result.json
relayx -q console --history-file ~/.relayx/history
relayx -q console --no-history --no-completion
```

console 示例命令：

```text
context
menu
next
discover jsonl
show summary
show paths
explain
clear
history
validate --mode dry-run
run --mode dry-run
exit
```

在交互式终端中，RelayX 会通过 readline 提供行编辑、上下键历史、Tab 补全，
以及终端后端支持时的 Ctrl-L 清屏。需要显式命令时可以使用 `clear` 或 `cls`。
敏感场景可使用 `--no-history`、`RELAYX_NO_HISTORY=1`，或在命令前加一个空格
避免写入持久化历史。

## 1. 查看 Result

先看摘要：

```bash
relayx -q summary examples/tutorial/sample-result.json
```

再查看 source asset 和 modeled capability：

```bash
relayx -q sources examples/tutorial/sample-result.json
```

解释要点：

- Source capability metadata 是建模输入，不代表 RelayX 执行了 source trigger。
- Route metadata 是建模输入，不代表 RelayX 打开或操作了 pivot session。
- result metadata 中 `active=false` 表示教程 result 是离线 artifact。

## 2. 查看 Readiness 与 Path

显示 readiness matrix：

```bash
relayx -q matrix examples/tutorial/sample-result.json
```

列出 candidate 和 blocked path：

```bash
relayx -q paths examples/tutorial/sample-result.json -b
```

稳定路径锚点：

| Path | 含义 | 初始解释 |
| --- | --- | --- |
| `PX-0001` | WebClient source 到 AD CS Web Enrollment over HTTP NTLM | 高影响 candidate；EPA state 未证明。 |
| `PX-0002` | Source 到 SMB signing not required 服务 | 有明确 hardening control 的 candidate path。 |
| `PX-0003` | Source 到 LDAP/389，带 NTLM negotiation evidence | Candidate，但 LDAP signing policy 仍保守。 |
| `PX-0004` | SQL-adjacent source 到 MSSQL SSPI，带 TLS CBT evidence | Candidate；MSSQL EPA enforcement 仍保守。 |
| `PX-0005` | Source 到 LDAPS/636 | 被 modeled route awareness 阻断。 |

解释单条 path：

```bash
relayx -q explain examples/tutorial/sample-result.json PX-0001
```

`PX-0001` 会展示 observed evidence、blocker、fix 和 OPSEC note。RelayX 会把
EPA state 保持为保守状态，因为 synthetic authentication rejection 不足以证明
EPA 是 off、accepted 还是 required。

审计 evidence contract：

```bash
relayx -q evidence-report -r examples/tutorial/sample-result.json -f json -o /tmp/relayx-evidence-report.json
relayx -q schema validate -k evidence-report /tmp/relayx-evidence-report.json
```

`evidence-report` 是离线命令。它用于发现缺失 evidence、protocol judgement
field、remaining uncertainty、confidence assignment 或 source taxonomy 的记录，
避免在 lab promotion 或 enterprise handoff 前把不完整证据当作结论。

## 3. 查看 Route / Pivot Awareness

生成 route report：

```bash
relayx -q routes -r examples/tutorial/sample-result.json -f json -o /tmp/relayx-routes.json
relayx -q schema validate -k route-report /tmp/relayx-routes.json
```

Route/pivot awareness 默认是 model-driven。RelayX 使用 `session`、`segment`、
`subnets` 和结构化 `route_hops` 来解释可能的 reachability 与 route risk。

授权 lab 或评估窗口内，可以添加 operator-runtime direct TCP observation：

```bash
relayx -q routes \
  -r examples/tutorial/sample-result.json \
  -P ldap \
  --connect-check \
  --rate-limit 60 \
  -f json \
  -o /tmp/relayx-routes-checked.json
```

`reachability_check` 只是 operator runtime 的 direct TCP context，适合 review
route profile，但不等价于证明 session-backed pivot 当前可用。

## 4. 理解 Calculus 与 Controls

查看 rule、control 和 remediation metadata：

```bash
relayx -q calculus examples/tutorial/sample-result.json
relayx -q controls examples/tutorial/sample-result.json
relayx -q fixes examples/tutorial/sample-result.json
```

为最高优先级 path 输出 OPSEC-aware plan：

```bash
relayx -q plan examples/tutorial/sample-result.json PX-0001 -f json -o /tmp/relayx-px0001-plan.json
```

模拟修复影响：

```bash
relayx -q simulate-fixes examples/tutorial/sample-result.json -c smb_signing -c http_epa -f json -o /tmp/relayx-simulation.json
```

Simulation 是只读的。它估算实施某些 control 后，modeled path 数量和 path score
会如何下降，并保留 control dependency、remaining control、remaining target
family 和 estimated residual exposure。

## 5. 应用 Lab Calibration

使用内置 calibration profile：

```bash
relayx -q calibrate examples/tutorial/sample-result.json -p fixtures/lab_profiles -f json -o /tmp/relayx-calibration.json
```

比较 baseline 和 richer sample：

```bash
relayx -q compare-baseline \
  -b examples/tutorial/baseline-result.json \
  -c examples/tutorial/sample-result.json \
  -p fixtures/lab_profiles \
  -f json \
  -o /tmp/relayx-baseline-compare.json
```

查看 lab corpus 的 provenance、stability 和 differential：

```bash
relayx -q lab-provenance -c fixtures/lab_corpus -f json -o /tmp/relayx-lab-provenance.json
relayx -q schema validate -k lab-provenance /tmp/relayx-lab-provenance.json
relayx -q lab-stability -c fixtures/lab_corpus -m 2 -f json -o /tmp/relayx-lab-stability.json
relayx -q schema validate -k lab-stability /tmp/relayx-lab-stability.json
relayx -q lab-diff -c fixtures/lab_corpus -m 2 -f json -o /tmp/relayx-lab-diff.json
relayx -q schema validate -k lab-differential /tmp/relayx-lab-diff.json
```

Calibration 是 RelayX 从保守推断走向更强 judgement 的路径。只有当 provenance、
operator review、repeat-capture stability 以及 profile 或 baseline difference
都支持时，finding 才能被提升。否则 RelayX 应说明为什么不能提升以及还剩什么
uncertainty。

## 6. 规划 Guarded Validation

Dry-run validation 可安全用于教程：

```bash
relayx -q validate \
  -r examples/tutorial/sample-result.json \
  -p PX-0001 \
  -m dry-run \
  -f json \
  -o /tmp/relayx-validation-dry-run.json
```

Confirmed validation 更严格：

```bash
relayx validate \
  -r result.json \
  -p PX-0001 \
  -m confirmed \
  -y \
  -O redpen \
  -R "authorized target reprobe" \
  -A audit.jsonl \
  --reprobe \
  --stop-before 2030-01-01T18:00:00+08:00
```

只在授权 lab 或评估窗口内使用 confirmed validation。若启用
`--auth-validation`，RelayX 会发送带 placeholder credential 的 synthetic NTLM
Authenticate message，可能产生 failed-logon telemetry。

## 7. 记录 Controlled Execution Decision

内置 supported adapter 是 offline audit-record adapter。它用于记录 controlled
execution decision：

```bash
relayx -q run \
  -r examples/tutorial/sample-result.json \
  -p PX-0001 \
  -M relayx_audit_record \
  -m confirmed \
  -y \
  -O redpen \
  -R "authorized offline tutorial audit" \
  -A /tmp/relayx-audit.jsonl \
  -S examples/tutorial/scope.txt \
  -f json \
  -o /tmp/relayx-execution-record.json
```

验证 execution record：

```bash
relayx -q schema validate -k execution-record /tmp/relayx-execution-record.json
```

这是训练或 CI 中测试 execution state machine 的稳妥方式。Confirmed execution
需要 explicit scope、operator identity、reason、confirmation 和 audit log。

## 8. 生成 Enterprise Outputs

导出 graph、SIEM 和 spreadsheet artifact：

```bash
relayx -q export -r examples/tutorial/sample-result.json -f opengraph -o /tmp/relayx-opengraph.json
relayx -q export -r examples/tutorial/sample-result.json -f jsonl -o /tmp/relayx-events.jsonl
relayx -q export -r examples/tutorial/sample-result.json -f csv -o /tmp/relayx.csv
```

验证 artifact：

```bash
relayx -q schema validate -k opengraph /tmp/relayx-opengraph.json
relayx -q schema validate -k jsonl /tmp/relayx-events.jsonl
relayx -q schema validate -k csv /tmp/relayx.csv
```

生成完整 handoff bundle：

```bash
relayx -q bundle \
  -r examples/tutorial/sample-result.json \
  -d /tmp/relayx-tutorial-bundle \
  -F opengraph,jsonl,csv,html,markdown,mermaid \
  -f json \
  -o /tmp/relayx-tutorial-bundle-summary.json

relayx -q schema validate -k bundle-manifest /tmp/relayx-tutorial-bundle/manifest.json
```

Bundle manifest 会记录 artifact path、format、schema kind、validation status、
byte count 和 SHA256 hash，是推荐的 team handoff package。

## 9. 比较多次扫描

比较 baseline 和 full sample：

```bash
relayx -q diff \
  examples/tutorial/baseline-result.json \
  examples/tutorial/sample-result.json \
  -f json \
  -o /tmp/relayx-tutorial-diff.json
```

预期 diff 会展示 AD CS、MSSQL 和 LDAPS 示例新增 path。JSON diff 还包含
exposure trend、score delta、control trend、remediation regression 和
remediation improvement。

## 10. 迁移到授权 Lab

从离线教程迁移到真实 lab 时：

1. 用授权 lab host 替换 `examples/tutorial/targets.txt`。
2. 用明确的 host、CIDR、source、listener、callback boundary 替换
   `examples/tutorial/scope.txt`。
3. 用真实授权 source metadata 替换 `examples/tutorial/sources.json`；需要 pivot
   context 时加入 `route_hops`。
4. 运行 readiness scan：

   ```bash
   relayx scan \
     -t lab-targets.txt \
     -s lab-sources.json \
     -S lab-scope.txt \
     -o lab-result.json
   ```

5. 在任何 confirmed action 前审阅 `summary`、`paths`、`routes`、`calculus`、
   `controls`、`plan` 和 `validate --mode dry-run`。
6. 仅在 failed-logon telemetry 被授权和监控时使用 `--auth-validation`。
7. 将 audit log、route report、calibration output 和 enterprise bundle 保存在
   engagement evidence set 中。

## 解释检查清单

将任何 path 从 analysis 推进到 validation 前，回答这些问题：

- RelayX 直接观察到了什么？
- RelayX 从观察中推断了什么？
- 哪些 evidence key 支持该推断？
- `relayx evidence-report` 是否存在 failure 或 unresolved warning？
- 哪些 blocker 仍然适用？
- 哪些 defensive control 能降低或移除该 path？
- 哪些 source capability 和 route assumption 只是 modeled，而不是 live-tested？
- 如果 validation 进入 confirmed 状态，预期 telemetry 是什么？
- 哪些 OPSEC policy gate 必须通过？
- calibration 后还剩什么 uncertainty？

当这些答案都能在 result、plan、validation record 或 enterprise bundle 中找到时，
RelayX 的判断才最有价值。
