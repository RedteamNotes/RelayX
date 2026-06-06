# RelayX

[English](../README.md) | [中文](README.zh-CN.md) | [Français](README.fr.md)

**面向授权红队行动的 OPSEC 感知 NTLM relay 暴露面评估、实验室校准验证与受控执行编排工具。**

<img align="left" src="assets/relayx-logo.png" alt="RelayX logo" width="195">

RelayX 是面向授权红队和安全评估工作的 OPSEC 感知 Python 工具。它将 NTLM
relay 暴露面评估、实验室校准验证与受控执行编排统一到企业常见服务场景中，
构建 source-to-target relay 路径，依据证据和操作风险排序，记录受控验证
决策，并输出适合红队、蓝队和报告流程使用的结果。

RelayX 致敬 Impacket `ntlmrelayx` 以及 NTLM relay 研究生态。它不是为了
替代这些项目，而是把 relay readiness、路径优先级、实验室校准、执行控制
和修复分析统一到同一套证据模型里。

默认情况下，RelayX 不捕获凭据、不转发 NTLM 身份验证、不执行 source-side
coercion。目标探测以 readiness 为主。可选的 synthetic authentication
validation 必须显式开启，并可能产生失败登录类遥测。

<p align="center">
  <img src="assets/RelayX-SS.png" alt="RelayX CLI help screenshot" width="100%">
</p>

## 能力概览

- SMB signing、HTTP/HTTPS NTLM、LDAP/LDAPS、MSSQL TDS/SSPI readiness
  探测。
- HTTP、LDAP/LDAPS、MSSQL 的 NTLM Type1/Type2 challenge-flow 证据，不提交
  真实凭据。
- MSSQL TDS-wrapped TLS 协商，以及服务端 TLS 完成时的
  `tls-server-end-point` CBT 证据。
- 可选 synthetic Type3 authentication validation，用于在授权条件下观察
  HTTP、LDAP/LDAPS、MSSQL 的拒绝语义。
- 面向 EPA、LDAP signing、LDAPS CBT、MSSQL encryption/EPA 的保守响应分类
  和共享 evidence key。
- Protocol oracle hardening，包含 response subclassification、policy
  inference、脱敏 oracle signature、标准化 observation 和 remaining
  uncertainty，便于 calibration 与 diff。
- WebClient/WebDAV、Spooler、EFSRPC、DFSNM、FSRVP、MSSQL outbound
  authentication、ADIDNS、ghost SPN、name-resolution inducement 的 source
  capability 建模。
- source-to-target path 构建，包含 scope guardrail、route/pivot awareness、
  noise filtering、blocker、fix 和 OPSEC note。
- Route/Pivot Awareness，支持 source session、segment、subnet、结构化
  `route_hops`、Ligolo、Sliver P2P、SOCKS、tun2socks、port forwarding、hop
  count、reachability state、route risk scoring，以及不会开启 pivot session
  的可选授权 direct TCP reachability check。
- Relay decision calculus，包含 rule ID、target family、precondition、
  hardening gate、防御控制和修复优先级。
- HTTP/IIS EPA、AD CS Web Enrollment EPA、LDAP signing、LDAPS CBT、MSSQL
  encryption/EPA policy state 的 lab calibration profile。
- lab baseline comparison，说明某个发现为什么可以提升判断，或为什么仍必须
  保持保守。
- lab signature corpus 提取和 calibration profile 草案生成，用于可重复的红蓝
  对抗演练研究。
- dry-run、armed、confirmed 三种模式的受控 validation / execution record，
  包含 operator context、timebox/noise/scope 检查和 JSONL audit log。
- WebClient/WebDAV、RPC coercion surface、MSSQL outbound authentication、
  name-resolution path 的 source validation planning，不执行 source trigger。
- OPSEC policy evaluation，覆盖 validation、execution 和 source planning，
  包含 noise ceiling、scope requirement、confirmed-mode context、
  network-action boundary、expected telemetry 与 rollback check。
- assessment 与 validation 的 operation control，包含 rate limit、delay、
  jitter、scheduled operation window、listener/callback scope contract，以及
  machine-clean output preservation。
- execution module inventory、compatibility planning 和 Adapter SDK dispatch，
  支持内置离线审计记录适配器、JSON manifest 模块定义、credential policy
  guardrail、listener policy guardrail、confirmed mode 硬阻断的 lab-only
  adapter fixture、one-shot/timeout/evidence-capture contract 和可审计
  adapter lifecycle record。
- versioned schema 与 evidence contract validation，覆盖 result file、lab
  profile、corpus、lab provenance report、execution record、evidence report、
  module manifest、OpenGraph、JSONL、CSV、OPSEC policy 和 route report
  artifact。
- standard lab matrix planning 和 corpus coverage verification，覆盖
  HTTP/IIS EPA、AD CS Web Enrollment EPA、LDAP signing、LDAPS CBT、MSSQL
  encryption/EPA 策略状态。
- lab corpus provenance review，区分 synthetic fixture、authorized lab
  capture metadata、endpoint build metadata、drift baseline 和 operator
  promotion decision。
- lab response differential analysis，用于比较稳定 lab policy state
  signature，区分真正的 response discriminator 和仅作上下文参考的字段。
- evidence completeness reporting，用于审计 finding/path 证据记录、
  protocol judgement 字段、source taxonomy、confidence 分布、缺失 contract key
  和剩余不确定性。
- graph、SIEM、CSV、HTML/Markdown report、scan diff、remediation impact
  simulation 等企业输出。
- enterprise bundle 生成，包含 manifest、artifact hash、schema status、
  可选 route report 和可发布交付元数据。
- CI / release quality gate，覆盖 package metadata、schema contract、JSON
  fixture、企业文档、GitHub workflow、wheel build 和 install smoke test。
- 常用 CLI flag 提供短选项别名，并在 curated help 中解释短写适用场景和
  长选项更清晰的场景。

## 安装

RelayX 需要 Python 3.11 或更新版本。

```bash
git clone https://github.com/RedteamNotes/RelayX.git
cd RelayX

python3 -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

relayx --version
```

通过 pipx 安装命令行工具：

```bash
pipx install git+https://github.com/RedteamNotes/RelayX.git
relayx --version
```

## 快速开始

运行目标评估并写出 RelayX result file：

```bash
relayx scan --targets examples/targets.txt --out result.json
relayx summary result.json
relayx matrix result.json
```

加入 source profile、scope policy 和 enterprise workflow profile：

```bash
relayx scan \
  --profile enterprise \
  --targets examples/targets.txt \
  --sources examples/sources.csv \
  --scope examples/scope.txt \
  --out result.json
```

查看 relay path、decision、control 和 remediation：

```bash
relayx paths result.json
relayx routes --result result.json
relayx routes --result result.json --target-protocol ldap --connect-check --rate-limit 60 --format json --out relayx-routes.json
relayx calculus result.json
relayx evidence-report --result result.json
relayx controls result.json
relayx fixes result.json
relayx plan result.json PX-0001 --format json --out plan.json
```

运行受控验证或离线执行记录：

```bash
relayx validate --result result.json --path-id PX-0001 --mode dry-run
relayx validate --result result.json --path-id PX-0001 --mode confirmed --confirm --operator redpen --reason "authorized target reprobe" --audit-log audit.jsonl --scope filesrv01 --reprobe --stop-before 2030-01-01T18:00:00+08:00
relayx run --result result.json --path-id PX-0001 --module relayx_audit_record --mode confirmed --confirm --operator redpen --reason "authorized offline audit record" --audit-log audit.jsonl --scope filesrv01
```

导出企业产物：

```bash
relayx export --result result.json --format opengraph --out relayx-opengraph.json
relayx export --result result.json --format jsonl --out relayx-events.jsonl
relayx bundle --result result.json --out-dir relayx-bundle
relayx diff old-result.json new-result.json --format json --out relayx-diff.json
relayx simulate-fixes result.json --control smb_signing --format json
relayx quality-gate --project-root .
```

验证 schema 和 evidence contract：

```bash
relayx schema list
relayx schema validate result.json
relayx schema validate --kind lab-profile fixtures/lab_profiles
```

## 完整示例教程

RelayX 提供一套完整的离线示例教程，覆盖 result model、path ranking、
route awareness、calibration、受控 validation、离线 execution audit、企业
export、diff、remediation simulation 和 schema validation。该教程不会访问
真实网络：

```bash
relayx -q summary examples/tutorial/sample-result.json
relayx -q paths examples/tutorial/sample-result.json -b
relayx -q bundle -r examples/tutorial/sample-result.json -d /tmp/relayx-tutorial-bundle
```

完整英文 runbook 见 [docs/TUTORIAL.md](TUTORIAL.md)，中文版本见
[docs/TUTORIAL.zh-CN.md](TUTORIAL.zh-CN.md)。示例 fixture 位于
[examples/tutorial](../examples/tutorial)。
授权 AD/IIS/AD CS/MSSQL lab 的 integration-test 期望见
[docs/INTEGRATION_TESTS.md](INTEGRATION_TESTS.md)。

## 命令参考

```text
relayx scan              评估目标并写出 RelayX result file
relayx assess            scan 的别名
relayx summary           汇总 finding 和 candidate path
relayx matrix            按 host/protocol 展示 relay readiness
relayx sources           展示 source asset 和 modeled capability
relayx source-check      在不执行 trigger 的情况下检查 source capability
relayx source-plan       创建 source-trigger validation plan
relayx routes            评估 route 和 pivot reachability
relayx paths             列出 relay candidate path
relayx calculus          展示 rule decision 和 hardening gate
relayx controls          展示防御控制优先级
relayx calibrate         应用 lab calibration profile
relayx compare-baseline  比较 baseline 和 candidate lab result signature
relayx lab-matrix        输出标准 RelayX lab policy matrix
relayx lab-corpus        从 result 提取 lab calibration signature
relayx lab-verify        按标准矩阵验证 lab corpus 覆盖
relayx lab-provenance    审计 lab corpus provenance 和 review readiness
relayx lab-stability     评估重复 lab capture 的稳定性和漂移
relayx lab-diff          比较稳定 lab policy-state response differential
relayx lab-index         汇总 lab signature corpus
relayx lab-profile       从 corpus 生成 calibration profile 草案
relayx evidence-report   审计 evidence completeness、source taxonomy 和 judgement 字段
relayx validate          对单条 path 运行受控 active validation
relayx profiles          列出内置 RelayX profile
relayx export            导出 graph、JSONL、CSV、report 或 diagram 产物
relayx bundle            写出经过验证的 enterprise handoff bundle
relayx diff              比较两个 RelayX result file
relayx simulate-fixes    模拟修复对 relay path 的影响
relayx quality-gate      运行本地 CI 和 release quality gate
relayx schema            列出或验证 schema 和 evidence contract
relayx opsec             列出或查看 OPSEC policy
relayx discover          按任务或关键词搜索命令和 topic
relayx next              根据当前 result/path 推荐下一步命令
relayx modules           列出 execution module manifest
relayx module-plan       评估 execution module 是否适用于某条 path
relayx run               运行受控 execution state machine
relayx console           启动带上下文 prompt 的本地 operator console
relayx completion        输出 bash、zsh 或 fish completion 脚本
relayx rank              按 impact、confidence 和 OPSEC cost 排序 path
relayx explain           解释某个 host 或 path
relayx fixes             展示修复优先级
relayx plan              为单条 path 创建 OPSEC-aware dry-run plan
relayx report            导出 JSON、Markdown、HTML、Mermaid 或 CSV
```

RelayX 也提供 curated help topic：

```bash
relayx help
relayx help getting-started
relayx help commands
relayx help workflows
relayx help exports
relayx help short-options
relayx help safety
relayx help calibration
relayx help execution
relayx help enterprise
relayx help troubleshooting
relayx help completion
relayx help scan
relayx help run --format json
relayx help schema
relayx --no-banner help
```

人类可读的 help 和命令输出会显示 RelayX banner 与当前版本。需要紧凑输出时可用
`--no-banner`。JSON、CSV、HTML、Markdown、Mermaid 和企业 export payload 会保持
机器可读，不插入 banner。

## 发现命令与下一步

知道任务但不记得命令时，用 `discover`；已有 RelayX result 后，用 `next` 获取
具体下一步命令。

```bash
relayx discover epa
relayx discover jsonl
relayx discover route --group Route/Pivot
relayx next
relayx next --result result.json
relayx next --result result.json --path-id PX-0001
```

`discover` 会搜索 command name、group、example、output contract、help topic 和
safety note。`next` 是只读引导：它不会执行 validation、execution、probe、export，
也不会修改文件；只有你手动运行建议命令时才会进入对应 workflow。

## 短选项

高频参数提供短选项。共享 runbook 和脚本中，长选项通常更清晰；交互式操作时，
短选项更高效。

```bash
relayx scan -t examples/targets.txt -s examples/sources.csv -S examples/scope.txt -o result.json
relayx validate -r result.json -p PX-0001 -m dry-run
relayx export -r result.json -f jsonl -o relayx-events.jsonl
relayx bundle -r result.json -d relayx-bundle -F opengraph,jsonl,csv
relayx quality-gate -C . -f json -o relayx-quality-gate.json
```

使用 `relayx help short-options` 查看别名表。`-A/--auth-validation`、
`-y/--confirm`、`-P/--opsec-policy` 这类安全敏感选项只是别名；RelayX 仍然
强制执行 operator、reason、scope、audit 和 adapter guardrail。

## Operator Console 与 Completion

`relayx console` 是本地单进程 operator console，用来在同一个 result、path、
OPSEC policy 和 scope 上重复分析。它会在 prompt 中显示当前上下文，并调用与
脚本化 workflow 相同的 CLI handler 和 guardrail。

```bash
relayx console --result result.json --path-id PX-0001 --opsec-policy strict
relayx console --history-file ~/.relayx/history
relayx console --no-history --no-completion
relayx completion zsh > relayx.zsh
relayx discover epa
relayx next --result result.json
relayx help getting-started
relayx --no-color help run
```

console 内可使用 `use result <file>`、`use path PX-0001`、`set opsec-policy
strict`、`show summary`、`show paths`、`explain`、`validate`、`run`、`export`、
`bundle`、`discover`、`next`、`menu`、`help`、`?`、`clear`、`cls`、`history`、
`back` 和 `exit`。

交互式 console 支持 readline 行编辑、上下键历史、Tab 补全、持久化历史和
清屏命令。敏感终端可使用 `--no-history`、`RELAYX_NO_HISTORY=1`，或在命令前
加一个空格避免写入历史；需要关闭 console Tab 补全时使用 `--no-completion`。

## 输出格式

- `json`：完整 RelayX result 或命令输出，适合自动化处理。
- `markdown` / `html`：面向 operator 和 stakeholder 的评估报告；HTML
  report 支持 status、severity、protocol、source capability、target family、
  defensive control 和 free-text 离线过滤。
- `mermaid`：轻量路径图。
- `csv`：面向表格审阅的 finding/path 输出，带稳定 field contract。
- `jsonl`：面向 SIEM 和蓝队管道的一行一个事件输出，带稳定 event ID 和
  field contract version。
- `opengraph`：BloodHound/OpenGraph 风格的自定义 graph，包含 RelayX node
  和 edge kind、artifact 内 mapping、确定性 edge ID 和 control node。
- `bundle-manifest`：带 hash 和 schema status 的 enterprise bundle manifest。
- `quality-gate`：面向 package、fixture、docs 和 workflow 检查的 CI/release
  gate report。

## Schema Contract

RelayX 内置 versioned schema 和 evidence contract validator：

```bash
relayx schema list --format json
relayx schema validate result.json --format json
relayx schema validate --kind module-manifest fixtures/execution_modules
```

支持的 kind 包括 `result`、`evidence`、`lab-profile`、`lab-corpus`、
`lab-provenance`、`lab-stability`、`lab-differential`、`evidence-report`、
`execution-record`、`module-manifest`、`opsec-policy`、`route-report`、
`bundle-manifest`、`quality-gate`、`opengraph`、`jsonl` 和 `csv`。
验证报告会按字段路径解释问题；artifact 不符合所选 contract 时返回 exit code `2`。

`relayx diff` 会报告 added/removed/changed path，以及 exposure trend、score
delta、control trend、remediation regression 和 remediation improvement。
`relayx simulate-fixes` 会报告 affected path、control dependency、remaining
control、remaining target family 和 estimated residual exposure。

`relayx evidence-report -r result.json` 会离线审计已有 result，不产生网络流量。
它会标出缺少 evidence 的 candidate/relayable record、缺少 policy inference 或
remaining uncertainty 的 protocol judgement record，以及仍为 unknown confidence
的 evidence entry，并统计 wire observation、policy inference、lab calibration、
source model、route model、control mapping 和 operator context 等 evidence source
类别。

## 实验室校准

RelayX 在网络证据存在歧义时默认保持保守。lab calibration profile 允许团队
把受控策略状态映射到 RelayX 观察到的 signature：

```bash
relayx calibrate result.json --profiles fixtures/lab_profiles --annotate-out calibrated-result.json
relayx compare-baseline --baseline epa-off.json --candidate epa-required.json --profiles fixtures/lab_profiles
relayx lab-matrix --target-family mssql_epa --format json --out lab-matrix.json
relayx lab-verify --corpus fixtures/lab_corpus --format json --out lab-verify.json
relayx lab-provenance --corpus fixtures/lab_corpus --format json --out lab-provenance.json
relayx lab-stability --corpus fixtures/lab_corpus --min-captures 2 --format json --out lab-stability.json
relayx lab-diff --corpus fixtures/lab_corpus --target-family http_iis_epa --format json --out lab-diff.json
relayx lab-corpus result.json --label iis-epa-required --policy-state epa_required --expected-state epa_or_cbt_enforcement_signal --promotion promote --format json --out corpus.json
relayx lab-profile --corpus corpus.json --profile-id http_iis_epa_lab --target-family http_iis_epa --service http --format json --out profile.json
```

只有当 profile 和 baseline 差异支持结论时，RelayX 才会提升 finding 的判断。
否则它会保留原始保守状态，并解释仍然缺失的证据。

`lab-matrix`、`lab-verify`、`lab-provenance`、`lab-stability`、`lab-diff`、
`lab-corpus` 和 `lab-profile` 是离线研究辅助命令，不会产生新的网络流量。它们把
已有 RelayX result 转成可复用 signature corpus，按标准策略矩阵验证覆盖，审计
provenance 和 operator review readiness，评估重复 capture 的稳定性和漂移，
比较稳定策略状态之间的 response discriminator，并生成 profile 草案，便于后续
人工审查。Synthetic fixture 可用于 pipeline test 和示例，但 RelayX 不会把它
当成真实 lab promotion evidence。`lab-diff` 面向 corpus 内稳定状态的响应差异；
比较两个 RelayX result file 时使用 `compare-baseline`。

## 安全边界

RelayX 只用于你拥有或明确授权评估的系统。默认评估不 relay 凭据，不执行
source-side coercion。`--auth-validation` 会发送 synthetic NTLM authenticate
message 和 placeholder credential，可能产生失败认证遥测。

confirmed validation 和 execution 要求 operator identity、reason、
confirmation 和 audit log；confirmed execution 还要求显式 scope。当前内置且
支持的 execution adapter 只做离线审计记录。执行通过 RelayX Adapter SDK dispatch；未注册 adapter、不安全
credential policy、不安全 listener policy，以及 manifest support 声明不一致
都会被 guardrail 阻断。live relay adapter 默认不可用。

## 致谢

RelayX 受公开 NTLM relay 研究和工具启发，包括 Impacket `ntlmrelayx`、
NetExec、Microsoft hardening guidance 以及 Microsoft protocol
specifications 等。
RelayX 重新实现自身逻辑，不直接引入 GPL 项目代码。
