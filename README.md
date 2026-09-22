# 本地安全事件关联检测引擎（Go）

一个可完全本地运行的安全事件关联检测引擎：用本地产生的多格式事件流模拟真实日志，
在**乱序到达、并发摄取、迟到事件与运行期规则变更**下，保证告警结论**一致、不漏不重、可解释**。

无任何外部依赖（标准库实现），可离线运行与重复验证。

## 快速开始

```bash
# 端到端演示：生成模拟日志（含乱序/重复/畸形）-> 并发摄取 -> 关联检测 -> 抑制 -> 规则热更新
go run ./cmd/demo

# 全量测试（建议加 -race 验证并发安全）
go test ./...
go test -race ./...

# 只跑端到端一致性测试，查看窗口状态与判定依据日志
go test ./internal/e2e/ -v
go test ./internal/correlate/ -v
```

## 目录结构

| 包 | 职责 |
|---|---|
| `internal/event` | 统一事件模型 `Event`、严重级别，以及**可区分的拒绝原因**枚举 |
| `internal/ingest` | 三种本地日志格式解析器（JSON / syslog / key=value）、归一化、时间戳校验、幂等去重、并发摄取 |
| `internal/rule` | 关联规则模型（有序模式、时间窗、MaxGap、分组）、版本化、抑制配置 |
| `internal/correlate` | 滑动窗口、乱序安全的有序多事件匹配、水印淘汰、迟到判定、规则热更新、引擎 |
| `internal/suppress` | 按可解释维度的告警聚合与高频抑制 |
| `internal/alert` | 告警模型（证据链、序列指纹、规则版本、判定依据文本） |
| `internal/datagen` | 可复现的本地模拟日志生成（含乱序、重复、畸形样本） |
| `internal/e2e` | 端到端一致性测试 |
| `cmd/demo` | 本地端到端可运行入口 |

## 1. 事件模型（归一化）

所有格式解析后归一为 `event.Event`：

```
ID            事件身份（内容哈希生成，见"一致性基础"）
OccurredAt    事件实际发生时间（UTC）——所有时间窗判定都以此为准，而非摄取墙钟
Source        来源应用（sshd / firewall / nginx ...）
EventType     归一化类型：auth.failure / auth.success / auth.locked / net.deny ...
SrcIP/DstIP/SrcHost/DstHost/User/Action/Status
Severity      info/low/medium/high/critical
Attributes    未标准化的原始字段（含 message），全部保留可追溯
Raw/RawFormat 原始记录与格式标识，保证可回溯
```

### 支持的本地格式

- **JSON 单行**：`{"timestamp":"...","source":"sshd",...}`
- **syslog**：`2026-09-23T10:00:01Z web-01 sshd[901]: Failed password for root from 3.3.3.3 ...`
  （散文式消息会抽取 `user`/`src_ip` 并推断 `event_type/action`）
- **key=value**：`timestamp="..." source=sshd src_ip=1.2.3.4 action=login_failed ...`

时间戳支持 RFC3339/Nano、`2006-01-02 15:04:05`、传统 syslog `Jan 2 15:04:05`、Unix 秒/毫秒。

### 不静默丢弃：可区分的拒绝原因

任何无法摄取的记录都以明确原因返回（`event.Reason`），并带可读 detail：

| Reason | 触发条件 |
|---|---|
| `empty_record` | 空或全空白记录 |
| `unsupported_format` | 无法识别为三种格式之一 |
| `malformed` | 结构解析失败（如截断的 JSON） |
| `missing_timestamp` | 缺少 timestamp/time/@timestamp/ts/date |
| `bad_timestamp` | 时间戳存在但无法解析 |
| `missing_event_field` | 缺来源，或无法推断事件类型等关键字段 |
| `future_event` | 事件时间领先墙钟超过 `MaxFutureSkew` |
| `too_old` | 事件时间早于允许的最早回溯边界 `MinAge` |
| `duplicate` | 与已接受记录内容完全相同（摄取层幂等去重） |
| `too_late`* | 关联阶段：事件时间晚于水印减去 `AllowedLateness` |

\* `too_late` 在引擎阶段产生，其余在摄取阶段产生。

## 2. 规则与时间窗语义

规则（`rule.Rule`）：

```go
Pattern  []Match         // 有序模式；每个 Match 对 Source/EventType/Action/User/SrcIP/DstIP 做等值约束，空字段为通配
Window   time.Duration   // 滑动窗口：序列首事件到末事件的最大时间跨度（含边界，<= 合法）
MaxGap   time.Duration   // 可选：相邻命中事件最大间隔（0 表示不约束）
GroupBy  string          // src_ip/dst_ip/user/src_host/dst_host/空；序列必须同组
```

匹配语义：

1. **有序**：`Pattern` 必须按事件的全序 `(OccurredAt, ID)` 依次匹配；允许中间夹杂无关事件。
2. **滑动窗口**：`末事件时间 - 首事件时间 <= Window`；配置 `MaxGap` 时还要满足相邻间隔约束。
3. **分组**：同一条序列的事件必须落在同一个 `GroupBy` 分组（如同一 `src_ip`）。
4. **不漏**：事件先进入按全序排序的缓冲，每次插入后对窗内事件做动态规划重枚举，
   因此无论先到的是序列末尾还是中间事件，只要完整序列的全部事件已进入窗口，就一定被发现。
5. **不重（规范序列）**：动态规划对"同一末事件"只保留时间最早的可行前序链，
   得到稳定的**规范序列指纹** `evtA>evtB>...`。检测器用永久指纹集合去重：
   同一事件序列在窗口滚动、乱序重放、规则更新下都只产生一次告警。
6. **过期淘汰**：水印 `watermark = 已观察到的最大事件时间`。
   早于 `watermark - Window` 的事件无法再成为任何合法序列的一员，被确定性淘汰；
   已告警指纹**永久保留**，防止过期重放造成重复告警。

### 乱序与迟到

- 引擎对每批事件按 `(OccurredAt, ID)` 稳定排序后再驱动检测，
  因此 goroutine 调度与到达顺序不影响结论（`ProcessBatchShuffled` 用固定种子洗牌验证）。
- `AllowedLateness` 之内的迟到事件正常参与（哪怕补的是序列中间事件，也不漏）。
- 超过水印容忍度的过迟事件返回 `too_late` 拒绝，不静默丢弃。

## 3. 告警与抑制策略

告警（`alert.Alert`）携带完整可解释信息：

- `Kind`：`fired`（实际发出）或 `suppressed`（被聚合抑制）
- `DedupKey`：规范序列指纹，告警身份
- `RuleVersion`：产生告警时的规则版本，支撑判定可复现
- `Evidence`：命中的全部事件 ID、事件时间、对应 Pattern 下标
- `FirstEventAt/LastEventAt`、`Reason`（人类可读判定依据）

抑制（`rule.SuppressionConfig` / `suppress.Suppressor`）：

```
AggregateBy    聚合维度，如 [rule_id, src_ip]；形成确定性 AggregateKey
QuietFor       静默时长：同一 AggregateKey 在该时长内的后续命中转为 suppressed
MaxOccurrences 聚合桶保留的证据样本上限
```

- 桶不存在或已过静默期 => 本次 `fired` 并（重新）开桶；
- 静默期内 => 本次 `suppressed`，`SuppressedBy` 指向首条告警指纹，`OccurrenceCnt` 累加；
- 抑制只改 `Kind/计数`，不改指纹、证据与规则版本，因此结论仍可复现、可解释。

## 4. 规则运行期变更

`Engine.UpsertRule(rule, version)`：

- 新增规则：直接装载；
- 更新同 ID 规则：**保留全部窗口事件缓冲与已告警指纹**，只替换规则参数与版本号。
  变更后立即用新规则评估；新告警携带新 `RuleVersion`。
- 因此规则变更不会丢失已积累状态，也不会让已产生的告警重复触发；
  对同一批历史事件，变更前后的命中身份一致（端到端测试
  `TestEndToEndRuleUpdateReproducible` 去掉版本标记后逐字节比较签名）。

## 5. 一致性基础（为什么乱序/并发下结论相同）

1. **内容哈希事件 ID**：`ID = sha256(format + raw)`，同一记录在任何调度/重放轮次 ID 相同。
2. **摄取层幂等**：`(format, 规范化原始内容)` 去重，重复投递返回 `duplicate`。
3. **并发确定性输出**：并发摄取后按 `(接受在前, OccurredAt, ID, 拒绝原因, 内容哈希)` 稳定排序。
4. **检测层全序**：进入检测器前按 `(OccurredAt, ID)` 稳定排序；时间戳相等时 ID 打破并列。
5. **规范序列 + 永久指纹**：同一攻击结论只有一个稳定指纹，只告警一次。
6. **固定随机种子**：洗牌与数据生成均用确定性 LCG/Fisher-Yates，测试可逐字节复现。

## 6. 验证方法（测试地图）

| 测试 | 验证点 |
|---|---|
| `ingest.TestParseThreeFormats` | 三种格式正确归一（含 syslog 散文抽取） |
| `ingest.TestRejectReasonsAreDistinguishable` | 8 类畸形输入返回**互不相同**的拒绝原因 |
| `ingest.TestIdempotentDuplicate` | 重复内容（含首尾空白差异）幂等去重 |
| `ingest.TestConcurrentIngestIsDeterministic` | 20 轮并发摄取结论签名完全一致、输出时间有序 |
| `correlate.TestOrderedSequenceFiresOnce` | 正常序列恰好 1 条告警，打印窗口状态与依据 |
| `correlate.TestOutOfOrderGivesSameConclusion` | 5 种乱序顺序得到同一告警签名 |
| `correlate.TestWindowBoundary` | 窗口边界：跨度恰好等于 Window 合法，超出不命中 |
| `correlate.TestExpiredStateIsEvicted` | 水印推进后过期事件/部分链被淘汰 |
| `correlate.TestLateEventWithinLatenessStillDetected` | 迟到的**中间**事件补齐序列不漏；过迟事件 `too_late` 拒绝 |
| `correlate.TestNoDuplicateAlertOnReprocessing` | 同批历史事件乱序重放 0 重复告警 |
| `correlate.TestTwoIndependentSequencesEachFire` | 不同分组独立告警、不漏 |
| `correlate.TestRuleHotUpdatePreservesStateAndNoRefire` | 热更新保留窗口状态、告警带新版本、历史不重复 |
| `correlate.TestSuppressionAggregatesHighFrequency` | 1 fired + N suppressed，维度/计数/suppressed-by 可解释 |
| `e2e.TestEndToEndConsistencyAcrossOrderingAndConcurrency` | 真实混合流（多格式+乱序+重复+畸形）在 5 个种子下结论一致 |
| `e2e.TestEndToEndRuleUpdateReproducible` | 规则变更前后对同一批历史事件判定可复现 |

单测在关键路径上通过 `t.Log` 与 `Engine.DumpState()` 打印水印、窗内事件、
部分匹配链、抑制桶与每条告警的判定依据；用 `go test -v` 查看。
