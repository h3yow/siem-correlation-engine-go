# 本地安全事件关联检测引擎（Go）

一个可完全本地运行的安全事件关联检测引擎：用本地产生的多格式事件流模拟真实日志，
在**乱序到达、并发摄取、迟到事件与运行期规则变更**下，保证告警结论**一致、不漏不重、可解释**。

此外支持把常驻服务的运行状态**随时导出为本地磁盘快照**，在新进程里**无损恢复**后
继续处理事件流：跨重启（含乱序、迟到、并发与重复投递）的告警结论与"进程从未重启"
**完全一致——不重不漏，告警身份（指纹）与判定依据逐字节对得上**。

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
| `internal/correlate` | 滑动窗口、乱序安全的有序多事件匹配、水印淘汰、迟到判定、规则热更新、引擎、快照导出/恢复 |
| `internal/snapshot` | 运行状态快照的磁盘格式、版本协商、sha256 校验与原子落盘/读取 |
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

## 5. 运行状态快照与跨进程恢复

常驻服务运行过程中，可随时把引擎当下累积的全部状态导出成一份本地磁盘快照；
在新进程里用这份快照把引擎恢复到导出那一刻，然后接着处理后续事件流——
而不是从头重算。

### 5.1 快照里有什么

| 状态 | 恢复后作用 |
|---|---|
| 水印 `watermark` + `allowed_lateness` | 迟到/过迟（`too_late`）判定边界与重启前完全相同 |
| 每条规则的**内容与版本** | 运行期 `UpsertRule` 后的版本（如 v2）原样带回，热更新语义照旧 |
| 各分组窗口内**保留的事件** | 恢复点落在未凑齐序列中间时，已攒下的事件不丢，恢复后继续参与 DP 重枚举 |
| **永久已告警指纹集合** | 重启前发过的告警，恢复后无论重放/乱序都**不会再冒出来**（不重） |
| 待排空缓冲 `pending` | 只缓冲未检测的事件也入快照，恢复后下批按全序排空（不漏） |
| 抑制桶（静默截止/首告警指纹/计数/样本）+ 聚合维度 | 静默期跨重启接续，`OccurrenceCnt` 接续累加，`SuppressedBy` 身份不变 |
| 摄取层幂等去重表（绑定 ingest.Service 时） | 重启前接受过的原始记录，重启后重复投递仍返回 `duplicate` |
| **事件时间判定口径 `time_policy`**（未来容忍 `max_future_skew` / 最早可回溯 `min_age`） | 以**导出那一刻**业务实际口径为准，恢复后原样沿用，不退回默认值；边界事件的 `future_event`/`too_old` 判定逐条一致 |
| 引擎身份 `engine_id` | 便于加载前核对快照是否属于本实例 |

> **部分匹配链（partials）不进快照**：它们是窗内事件的确定性派生物，
> 恢复后由后续事件触发的全量动态规划重枚举自动重建，语义零损失，快照更小。

### 5.2 怎么用

```go
import "github.com/h3yow/siem-correlation-engine-go/internal/correlate"
import "github.com/h3yow/siem-correlation-engine-go/internal/ingest"

// —— 运行中的进程 ——
svc := ingest.NewService(nil)
eng := correlate.NewEngine(cfg, allowedLateness)
eng.BindIngestService(svc) // 可选：绑定后快照连幂等去重表一起保存
eng.SetEngineID("siem-prod-1")
eng.UpsertRule(rule1, 1)
eng.ProcessBatch(events)          // 正常处理事件流
eng.UpsertRule(rule1V2, 2)        // 运行期热更新，版本会进快照

// 随时导出（锁内只做内存拷贝，锁外原子落盘；不卡摄取，可周期性调用）
if err := eng.SaveSnapshot("/var/lib/siem/engine.snap.json"); err != nil { ... }

// —— 新进程 ——
// 注意：恢复一律以快照里的时间口径为准；即使这里用默认口径（NewService(nil)）
// 构造，LoadSnapshotFromFile 也会把快照导出那一刻的 future/min_age 口径强制
// 套用到 newSvc 上，调用方后来传入的设置不会改变恢复结论。
newSvc := ingest.NewService(nil)
restored, err := correlate.LoadSnapshotFromFile(
    "/var/lib/siem/engine.snap.json", newSvc)             // 连去重表+时间口径一起恢复
if err != nil { ... }                                     // 版本/损坏/口径缺失等原因明确可区分
restored.ProcessBatch(eventsAfterRestart)                 // 接着处理，结论与未重启一致
```

也可以只在内存中编解码（不碰磁盘）：`eng.ExportState()` 返回 `snapshot.State`，
`snapshot.Encode/Decode` 做带版本与校验和的序列化，`correlate.RestoreEngine` 完成重建。

### 5.3 兼容范围与版本演进（不会默默算错）

快照文件是带外层信封的 JSON：

```
format_version  当前写出为 1；读取支持区间 [MinSupportedVersion=1, CurrentFormatVersion=1]
engine_id / created_at
checksum        state 规范 JSON（Go struct 字段序 + map 按键排序）的 sha256
state           上述全部运行状态
```

读取按 **格式 → 版本 → 校验和** 的顺序把关，失败原因互不混淆，绝不"默默读进来算出错结论"：

| 错误（`errors.Is` 可判） | 含义 / 处置 |
|---|---|
| `snapshot.ErrMalformedSnapshot` | 文件不是合法快照（截断、非 JSON）。拒绝加载。 |
| `snapshot.ErrUnsupportedVersion`（`*VersionError`，含 `Got/Min/Max`） | 版本不在支持区间（典型：**未来版本**的快照被旧程序读到）。拒绝加载，错误里写明期望区间，可据此提示升级或迁移。 |
| `snapshot.ErrChecksumMismatch` | 状态被篡改/损坏。拒绝加载。 |
| `snapshot.ErrMissingTimePolicy` | 快照缺少事件时间判定口径节（典型：口径持久化之前写出的旧快照）。**拒绝加载**，绝不拿默认值顶替——否则边界事件会被误放/误拒。 |
| `snapshot.ErrInvalidTimePolicy` | 口径取值不合理（`max_future_skew`/`min_age` 为负）。拒绝加载。 |
| `snapshot: invalid state: ...` | 版本兼容但内容结构非法（如规则 `window<=0`、悬空 `rule_order`）。拒绝加载。 |

演进约定：

- **新版本读旧版本**：`format_version` 在 `[1, 当前]` 内一律兼容。新增字段对旧快照缺省；
  时长以**纳秒整数**持久化、严重级别以**名称字符串**（而非枚举序号）持久化，
  因此未来调整枚举顺序/新增级别也不会把旧快照错误映射。
- **旧版本读新版本**：得到可区分的 `ErrUnsupportedVersion`，而不是误读。
- 需要破坏性迁移时提升 `format_version`，并在 `Decode` 中为旧版本提供显式迁移或明确拒绝。

### 5.3.1 事件时间判定口径如何随快照延续

业务常驻服务往往**不按默认口径**运行：对未来事件的容忍（`MaxFutureSkew`）
与允许回溯到多早（`MinAge`）都按业务调过。这两个边界一旦在换进程后悄悄
退回默认值（`1h / 不限制`），同一批记录重启前后的接受/拒绝就会对不上，
进而改变告警分布。因此口径被当作**运行状态的一部分**对待：

- **导出**：`ExportState()` 把当时引擎沿用的口径写入 `state.time_policy`
  （绑定了 `ingest.Service` 时即该服务归一化器的实际口径；未绑定时取摄取层默认）。
- **恢复**：`RestoreEngine` / `LoadSnapshotFromFile` 先校验口径节，再把它
  同时套到恢复出的引擎和传入的 `ingest.Service` 上——**恢复方构造
  Normalizer 时传的任何值（含默认值）都会被快照口径覆盖**，不存在
  "正常恢复却被后来设置顶掉"的路径。
- **边界语义**（与归一化器的判定完全一致，含临界值）：
  - `ts > now + max_future_skew` 才拒绝为 `future_event`；**恰好等于上界接受**；
  - 当 `min_age > 0` 时，`ts < now - min_age` 才拒绝为 `too_old`；**恰好等于最早边界接受**。
  - 因此"刚好处在容忍范围内、刚好超出、最早边界两侧"的记录恢复前后逐条同判。
- **缺失/非法即失败**：旧快照没有该节 → `ErrMissingTimePolicy`；取值为负 →
  `ErrInvalidTimePolicy`。两者与 `ErrUnsupportedVersion`、`ErrChecksumMismatch`
  互不混淆，`errors.Is` 可精确区分。时钟本身是各进程本地墙钟、**不属于快照**；
  需要跨进程严格对齐时，应像演示/测试一样给归一化器注入同一面钟（`SetClock`）。

### 5.4 不卡摄取、长期周期性导出

- 导出在引擎读锁内**仅做一次内存状态深拷贝**，编码与磁盘写入都在锁外完成，
  慢磁盘不会阻塞正在进行的摄取/检测。
- 落盘采用 **同目录临时文件 + fsync + 原子 rename**：读取方永远看不到写一半的文件；
  失败与反复/周期性导出都不会残留临时文件，内存占用也不随导出次数增长。
- 并发摄取与并发导出可用 `-race` 验证（`TestConcurrentExportsDoNotBlockOrGrow`）。

### 5.5 本地如何验证"恢复前后结论一致"

```bash
# 端到端可运行演示（第 5 段会真实落盘一份快照并在新引擎视角恢复、继续喂事件）
go run ./cmd/demo

# 快照/恢复专项 + 全部一致性测试（建议带 -race）
go test ./...
go test -race ./...

# 只看快照相关用例的详细日志
go test ./internal/snapshot/ ./internal/correlate/ ./internal/e2e/ -v

# 只看"非默认时间口径跨恢复"专项（-v 日志逐条打印边界用例的接受/拒绝与分布）
go test ./internal/e2e/ -v -run 'TestNonDefaultTimePolicySurvivesRestore|TestRestoreRejectsMissingOrInvalidTimePolicy'
go test ./internal/ingest/ ./internal/correlate/ ./internal/snapshot/ -v -run 'TimePolicy'
```

最直接的人工核对方式：让同一段事件流分别走"从未重启"和"中途导出/恢复"两条路径，
对告警结论签名（`Kind:RuleID:RuleVersion:DedupKey:AggregateKey:OccurrenceCnt:SuppressedBy`）
与重启后的拒绝分布（`duplicate/too_late/future_event/too_old/...`）做逐字节比较——
端到端用例 `TestEndToEndSnapshotRestoreEquivalent` 正是这样断言的。

**非默认口径下恢复前后结论一致**由专项用例覆盖：

- `TestNonDefaultTimePolicySurvivesRestore`（e2e）：用收紧口径
  （`max_future_skew=30s, min_age=2m`）运行、处理完一段命中告警的前缀后导出，
  新进程**故意用默认口径**构造服务再恢复，继续喂 9 条边界附近记录
  （领先 10m/31s/30s/29s/0、落后 119s/120s/121s/30m）。断言：
  每条边界记录的期望成立（`>30s` 与 `<-2m` 拒绝、两个临界值接受）、
  恢复前后逐条一致、接受/拒绝分布（接受 5、`future_event` 2、`too_old` 2）一致、
  告警结论（Fired=1）一致。
- `TestRestoreRejectsMissingOrInvalidTimePolicy`（e2e）：摘掉 `time_policy` 节
  并重算校验和后必须报 `ErrMissingTimePolicy`；负时长报 `ErrInvalidTimePolicy`；
  同一份文件分别触发版本/校验和/口径三类错误并断言彼此可区分。
- 单元层另有摄取口径覆盖（`TestTimePolicyRestoreOverridesConstructorSetting`、
  `-race` 下的 `TestTimePolicyAppliesUnderConcurrentAccess`）、快照校验
  （`TestDecodeRejectsMissingOrInvalidTimePolicy`）与引擎恢复
  （`TestTimePolicySurvivesEngineRestore`）。

## 6. 一致性基础（为什么乱序/并发下结论相同）

1. **内容哈希事件 ID**：`ID = sha256(format + raw)`，同一记录在任何调度/重放轮次 ID 相同。
2. **摄取层幂等**：`(format, 规范化原始内容)` 去重，重复投递返回 `duplicate`。
3. **并发确定性输出**：并发摄取后按 `(接受在前, OccurredAt, ID, 拒绝原因, 内容哈希)` 稳定排序。
4. **检测层全序**：进入检测器前按 `(OccurredAt, ID)` 稳定排序；时间戳相等时 ID 打破并列。
5. **规范序列 + 永久指纹**：同一攻击结论只有一个稳定指纹，只告警一次。
6. **固定随机种子**：洗牌与数据生成均用确定性 LCG/Fisher-Yates，测试可逐字节复现。

## 7. 验证方法（测试地图）

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
| `snapshot.TestEncodeDecodeRoundTrip` / `...FileRoundTrip...` | 快照内存/文件往返一致，权限 0600、无临时文件泄漏 |
| `snapshot.TestDecodeRejectsFutureVersion` / `...OldVersion` | 未来/过旧版本返回可区分的 `ErrUnsupportedVersion`（含 `VersionError` 细节） |
| `snapshot.TestDecodeRejectsMalformed` / `...TamperedState` | 非法文件→`ErrMalformedSnapshot`；篡改载荷/伪造校验和→`ErrChecksumMismatch` |
| `correlate.TestRestoreMidSequenceCompletesAfterRestart` | **恢复点正落在未凑齐序列中间**：恢复后迟到事件补齐，指纹与未重启一致、重放不重复 |
| `correlate.TestLateAndOutOfOrderEventsCrossRestoreBoundary` | **迟到、乱序事件跨过恢复边界**：恢复后补全唯一序列，身份逐字节一致、重放 0 重复 |
| `correlate.TestWatermarkAndLatenessCrossRestore` | 恢复后水印/迟到容忍语义不变，过迟事件仍 `too_late` |
| `correlate.TestPendingBufferSurvivesRestore` | 未排空缓冲随快照保存，恢复后乱序缓冲→全序排空不漏 |
| `correlate.TestSuppressionStateSurvivesRestore` | 抑制桶跨重启接续：静默期、计数、`SuppressedBy`/聚合身份一致 |
| `correlate.TestRuleHotUpdateVersionInSnapshot` | 热更新后的版本/内容入快照，恢复后变更语义照旧、历史不重复 |
| `correlate.TestConcurrentExportsDoNotBlockOrGrow` | 并发摄取 + 周期并发导出（`-race`）安全、可恢复、无临时文件堆积 |
| `correlate.TestRestoreRejectsInvalidState` | 结构非法（非法窗口/悬空 rule_order）被明确拒绝 |
| `ingest.TestExportRestoreStateKeepsDedup` | 幂等去重表跨进程恢复，重复投递仍 `duplicate`、计数接续 |
| `e2e.TestEndToEndSnapshotRestoreEquivalent` | 真实多格式流中途导出/恢复，乱序+重复+畸形跨边界，告警身份与拒绝分布逐字节一致 |
| `e2e.TestEndToEndSnapshotFileIsVersioned` | 落盘快照包含 format_version/checksum/rules/watermark/ingest_seen 等字段 |

单测在关键路径上通过 `t.Log` 与 `Engine.DumpState()` 打印水印、窗内事件、
部分匹配链、抑制桶与每条告警的判定依据；用 `go test -v` 查看。
