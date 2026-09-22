# 本地安全事件关联检测引擎（Go）

一套可完全本地运行的 SIEM 关联检测引擎：本地生成/读取多种格式的日志行，归一化为
统一事件模型，在**事件时间（event time）滑动窗口**上做多事件关联，支持**乱序到达、
并发摄取、迟到事件、运行期规则变更**，并保证告警结论**确定、可复现、可解释**。

## 快速开始

```bash
# 运行本地演示：混合格式事件 + 乱序 + 并发摄取 + 运行期新增规则
go run ./cmd/siem

# 全量测试（带竞态检测）
go test -race ./... -v

# 覆盖率
go test -race -cover ./...
```

演示与测试运行时会打印 `[window]`/`[fire]`/`[late]`/`[suppress]`/`[reject]`/
`[replay-fire]` 等日志，其中 `[window]` 行输出每次判定后的**窗口内全部事件、最大事件
时间、水位线**，`[fire]` 行输出完整证据链与判定依据。

## 架构

```
原始日志行 (JSON / key=value / CSV)
        │  pkg/parser：格式探测 → 解析 → 时间戳/字段校验
        ▼
统一事件 event.Event  ──拒绝──▶ event.RejectedRecord（可区分原因，绝不静默丢弃）
        │  去重(ID) + 分配摄取序号 + 保留历史
        ▼
rule.Store（规则快照/版本） ──▶ window.Manager（每 规则×分区 的事件时间窗口状态机）
        │  枚举窗口内全部合法证据链，稳定指纹去重
        ▼
alert.Alert（携带证据链/窗口/原因） ──▶ suppression.Suppressor（按指纹聚合抑制）
        │
        ▼
结论输出（FIRE / SUPPRESS）
```

* **串行化判定**：无论多少个 goroutine 并发 `Ingest`，所有解析与窗口判定都经过引擎
  内部单一串行点（后台 worker goroutine + 处理互斥），消除数据竞争；`-race` 测试验证。
* **确定性排序**：窗口内事件按 `(事件时间, 摄取序号, 事件ID)` 排序，消除同刻歧义。

## 统一事件模型（`pkg/event`）

| 字段 | 含义 |
| --- | --- |
| `ID` | 事件唯一标识；重复 ID 以 `duplicate_event_id` 拒绝 |
| `Source` | 日志源（摄取时由调用方标注） |
| `Type` | 归一化事件类型，如 `auth.login_failed` |
| `Timestamp` | **事件时间**（UTC），RFC3339 字符串或 unix 秒 |
| `Severity` | `info/low/medium/high/critical/unknown`，未知词归一为 `unknown` |
| `Subject` | 主体（用户/主机等），常用于分区 |
| `Message` / `Attrs` | 自由文本与扩展键值（规则条件可引用） |
| `IngestSeq` | 引擎分配的单调递增摄取序号 |

### 支持的日志格式（`pkg/parser`）

* **JSON**：以 `{` 开头；字段 `id, ts, type, severity, subject, message, attrs`。
* **key=value**：空格分隔、值可用双引号；保留键 `id/ts/type/severity/subject/msg`，
  其余键自动进入 `Attrs`。
* **CSV**：固定 6 列 `id,ts,type,severity,subject,message`。

格式按行内容自动探测；无法识别给出 `unsupported_format`。

### 拒绝原因（`event.RejectReason`，可区分、不静默丢弃）

| 原因 | 触发条件 |
| --- | --- |
| `empty_record` | 空白行 |
| `unsupported_format` | 无法探测/未注册解析器 |
| `malformed_record` | JSON 语法错、KV 无 `=`、CSV 列数不对等 |
| `missing_id` / `missing_type` / `missing_timestamp` | 关键字段缺失 |
| `bad_timestamp` | 时间戳无法解析或离谱（unix 值越界） |
| `future_timestamp` | 超过 `now + MaxFutureSkew` |
| `timestamp_too_old` | 早于 `now - MaxAge` |
| `duplicate_event_id` | 同一事件 ID 被重复摄取 |
| `late_beyond_watermark` | 对某规则晚于水位线，拒绝参与该规则关联 |

> 迟到事件不是全局丢弃：它只对**水位线已经越过它的（规则,分区）**拒绝参与关联，
> 拒绝结果逐规则返回在 `Result.Rejected` 中。

## 规则与时间窗语义（`pkg/rule`、`pkg/window`）

规则示例：60 秒内同一用户按序出现「登录失败 → 提权 → 敏感操作」。

```go
&rule.Rule{
    ID: "R-BRUTE-PRIV", Window: 60*time.Second, Lateness: 5*time.Second,
    GroupBy:     []string{"subject"},            // 分区维度
    DedupWindow: 30*time.Second,                 // 告警抑制窗口
    Sequence: []rule.Condition{
        {Type: "auth.login_failed"},
        {Type: "auth.privilege_granted"},
        {Type: "audit.sensitive_action"},
    },
}
```

* **条件（Condition）**：`type` 精确匹配（`*` 为任意）；`source`、`severity 列表`、
  `attrs` 均可附加约束；`attrs` 支持特殊键 `source/type/subject/severity`。
* **分区（GroupBy）**：窗口状态按 `(规则ID, 分区键)` 隔离，不同 subject 绝不串链。
* **滑动时间窗**：一条证据链的首末事件时间跨度 `<= Window`（边界相等算命中）。
* **乱序与水位线（watermark）**：
  * 窗口状态随已观察到的最大事件时间推进：`watermark = maxEventTime - Lateness`。
  * 事件时间 `>= watermark` 的迟到事件被**插入正确的事件时间位置**并参与判定。
  * 事件时间 `< watermark` 的事件以 `late_beyond_watermark` 拒绝（可解释明细中
    给出当时的水位线值）。
* **过期淘汰**：单条事件早于 `maxEventTime - (Window + Lateness)` 即从窗口淘汰；
  长期空闲的分区由 `Engine.Housekeep()` 整体回收（同时清理过期抑制状态）。

### 为什么乱序/并发下结论一致

每次有事件加入（即使它插到窗口中间），引擎都会在窗口内**全量有序事件**上，以
**确定性顺序（DFS，按事件时间/摄取序）枚举所有满足序列且跨度不超窗的完整证据链**；
每条链以稳定指纹标识，只有此前从未触发过的指纹才产生告警。

因此在水位线容忍度（`Lateness`）覆盖的乱序范围内：

> 同一批历史事件，无论按什么顺序、由多少个 goroutine 并发喂入，
> 最终的告警指纹集合**必然相同**；到达顺序只影响"告警在何时被发现"。

超过容忍度的迟到属于事件时间语义上的"不可恢复"，会明确拒绝并给出原因，
而不是产生静默的漏报或不确定结论。`TestOutOfOrderConsistency` /
`TestOrderIndependence` 对这一不变量做了断言（顺序/逆序/打乱三种输入比对指纹集合）。

**告警指纹（`pkg/alert`）**：`sha1(规则ID, 分区, 排序后的证据事件ID)`，
与到达顺序、证据排列顺序无关。

## 告警抑制与聚合（`pkg/suppression`）

* 以告警指纹为键：窗口内第一次到达 → `Suppressed=false, Count=1` 正常发出；
  窗口内再次到达 → `Suppressed=true`，`Count` 累加（高频重复告警被聚合成计数）。
* 距上次出现 `>= DedupWindow` 后自动重新放行；`DedupWindow<=0` 表示永久去重。
* 被抑制的告警仍保留在 `Engine.Alerts()` 中（带标记），便于审计聚合情况。
* `Engine.Housekeep()` 淘汰滑出抑制窗口的聚合键。

## 运行期规则变更语义（`rule.Store` + 引擎）

`Store` 每次 Upsert/Delete 递增版本号，引擎变更操作与摄取共用同一串行点。

| 操作 | 语义 |
| --- | --- |
| **更新既有规则**（同 ID，新 `Version`） | 已积累的窗口状态**原样保留**；不会对历史证据链重复触发（指纹已记录）。新事件按新版本判定，告警携带新版本号。 |
| **新增规则** | 对引擎保留的历史事件（`HistoryLimit`）按**事件时间顺序回放**，立即补齐历史判定；回放日志以 `[replay-fire]`/`[replay-suppress]` 标注。 |
| **删除规则** | 清理该规则全部窗口状态；**抑制聚合键保留**（按规则 ID）。 |
| **删除后重新加入** | 历史回放出的旧指纹命中保留的抑制键 → 标记 `Suppressed`，**不重复告警**；全新证据链仍正常触发。 |
| **禁用规则**（`Disabled=true`） | 跳过评估，状态保留。 |

由于新增规则按事件时间确定性回放，且指纹与运行时逐步触发一致，
「规则创建前就存在」与「规则创建后喂入」对同一批历史事件的判定结果**可复现一致**。

## 验证方法 / 测试清单

```bash
go test -race -v ./...
```

| 测试 | 覆盖点 |
| --- | --- |
| `pkg/parser` TestParseFormats | 三种格式、严重级别归一、时间戳两种编码 |
| `pkg/parser` TestRejectReasons | 10 类可区分拒绝原因（缺失/畸形/未来/过旧/坏时间戳…） |
| `pkg/window` TestOutOfOrderConsistency | 顺序/逆序/打乱三种输入 → 告警指纹集合完全一致 |
| `pkg/window` TestWindowBoundary | 跨度恰等于窗口命中、超出 1 秒不命中 |
| `pkg/window` TestNoDuplicateAlert | 旧链不重复触发、乱序补送不重报 |
| `pkg/window` TestLateBeyondWatermark | 水位线外拒绝、容忍度内乱序仍命中 |
| `pkg/window` TestEviction | 事件级过期淘汰与空闲分区回收 |
| `pkg/engine` TestConcurrentIngest | 多 goroutine 并发喂入（含畸形输入）结论确定 |
| `pkg/engine` TestOrderIndependence | 引擎层三种顺序告警集合一致性 |
| `pkg/engine` TestRuleUpdatePreservesState | 更新规则不丢窗口状态、不重复历史告警 |
| `pkg/engine` TestNewRuleReplayAndDeleteReadd | 新规则历史回放；删除重加旧指纹被抑制 |
| `pkg/engine` TestPartitionIsolation | 不同 GroupBy 分区不串链 |
| `pkg/engine` TestEngineRejectReasons | 迟到/坏时间戳/重复 ID 原因可区分 |
| `pkg/suppression` | 窗口内聚合抑制、滑过窗口重新放行、永久去重、淘汰 |
| `pkg/alert` | 指纹与证据顺序无关；分区/规则不同则指纹不同 |

## 代码结构

```
pkg/event/       统一事件模型、拒绝原因枚举
pkg/parser/      JSON/KV/CSV 解析器、格式探测注册表、时间/字段校验
pkg/rule/        条件/规则模型、分区键、合法性校验、并发安全规则存储
pkg/window/      事件时间滑动窗口状态机、水位线、证据链枚举、淘汰
pkg/alert/       告警模型、稳定指纹、严重级别聚合
pkg/suppression/ 指纹维度的聚合计数与时间抑制
pkg/engine/      串行摄取、乱序/并发处理、规则热更新与历史回放、可解释日志
cmd/siem/        本地可运行演示
```
