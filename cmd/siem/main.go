package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/engine"
	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
	"github.com/h3yow/siem-correlation-engine-go/pkg/parser"
	"github.com/h3yow/siem-correlation-engine-go/pkg/rule"
)

func main() {
	logger := log.New(os.Stdout, "", log.Ltime|log.Lmicroseconds)
	base := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	cfg := engine.Config{
		MaxFutureSkewSec: 300,
		MaxAgeSec:        86400,
		HistoryLimit:     5000,
		Logger:           logger,
		Now:              func() time.Time { return base.Add(1 * time.Hour) },
	}
	e := engine.New(cfg)
	e.Registry().Register(parser.NewJSONParser())
	e.Registry().Register(parser.NewKVParser())
	e.Registry().Register(parser.NewCSVParser())
	e.Start()
	defer e.Stop()

	// 规则：同一 subject 在 60s 内 登录失败 -> 提权 -> 敏感操作，即告警。
	r1 := &rule.Rule{
		ID: "R-BRUTE-PRIV", Name: "爆破后提权",
		Window:      60 * time.Second,
		Lateness:    120 * time.Second,
		DedupWindow: 30 * time.Second,
		GroupBy:     []string{"subject"},
		Version:     1,
		Sequence: []rule.Condition{
			{Type: "auth.login_failed"},
			{Type: "auth.privilege_granted"},
			{Type: "audit.sensitive_action"},
		},
	}
	if _, err := e.UpdateRule(r1); err != nil {
		panic(err)
	}

	// 本地生成的混合格式事件流（故意乱序：先送 t10、t40、t05）。
	type rec struct{ line, source string }
	t := func(sec int) string { return base.Add(time.Duration(sec) * time.Second).Format(time.RFC3339) }
	records := []rec{
		{fmt.Sprintf(`{"id":"e2","ts":"%s","type":"auth.privilege_granted","severity":"high","subject":"bob","attrs":{"role":"root"}}`, t(40)), "app1"},
		{fmt.Sprintf(`id=e1 ts=%s type=auth.login_failed severity=medium subject=bob src_ip=10.0.0.9`, t(5)), "app1"},
		{fmt.Sprintf(`e3,%s,audit.sensitive_action,critical,bob,delete users`, t(50)), "audit"},
		// bob 的第二次登录失败（供 R-REPEAT-FAIL 回放触发）
		{fmt.Sprintf(`id=e8 ts=%s type=auth.login_failed severity=medium subject=bob`, t(8)), "app1"},
		// 极端迟到：远早于水位线，应被拒绝参与关联
		{fmt.Sprintf(`{"id":"e9","ts":"%s","type":"auth.login_failed","severity":"low","subject":"bob"}`, t(-500)), "app1"},
		// 另一 subject，不构成告警
		{fmt.Sprintf(`id=e4 ts=%s type=auth.login_failed severity=low subject=alice`, t(6)), "app1"},
		// 畸形 / 异常输入
		{`{"id":"e5","type":"auth.login_failed"}`, "app1"},                                   // 缺时间戳
		{`{"id":"e6","ts":"not-a-time","type":"x"}`, "app1"},                                 // 坏时间戳
		{`id=e1 ts=` + t(5) + ` type=auth.login_failed severity=medium subject=bob`, "app1"}, // 重复 ID
		{`totally unstructured line`, "app1"},                                                // 无法识别格式
	}

	var wg sync.WaitGroup
	for _, r := range records {
		wg.Add(1)
		go func(r rec) {
			defer wg.Done()
			e.Ingest(r.line, r.source)
		}(r)
	}
	wg.Wait()

	// 运行期新增规则，并对历史事件回放：同一 subject 60s 内两次登录失败。
	r2 := &rule.Rule{
		ID: "R-REPEAT-FAIL", Name: "重复登录失败",
		Window:   60 * time.Second,
		Lateness: 5 * time.Second,
		GroupBy:  []string{"subject"},
		Version:  1,
		Sequence: []rule.Condition{
			{Type: "auth.login_failed"},
			{Type: "auth.login_failed"},
		},
	}
	if _, err := e.UpdateRule(r2); err != nil {
		panic(err)
	}

	// 新事件 e7 与 e1/e2 组成另一条证据链，产生新的告警。
	e.Ingest(fmt.Sprintf(`{"id":"e7","ts":"%s","type":"audit.sensitive_action","severity":"high","subject":"bob"}`, t(55)), "audit")

	// 删除规则后以相同定义重新加入：历史回放出的旧指纹必须被抑制，不重复告警。
	e.DeleteRule("R-REPEAT-FAIL")
	if _, err := e.UpdateRule(r2); err != nil {
		panic(err)
	}

	fmt.Println("========== 结论 ==========")
	alerts := e.Alerts()
	fired, suppressed := 0, 0
	for _, a := range alerts {
		tag := "FIRE"
		if a.Suppressed {
			tag = "SUPPRESS"
			suppressed++
		} else {
			fired++
		}
		fmt.Printf("[%s] %s rule=%s v%d sev=%s events=%v\n  依据: %s\n",
			tag, a.Fingerprint, a.RuleID, a.RuleVersion, a.Severity, a.EventIDs, a.Reason)
	}
	fmt.Printf("总计: 告警 %d（触发 %d，抑制聚合 %d）\n", len(alerts), fired, suppressed)
	_ = event.SeverityHigh
}
