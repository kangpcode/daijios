// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijicloud

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// LogEntry captures one structured DaijiCloud observability event.
type LogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	OrgID   string `json:"org_id,omitempty"`
	Comp    string `json:"component"`
	Message string `json:"message"`
	TraceID string `json:"trace_id,omitempty"`
}

// TraceSpan captures one distributed operation timing span.
type TraceSpan struct {
	TraceID   string `json:"trace_id"`
	SpanID    string `json:"span_id"`
	Operation string `json:"operation"`
	Status    int    `json:"status"`
	DurationUS int64 `json:"duration_us"`
	Timestamp string `json:"timestamp"`
}

// Observability collects Prometheus metrics, structured logs, and trace spans.
type Observability struct {
	httpRequests atomic.Uint64
	ztpAdoptions atomic.Uint64
	rolloutsRun  atomic.Uint64

	mu     sync.Mutex
	logs   []LogEntry
	traces []TraceSpan
}

func NewObservability() *Observability {
	return &Observability{}
}

func (o *Observability) IncHTTP()    { o.httpRequests.Add(1) }
func (o *Observability) IncZTP()     { o.ztpAdoptions.Add(1) }
func (o *Observability) IncRollout() { o.rolloutsRun.Add(1) }

func (o *Observability) AddLog(level, orgID, comp, msg, traceID string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.logs = append(o.logs, LogEntry{
		Time:    time.Now().UTC().Format(time.RFC3339),
		Level:   level,
		OrgID:   orgID,
		Comp:    comp,
		Message: msg,
		TraceID: traceID,
	})
	if len(o.logs) > 500 {
		o.logs = o.logs[len(o.logs)-500:]
	}
}

func (o *Observability) AddTrace(traceID, op string, status int, dur time.Duration) {
	var b [4]byte
	_, _ = rand.Read(b[:])
	o.mu.Lock()
	defer o.mu.Unlock()
	o.traces = append(o.traces, TraceSpan{
		TraceID:    traceID,
		SpanID:     hex.EncodeToString(b[:]),
		Operation:  op,
		Status:     status,
		DurationUS: dur.Microseconds(),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	})
	if len(o.traces) > 500 {
		o.traces = o.traces[len(o.traces)-500:]
	}
}

func (o *Observability) RenderPrometheus(totalDevices, onlineDevices, openAlerts int) string {
	return fmt.Sprintf(
		"# HELP daijicloud_devices_total Total adopted devices\n"+
			"# TYPE daijicloud_devices_total gauge\n"+
			"daijicloud_devices_total %d\n"+
			"# HELP daijicloud_devices_online Online devices\n"+
			"# TYPE daijicloud_devices_online gauge\n"+
			"daijicloud_devices_online %d\n"+
			"# HELP daijicloud_alerts_open Open alerts across tenants\n"+
			"# TYPE daijicloud_alerts_open gauge\n"+
			"daijicloud_alerts_open %d\n"+
			"# HELP daijicloud_http_requests_total Public API requests served\n"+
			"# TYPE daijicloud_http_requests_total counter\n"+
			"daijicloud_http_requests_total %d\n"+
			"# HELP daijicloud_ztp_adoptions_total Devices enrolled via ZTP\n"+
			"# TYPE daijicloud_ztp_adoptions_total counter\n"+
			"daijicloud_ztp_adoptions_total %d\n"+
			"# HELP daijicloud_rollouts_total Canary firmware rollouts started\n"+
			"# TYPE daijicloud_rollouts_total counter\n"+
			"daijicloud_rollouts_total %d\n",
		totalDevices, onlineDevices, openAlerts,
		o.httpRequests.Load(), o.ztpAdoptions.Load(), o.rolloutsRun.Load(),
	)
}
