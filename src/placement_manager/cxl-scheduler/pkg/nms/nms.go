package nms

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var GVR = schema.GroupVersionResource{Group: "mtier.kinetic.io", Version: "v1alpha1", Resource: "nodememorystatuses"}

const (
	Kind       = "NodeMemoryStatus"
	APIVersion = "mtier.kinetic.io/v1alpha1"

	EventGVK = "nodememorystatuses.v1alpha1.mtier.kinetic.io"
)

const (
	AnnoManaged     = "mtier.scheduler/managed"
	AnnoExpected    = "mtier.scheduler/expected-tier"
	AnnoBoundAt     = "mtier.scheduler/bound-at"
	AnnoSubmittedAt = "mtier.scheduler/submitted-at"
	AnnoExcludeNode = "mtier.scheduler/exclude-node"
	AnnoHostOnly    = "mtier.scheduler/host-only"
	AnnoRescued     = "mtier.scheduler/rescued"
)

type Status struct {
	TS           float64
	HostBufferMB float64
	CxlFreeMB    float64
	LatRatio     float64
	CxlLatRatio  float64

	ThrCxlPct     float64
	ThrCxlTargets float64
	ThrCxlFloor   float64

	RecHold float64
}

func num(m map[string]interface{}, k string) float64 {
	switch v := m[k].(type) {
	case float64:
		return v
	case int64:
		return float64(v)
	}
	return -1
}

func FromUnstructured(u *unstructured.Unstructured) (Status, bool) {
	m, ok, _ := unstructured.NestedMap(u.Object, "status")
	if !ok {
		return Status{}, false
	}
	return Status{TS: num(m, "ts"), HostBufferMB: num(m, "hostBufferMB"), CxlFreeMB: num(m, "cxlFreeMB"),
		LatRatio: num(m, "latRatio"), CxlLatRatio: num(m, "cxlLatRatio"),
		ThrCxlPct: num(m, "thrCxlPct"), ThrCxlTargets: num(m, "thrCxlTargets"), ThrCxlFloor: num(m, "thrCxlFloor"), RecHold: num(m, "recHold")}, true
}

func (s Status) StatusMap() map[string]interface{} {
	return map[string]interface{}{"ts": s.TS, "hostBufferMB": s.HostBufferMB, "cxlFreeMB": s.CxlFreeMB,
		"latRatio": s.LatRatio, "cxlLatRatio": s.CxlLatRatio,
		"thrCxlPct": s.ThrCxlPct, "thrCxlTargets": s.ThrCxlTargets, "thrCxlFloor": s.ThrCxlFloor, "recHold": s.RecHold}
}
