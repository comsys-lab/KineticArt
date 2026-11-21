package rules

import (
	"fmt"
	"sort"
)

type NodeState struct {
	Name         string
	Order        int
	CPUAllocM    float64
	CPUUsedM     float64
	HostBufferMB float64
	ReservedMB   float64
	CxlFreeMB    float64
	LatRatio     float64
	Fresh        bool
	RecHold      bool
}

func (n NodeState) slack() float64   { return n.HostBufferMB - n.ReservedMB }
func (n NodeState) cpuFree() float64 { return n.CPUAllocM - n.CPUUsedM }

type Params struct {
	MarginMB float64
	HostThr  float64
	CxlThr   float64
}

type Request struct {
	CPUM        float64
	MemMB       float64
	ExcludeNode string
	HostOnly    bool
}

type Decision struct {
	Node   string
	Tier   string
	Reason string
}

func (d Decision) Wait() bool { return d.Node == "" }

func Decide(req Request, nodes []NodeState, cxlSig float64, p Params) Decision {
	need := req.MemMB + p.MarginMB
	var fit []NodeState
	for _, n := range nodes {
		if n.Fresh && n.cpuFree() >= req.CPUM && n.Name != req.ExcludeNode {
			fit = append(fit, n)
		}
	}
	if len(fit) == 0 {
		return Decision{Reason: "no_cpu"}
	}
	hostOK := func(n NodeState) bool {
		return !n.RecHold && n.slack() >= need && (n.LatRatio <= 0 || n.LatRatio < p.HostThr)
	}
	cxlOK := cxlSig <= 0 || cxlSig < p.CxlThr

	tgt := fit[0]
	for _, n := range fit[1:] {
		if n.CPUUsedM > tgt.CPUUsedM || (n.CPUUsedM == tgt.CPUUsedM && n.Order < tgt.Order) {
			tgt = n
		}
	}

	if hostOK(tgt) {
		return Decision{tgt.Name, "HOST", "binpack_host_ok"}
	}

	if !req.HostOnly && cxlOK && tgt.CxlFreeMB >= need {
		if tgt.RecHold {
			return Decision{tgt.Name, "CXL", "binpack_rechold_cxl_ok"}
		}
		return Decision{tgt.Name, "CXL", "binpack_host_busy_cxl_ok"}
	}

	var oth []NodeState
	for _, n := range fit {
		if n.Name != tgt.Name && hostOK(n) {
			oth = append(oth, n)
		}
	}
	if len(oth) > 0 {
		sort.Slice(oth, func(i, j int) bool {
			if oth[i].slack() != oth[j].slack() {
				return oth[i].slack() < oth[j].slack()
			}
			return oth[i].Order < oth[j].Order
		})
		why := "cxl_full_other_host"
		if req.HostOnly {
			why = "rescue_other_host"
		} else if !cxlOK {
			why = "cxl_busy_other_host"
		}
		return Decision{oth[0].Name, "HOST", why}
	}
	if req.HostOnly {
		return Decision{Reason: "rescue_no_host_slack"}
	}
	if !cxlOK {
		return Decision{Reason: fmt.Sprintf("cxl_contention(%.3f>=%.3f)", cxlSig, p.CxlThr)}
	}
	return Decision{Reason: "cxl_full_no_slack"}
}
