package rules

import "testing"

var prm = Params{MarginMB: 300, HostThr: 1.054, CxlThr: 1.288}

func three() []NodeState {
	mk := func(name string, ord int, used float64) NodeState {
		return NodeState{Name: name, Order: ord, CPUAllocM: 9000, CPUUsedM: used, HostBufferMB: 5000, CxlFreeMB: 20000, LatRatio: 1.0, Fresh: true}
	}
	return []NodeState{mk("n1", 0, 6500), mk("n2", 1, 6250), mk("n3", 2, 6000)}
}

var be = Request{CPUM: 250, MemMB: 1536}

func TestBinpackHost(t *testing.T) {
	d := Decide(be, three(), 1.0, prm)
	if d.Node != "n1" || d.Tier != "HOST" || d.Reason != "binpack_host_ok" {
		t.Fatal(d)
	}
}

func TestTieOrder(t *testing.T) {
	n := three()
	n[1].CPUUsedM = 6500
	if d := Decide(be, n, 1.0, prm); d.Node != "n1" {
		t.Fatal(d)
	}
}

func TestHostBusyToCXL(t *testing.T) {
	n := three()
	n[0].LatRatio = 1.06
	d := Decide(be, n, 1.1, prm)
	if d.Node != "n1" || d.Tier != "CXL" {
		t.Fatal(d)
	}
}

func TestSlackShortToCXL(t *testing.T) {
	n := three()
	n[0].HostBufferMB = 1000
	if d := Decide(be, n, 1.1, prm); d.Node != "n1" || d.Tier != "CXL" {
		t.Fatal(d)
	}
}

func TestReservationCountsAgainstSlack(t *testing.T) {
	n := three()
	n[0].ReservedMB = 4000
	if d := Decide(be, n, 1.1, prm); d.Tier != "CXL" {
		t.Fatal(d)
	}
}

func TestContentionBelowThrCXL(t *testing.T) {
	n := three()
	n[0].LatRatio = 1.06
	n[1].LatRatio = 1.06
	n[2].LatRatio = 1.06
	if d := Decide(be, n, 1.28, prm); d.Tier != "CXL" {
		t.Fatal(d)
	}
}

func TestOtherHostBestFit(t *testing.T) {
	n := three()
	n[0].LatRatio = 1.06
	n[1].HostBufferMB = 6000
	n[2].HostBufferMB = 2500
	d := Decide(be, n, 1.30, prm)
	if d.Node != "n3" || d.Tier != "HOST" || d.Reason != "cxl_busy_other_host" {
		t.Fatal(d)
	}
}

func TestSkipsBusyHosts(t *testing.T) {
	n := three()
	n[0].LatRatio = 1.06
	n[2].LatRatio = 1.06
	if d := Decide(be, n, 1.30, prm); d.Node != "n2" {
		t.Fatal(d)
	}
}

func TestCxlFullOtherHost(t *testing.T) {
	n := three()
	n[0].LatRatio = 1.06
	n[0].CxlFreeMB = 100
	if d := Decide(be, n, 1.0, prm); d.Node != "n2" || d.Reason != "cxl_full_other_host" {
		t.Fatal(d)
	}
}

func TestWaitContention(t *testing.T) {
	n := three()
	for i := range n {
		n[i].LatRatio = 1.06
	}
	if d := Decide(be, n, 1.30, prm); !d.Wait() || d.Reason != "cxl_contention(1.300>=1.288)" {
		t.Fatal(d)
	}
}

func TestNoCPUAndStale(t *testing.T) {
	n := three()
	for i := range n {
		n[i].CPUUsedM = 8900
	}
	if d := Decide(be, n, 1.0, prm); d.Reason != "no_cpu" {
		t.Fatal(d)
	}
	n = three()
	n[0].Fresh = false
	if d := Decide(be, n, 1.0, prm); d.Node != "n2" {
		t.Fatal(d)
	}
}

func TestHostNAPasses(t *testing.T) {
	n := three()
	n[0].LatRatio = -1
	if d := Decide(be, n, -1, prm); d.Tier != "HOST" {
		t.Fatal(d)
	}
}

func TestRescueExcludesOriginHostOnly(t *testing.T) {
	n := three()
	req := Request{CPUM: 250, MemMB: 1536, ExcludeNode: "n1", HostOnly: true}
	d := Decide(req, n, 1.0, prm)
	if d.Wait() || d.Node == "n1" || d.Tier != "HOST" {
		t.Fatal(d)
	}
	for i := range n {
		if n[i].Name != "n1" {
			n[i].HostBufferMB = 500
		}
	}
	if d := Decide(req, n, 1.0, prm); !d.Wait() || d.Reason != "rescue_no_host_slack" {
		t.Fatal(d)
	}
}

func TestRecHoldBlocksHost(t *testing.T) {
	n := three()
	n[0].RecHold = true
	if d := Decide(be, n, 1.0, prm); d.Node != "n1" || d.Tier != "CXL" || d.Reason != "binpack_rechold_cxl_ok" {
		t.Fatal(d)
	}
	if d := Decide(be, n, 1.3, prm); d.Node == "n1" || d.Tier != "HOST" || d.Reason != "cxl_busy_other_host" {
		t.Fatal(d)
	}
	for i := range n {
		n[i].RecHold = true
	}
	if d := Decide(be, n, 1.3, prm); d.Node != "" {
		t.Fatal(d)
	}
}
