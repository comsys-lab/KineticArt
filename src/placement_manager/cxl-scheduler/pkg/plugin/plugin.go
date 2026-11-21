package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/scheduler/framework"
	frameworkruntime "k8s.io/kubernetes/pkg/scheduler/framework/runtime"

	"cxlsched/pkg/nms"
	"cxlsched/pkg/rules"
)

const Name = "MemTierAware"

type Args struct {
	MarginMB     float64 `json:"marginMB"`
	HostThr      float64 `json:"hostThr"`
	CxlThr       float64 `json:"cxlThr"`
	StaleSec     float64 `json:"staleSec"`
	FillRatio    float64 `json:"fillRatio"`
	FillHoldSec  float64 `json:"fillHoldSec"`
	GraceSec     float64 `json:"graceSec"`
	HostReserveS float64 `json:"hostReserveS"`
}

type hres struct {
	until float64
	mb    float64
}

type Plugin struct {
	h      framework.Handle
	args   Args
	nmsInf cache.SharedIndexInformer

	mu           sync.Mutex
	hres         map[string][]hres
	cres         *rules.CXLReserve
	cxlThrottled bool
}

var (
	_ framework.PreFilterPlugin   = &Plugin{}
	_ framework.ReservePlugin     = &Plugin{}
	_ framework.PreBindPlugin     = &Plugin{}
	_ framework.EnqueueExtensions = &Plugin{}
)

func (p *Plugin) Name() string { return Name }

func now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func New(ctx context.Context, obj runtime.Object, h framework.Handle) (framework.Plugin, error) {
	a := Args{MarginMB: 1000, HostThr: 1.125, CxlThr: 1.299, StaleSec: 5, FillRatio: 0.70, FillHoldSec: 5, GraceSec: 30, HostReserveS: 10}
	if err := frameworkruntime.DecodeInto(obj, &a); err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(h.KubeConfig())
	if err != nil {
		return nil, err
	}
	f := dynamicinformer.NewDynamicSharedInformerFactory(dyn, 0)
	inf := f.ForResource(nms.GVR).Informer()
	p := &Plugin{h: h, args: a, nmsInf: inf, hres: map[string][]hres{},
		cres: &rules.CXLReserve{Curve: rules.MLBECurve, FillRatio: a.FillRatio, FillHold: a.FillHoldSec, Grace: a.GraceSec}}
	f.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		return nil, fmt.Errorf("NodeMemoryStatus informer sync failed")
	}
	klog.InfoS("MTIER start", "args", a)
	go p.releaseLoop(ctx)
	return p, nil
}

func managed(pod *v1.Pod) bool { return pod.Annotations[nms.AnnoManaged] == "true" }

func podKey(pod *v1.Pod) string { return pod.Namespace + "/" + pod.Name }

func memLimitMB(pod *v1.Pod) float64 {
	s := 0.0
	for _, c := range pod.Spec.Containers {
		if q, ok := c.Resources.Limits[v1.ResourceMemory]; ok {
			s += float64(q.Value()) / (1 << 20)
		}
	}
	return s
}

func cpuReqM(pod *v1.Pod) float64 {
	s := 0.0
	for _, c := range pod.Spec.Containers {
		if q, ok := c.Resources.Requests[v1.ResourceCPU]; ok {
			s += float64(q.MilliValue())
		}
	}
	return s
}

func (p *Plugin) snapshot(t float64) ([]rules.NodeState, float64) {
	st := map[string]nms.Status{}
	for _, o := range p.nmsInf.GetStore().List() {
		u, ok := o.(*unstructured.Unstructured)
		if !ok {
			continue
		}
		if s, ok := nms.FromUnstructured(u); ok {
			st[u.GetName()] = s
		}
	}
	infos, _ := p.h.SnapshotSharedLister().NodeInfos().List()
	sort.Slice(infos, func(i, j int) bool { return infos[i].Node().Name < infos[j].Node().Name })
	var out []rules.NodeState
	obs := -1.0
	p.cxlThrottled = false
	for n, xs := range p.hres {
		k := xs[:0]
		for _, x := range xs {
			if x.until > t {
				k = append(k, x)
			}
		}
		p.hres[n] = k
	}
	for i, ni := range infos {
		name := ni.Node().Name
		s, ok := st[name]
		if !ok {
			continue
		}
		fresh := t-s.TS <= p.args.StaleSec && s.HostBufferMB >= 0
		r := 0.0
		for _, x := range p.hres[name] {
			r += x.mb
		}
		out = append(out, rules.NodeState{Name: name, Order: i, CPUAllocM: float64(ni.Allocatable.MilliCPU), CPUUsedM: float64(ni.Requested.MilliCPU),
			HostBufferMB: s.HostBufferMB, ReservedMB: r, CxlFreeMB: s.CxlFreeMB, LatRatio: s.LatRatio, Fresh: fresh,
			RecHold: fresh && s.RecHold == 1})
		if fresh && s.CxlLatRatio > obs {
			obs = s.CxlLatRatio
		}

		if fresh && s.ThrCxlPct > 0 && s.ThrCxlPct < 100 {
			p.cxlThrottled = true
		}
	}
	return out, obs
}

func (p *Plugin) params() rules.Params {
	return rules.Params{MarginMB: p.args.MarginMB, HostThr: p.args.HostThr, CxlThr: p.args.CxlThr}
}

const stateKey framework.StateKey = Name + "/decision"

type decState struct {
	d   rules.Decision
	mem float64
	obs float64
}

func (s *decState) Clone() framework.StateData { return s }

func (p *Plugin) PreFilter(ctx context.Context, cs *framework.CycleState, pod *v1.Pod) (*framework.PreFilterResult, *framework.Status) {
	if !managed(pod) {
		return nil, framework.NewStatus(framework.Skip)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	t := now()
	nodes, obs := p.snapshot(t)
	out, why := p.cres.Release(t, obs)
	for i, x := range out {
		klog.InfoS("MTIER CXL-RELEASE", "pod", x.Pod, "why", why[i], "obs", obs, "eff0", x.Eff0, "delta", x.Delta, "age", t-x.T0, "at", "prefilter")
	}
	req := rules.Request{CPUM: cpuReqM(pod), MemMB: memLimitMB(pod), ExcludeNode: pod.Annotations[nms.AnnoExcludeNode], HostOnly: pod.Annotations[nms.AnnoHostOnly] == "true"}
	eff := p.cres.Effective(obs)
	if p.cxlThrottled && eff < p.args.CxlThr {
		eff = p.args.CxlThr
	}
	d := rules.Decide(req, nodes, eff, p.params())
	if d.Wait() {
		klog.InfoS("MTIER WAIT", "pod", podKey(pod), "reason", d.Reason, "cxlObs", obs, "cxlEff", eff)
		return nil, framework.NewStatus(framework.UnschedulableAndUnresolvable, "mtier: "+d.Reason)
	}
	cs.Write(stateKey, &decState{d: d, mem: req.MemMB, obs: obs})
	klog.InfoS("MTIER PICK", "pod", podKey(pod), "node", d.Node, "tier", d.Tier, "reason", d.Reason, "cxlObs", obs, "cxlEff", eff)
	return &framework.PreFilterResult{NodeNames: sets.New(d.Node)}, nil
}

func (p *Plugin) PreFilterExtensions() framework.PreFilterExtensions { return nil }

func getState(cs *framework.CycleState) *decState {
	v, err := cs.Read(stateKey)
	if err != nil {
		return nil
	}
	s, _ := v.(*decState)
	return s
}

func (p *Plugin) Reserve(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, node string) *framework.Status {
	s := getState(cs)
	if s == nil || s.d.Node != node {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	t := now()
	switch s.d.Tier {
	case "HOST":
		p.hres[node] = append(p.hres[node], hres{until: t + p.args.HostReserveS, mb: s.mem})
	case "CXL":
		x := p.cres.Add(podKey(pod), t, s.obs)
		klog.InfoS("MTIER CXL-RESERVE", "pod", podKey(pod), "eff0", x.Eff0, "delta", x.Delta, "outstanding", len(p.cres.List))
	}
	return nil
}

func (p *Plugin) Unreserve(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, node string) {
	s := getState(cs)
	if s == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cres.Drop(podKey(pod))
	if s.d.Tier == "HOST" {
		l := p.hres[node]
		for i := len(l) - 1; i >= 0; i-- {
			if l[i].mb == s.mem {
				p.hres[node] = append(l[:i], l[i+1:]...)
				break
			}
		}
	}
}

func (p *Plugin) PreBind(ctx context.Context, cs *framework.CycleState, pod *v1.Pod, node string) *framework.Status {
	s := getState(cs)
	if s == nil {
		return nil
	}
	an := map[string]string{nms.AnnoExpected: s.d.Tier, nms.AnnoBoundAt: strconv.FormatFloat(now(), 'f', 3, 64)}
	if _, ok := pod.Annotations[nms.AnnoSubmittedAt]; !ok {
		an[nms.AnnoSubmittedAt] = strconv.FormatFloat(float64(pod.CreationTimestamp.UnixNano())/1e9, 'f', 3, 64)
	}
	b, _ := json.Marshal(map[string]interface{}{"metadata": map[string]interface{}{"annotations": an}})
	if _, err := p.h.ClientSet().CoreV1().Pods(pod.Namespace).Patch(ctx, pod.Name, types.MergePatchType, b, metav1.PatchOptions{}); err != nil {
		return framework.AsStatus(err)
	}
	klog.InfoS("MTIER BIND", "pod", podKey(pod), "node", node, "tier", s.d.Tier, "reason", s.d.Reason)
	return nil
}

func (p *Plugin) EventsToRegister() []framework.ClusterEventWithHint {
	return []framework.ClusterEventWithHint{
		{Event: framework.ClusterEvent{Resource: framework.GVK(nms.EventGVK), ActionType: framework.All}},
		{Event: framework.ClusterEvent{Resource: framework.Pod, ActionType: framework.Delete}},
	}
}

func (p *Plugin) releaseLoop(ctx context.Context) {
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		p.mu.Lock()
		t := now()
		_, obs := p.snapshot(t)
		out, why := p.cres.Release(t, obs)
		p.mu.Unlock()
		for i, x := range out {
			klog.InfoS("MTIER CXL-RELEASE", "pod", x.Pod, "why", why[i], "obs", obs, "eff0", x.Eff0, "delta", x.Delta, "age", t-x.T0)
		}
	}
}
