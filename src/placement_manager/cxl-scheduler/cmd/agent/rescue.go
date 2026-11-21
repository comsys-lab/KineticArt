//go:build linux

package main

import (
	"bufio"
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"cxlsched/pkg/nms"
)

var podUIDRe = regexp.MustCompile(`(?:pod|be_sched_)([0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12})`)

type rescuer struct {
	cs              kubernetes.Interface
	dyn             dynamic.ResourceInterface
	node, file      string
	marginMB, hostT float64
	stale           time.Duration
	off             int64
}

func (r *rescuer) otherHostSlack(ctx context.Context, memMB float64) (string, error) {
	l, err := r.dyn.List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}
	nowS := float64(time.Now().UnixNano()) / 1e9
	for _, it := range l.Items {
		if it.GetName() == r.node {
			continue
		}
		s, ok := nms.FromUnstructured(&it)
		if !ok || nowS-s.TS > r.stale.Seconds() || s.HostBufferMB < 0 {
			continue
		}
		if s.HostBufferMB >= memMB+r.marginMB && (s.LatRatio <= 0 || s.LatRatio < r.hostT) {
			return it.GetName(), nil
		}
	}
	return "", nil
}

func memMB(pod *v1.Pod) float64 {
	s := 0.0
	for _, c := range pod.Spec.Containers {
		if q, ok := c.Resources.Limits[v1.ResourceMemory]; ok {
			s += float64(q.Value()) / (1 << 20)
		}
	}
	return s
}

func (r *rescuer) handle(ctx context.Context, cg string) {
	m := podUIDRe.FindStringSubmatch(cg)
	if m == nil {
		klog.InfoS("AGENT RESCUE skip (no pod UID)", "cg", cg)
		return
	}
	uid := types.UID(strings.ReplaceAll(m[1], "_", "-"))
	pl, err := r.cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: "spec.nodeName=" + r.node})
	if err != nil {
		klog.ErrorS(err, "AGENT RESCUE pod list")
		return
	}
	var old *v1.Pod
	for i := range pl.Items {
		if pl.Items[i].UID == uid {
			old = &pl.Items[i]
		}
	}
	if old == nil || old.Annotations[nms.AnnoManaged] != "true" {
		klog.InfoS("AGENT RESCUE skip (not a managed BE or gone)", "uid", uid)
		return
	}
	mb := memMB(old)
	to, err := r.otherHostSlack(ctx, mb)
	if err != nil {
		klog.ErrorS(err, "AGENT RESCUE CR list")
		return
	}
	if to == "" {
		klog.InfoS("AGENT RESCUE none -> stays killed (no host slack on other nodes)", "pod", old.Namespace+"/"+old.Name, "memMB", mb)
		return
	}
	n, _ := strconv.Atoi(old.Annotations[nms.AnnoRescued])
	np := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: old.Name + "-r", Namespace: old.Namespace, Labels: old.Labels, Annotations: map[string]string{}}, Spec: *old.Spec.DeepCopy()}
	for _, k := range []string{nms.AnnoManaged, nms.AnnoSubmittedAt} {
		if v, ok := old.Annotations[k]; ok {
			np.Annotations[k] = v
		}
	}
	np.Annotations[nms.AnnoExcludeNode] = r.node
	np.Annotations[nms.AnnoHostOnly] = "true"
	np.Annotations[nms.AnnoRescued] = strconv.Itoa(n + 1)
	np.Spec.NodeName = ""

	zero := int64(0)
	var cerr error
	for t := 0; t < 3; t++ {
		if _, cerr = r.cs.CoreV1().Pods(old.Namespace).Create(ctx, np, metav1.CreateOptions{}); cerr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if cerr != nil {
		klog.ErrorS(cerr, "AGENT RESCUE create failed -> original pod kept (killed)", "pod", old.Name)
		return
	}
	derr := r.cs.CoreV1().Pods(old.Namespace).Delete(ctx, old.Name, metav1.DeleteOptions{GracePeriodSeconds: &zero})
	klog.InfoS("AGENT RESCUE", "old", old.Namespace+"/"+old.Name, "new", np.Name, "fromNode", r.node, "slackOn", to, "memMB", mb, "rescued", n+1, "deleteErr", derr)
}

func (r *rescuer) poll(ctx context.Context) {
	f, err := os.Open(r.file)
	if err != nil {
		return
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() < r.off {
		r.off = 0
	}
	if _, err := f.Seek(r.off, 0); err != nil {
		return
	}
	rd := bufio.NewReader(f)
	for {
		ln, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		r.off += int64(len(ln))
		a := strings.Fields(ln)
		if len(a) == 2 {
			r.handle(ctx, a[1])
		}
	}
}

func startRescuer(ctx context.Context, cs kubernetes.Interface, dyn dynamic.ResourceInterface, node, file string, marginMB, hostT float64, stale time.Duration) {
	r := &rescuer{cs: cs, dyn: dyn, node: node, file: file, marginMB: marginMB, hostT: hostT, stale: stale}
	if st, err := os.Stat(file); err == nil {
		r.off = st.Size()
	}
	klog.InfoS("AGENT rescuer start", "file", file, "marginMB", marginMB, "hostThr", hostT, "skipBytes", r.off)
	go func() {
		tk := time.NewTicker(time.Second)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				r.poll(ctx)
			}
		}
	}()
}
