//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"cxlsched/pkg/nms"
)

func readFresh(path string, stale time.Duration, v interface{}) bool {
	fi, err := os.Stat(path)
	if err != nil || time.Since(fi.ModTime()) > stale {
		return false
	}
	b, err := os.ReadFile(path)
	return err == nil && json.Unmarshal(b, v) == nil
}

func main() {
	node := flag.String("node", "", "node name (CR name)")
	kc := flag.String("kubeconfig", "", "kubeconfig")
	capJ := flag.String("cap-json", "/tmp/capacity_stats.json", "memory slack monitor JSON")
	latJ := flag.String("lat-json", "/tmp/probe_stats.json", "bandwidth contention monitor JSON")
	iv := flag.Duration("interval", time.Second, "publish interval")
	stale := flag.Duration("stale", 5*time.Second, "input JSON freshness limit")
	killedF := flag.String("killed-file", "/tmp/mtier_killed.list", "BE cgroups killed by recovery_manager")
	rescue := flag.Bool("rescue", true, "resubmit killed BEs to a node with host slack")
	marginMB := flag.Float64("margin-mb", 1000, "host slack margin MB (match scheduler marginMB)")
	hostThr := flag.Float64("host-thr", 1.125, "host latency_ratio threshold (match scheduler hostThr)")
	thrLevelF := flag.String("thr-level-file", "/tmp/mtier_thr_cxl.level", "CXL throttle level file: <pct> <targets> <floor>")
	recF := flag.String("rec-metrics", "/tmp/recovery_metrics.csv", "recovery_manager metrics CSV (acted_mb > 0 starts recovery hold)")
	holdWin := flag.Duration("rec-hold-window", 30*time.Second, "recovery hold release window")
	holdG := flag.Float64("rec-hold-growth-mbps", 1.0, "recovery hold release threshold, LC host growth MB/s")
	clusterF := flag.String("cluster-json", "/tmp/mtier_cluster.json", "cluster CXL signal output (max cxlLatRatio, all_floor) for the CXL throttle")
	flag.Parse()
	if *node == "" {
		klog.Fatal("--node required")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", *kc)
	if err != nil {
		klog.Fatal(err)
	}
	dyn := dynamic.NewForConfigOrDie(cfg).Resource(nms.GVR)
	ctx := context.Background()
	if *rescue {
		startRescuer(ctx, kubernetes.NewForConfigOrDie(cfg), dyn, *node, *killedF, *marginMB, *hostThr, *stale)
	}
	rh := &recHold{path: *recF, win: *holdWin, g: *holdG}
	for {
		var c struct {
			HB float64  `json:"host_buffer_mb"`
			CF float64  `json:"cxl_free_mb"`
			LM *float64 `json:"lc_mapped_host_mb"`
		}
		var l struct {
			L  *float64 `json:"latency_ratio"`
			CL *float64 `json:"cxl_latency_ratio"`
		}
		s := nms.Status{TS: float64(time.Now().UnixNano()) / 1e9, HostBufferMB: -1, CxlFreeMB: -1, LatRatio: -1, CxlLatRatio: -1, ThrCxlPct: -1, RecHold: -1}
		if st, err := os.Stat(*thrLevelF); err == nil && time.Since(st.ModTime()) <= *stale {
			if b, err := os.ReadFile(*thrLevelF); err == nil {
				var p, t, f float64
				if n, _ := fmt.Sscan(string(b), &p, &t, &f); n == 3 {
					s.ThrCxlPct, s.ThrCxlTargets, s.ThrCxlFloor = p, t, f
				}
			}
		}
		if readFresh(*capJ, *stale, &c) {
			s.HostBufferMB, s.CxlFreeMB = c.HB, c.CF
			if c.LM != nil {
				s.RecHold = rh.update(time.Now(), *c.LM)
			}
		}
		if readFresh(*latJ, *stale, &l) && l.L != nil && l.CL != nil {
			s.LatRatio, s.CxlLatRatio = *l.L, *l.CL
		}
		b, _ := json.Marshal(map[string]interface{}{"status": s.StatusMap()})
		if _, err := dyn.Patch(ctx, *node, types.MergePatchType, b, metav1.PatchOptions{}); apierrors.IsNotFound(err) {
			u := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": nms.APIVersion, "kind": nms.Kind,
				"metadata": map[string]interface{}{"name": *node}, "status": s.StatusMap()}}
			_, err = dyn.Create(ctx, u, metav1.CreateOptions{})
			if err != nil {
				klog.ErrorS(err, "create")
			}
		} else if err != nil {
			klog.ErrorS(err, "patch")
		}
		writeCluster(ctx, dyn, *clusterF, *stale)
		time.Sleep(*iv)
	}
}

func writeCluster(ctx context.Context, dyn dynamic.ResourceInterface, path string, stale time.Duration) {
	l, err := dyn.List(ctx, metav1.ListOptions{})
	if err != nil {
		klog.ErrorS(err, "cluster list")
		return
	}
	nowS := float64(time.Now().UnixNano()) / 1e9
	mx, n, withBE, atFloor, maxNode := -1.0, 0, 0, 0, ""
	for i := range l.Items {
		st, ok := nms.FromUnstructured(&l.Items[i])
		if !ok || nowS-st.TS > stale.Seconds() {
			continue
		}
		n++
		if st.CxlLatRatio > mx {
			mx, maxNode = st.CxlLatRatio, l.Items[i].GetName()
		}
		if st.ThrCxlTargets > 0 {
			withBE++
			if st.ThrCxlFloor == 1 {
				atFloor++
			}
		}
	}
	all := 0
	if withBE > 0 && atFloor == withBE {
		all = 1
	}
	b, _ := json.Marshal(map[string]interface{}{"ts": nowS, "cxl_latency_ratio": mx, "max_node": maxNode, "nodes": n, "cxl_nodes": withBE, "all_floor": all})
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0644) == nil {
		os.Rename(tmp, path)
	}
}

type recHold struct {
	path    string
	win     time.Duration
	g       float64
	off     int64
	on      bool
	lastAct time.Time
	samp    []recSamp
}

type recSamp struct {
	t time.Time
	v float64
}

func (r *recHold) acted() bool {
	f, err := os.Open(r.path)
	if err != nil {
		return false
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() < r.off {
		r.off = 0
	}
	if _, err := f.Seek(r.off, 0); err != nil {
		return false
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return false
	}
	i := strings.LastIndexByte(string(b), '\n')
	if i < 0 {
		return false
	}
	r.off += int64(i + 1)
	hit := false
	for _, ln := range strings.Split(string(b[:i]), "\n") {
		a := strings.Split(ln, ",")
		if len(a) > 9 {
			if v, err := strconv.ParseFloat(a[9], 64); err == nil && v > 0 {
				hit = true
			}
		}
	}
	return hit
}

func (r *recHold) update(now time.Time, lcMapped float64) float64 {
	r.samp = append(r.samp, recSamp{now, lcMapped})
	for len(r.samp) > 1 && now.Sub(r.samp[1].t) >= r.win {
		r.samp = r.samp[1:]
	}
	if r.acted() {
		if !r.on {
			klog.InfoS("REC-HOLD on", "lcMappedMB", lcMapped)
		}
		r.on, r.lastAct = true, now
	}
	if r.on && now.Sub(r.lastAct) >= r.win && now.Sub(r.samp[0].t) >= r.win-2*time.Second {
		g := (lcMapped - r.samp[0].v) / now.Sub(r.samp[0].t).Seconds()
		if g < r.g {
			r.on = false
			klog.InfoS("REC-HOLD off", "growthMBps", g, "heldSinceLastActS", now.Sub(r.lastAct).Seconds())
		}
	}
	if r.on {
		return 1
	}
	return 0
}
