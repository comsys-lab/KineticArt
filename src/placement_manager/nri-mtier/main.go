package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

type config struct {
	capJSON, latJSON string
	marginMB         float64
	latThresh        float64
	staleSec         float64
	manageAnnotation string
	followAnno       string
	beListFile       string
	beSchedDir       string
	beCPUs           string
}

func podCgroupPath(uid string) string {
	u := strings.ReplaceAll(uid, "-", "_")
	for _, p := range []string{
		"/sys/fs/cgroup/kubepods.slice/kubepods-pod" + u + ".slice",
		"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + u + ".slice",
		"/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + u + ".slice",
	} {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	return ""
}

func (p *plugin) registerBEForRecovery(uid string) {
	dir, u := p.cfg.beSchedDir, strings.ReplaceAll(uid, "-", "_")
	if dir == "" || uid == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("[mtier] WARN mkdir be-sched-dir failed (%s): %v", dir, err)
		return
	}
	go func() {
		for i := 0; i < 15; i++ {
			if cg := podCgroupPath(uid); cg != "" {
				link := filepath.Join(dir, "be_sched_"+u)
				os.Remove(link)
				if err := os.Symlink(cg, link); err != nil {
					log.Printf("[mtier] WARN be_sched_ symlink failed (%s): %v", link, err)
				} else {
					log.Printf("[mtier] registered for recovery: %s -> %s", link, cg)
				}
				return
			}
			time.Sleep(time.Second)
		}
		log.Printf("[mtier] WARN cgroup of pod %s not found within 15s -> not registered for recovery", uid)
	}()
}

func appendBEUID(path, uid string) {
	if path == "" || uid == "" {
		return
	}
	if b, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(line) == uid {
				return
			}
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[mtier] WARN be-list append failed (%s): %v", path, err)
		return
	}
	defer f.Close()
	f.WriteString(uid + "\n")
}

type plugin struct {
	cfg  config
	cpus *cpuPool
}

func readFresh(path string, staleSec float64, v interface{}) bool {
	fi, err := os.Stat(path)
	if err != nil || time.Since(fi.ModTime()).Seconds() > staleSec {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, v) == nil
}

func managed(pod *api.PodSandbox, key string) bool {
	return pod != nil && pod.GetAnnotations()[key] == "true"
}

func memLimitMB(ctr *api.Container) float64 {
	return float64(ctr.GetLinux().GetResources().GetMemory().GetLimit().GetValue()) / (1024 * 1024)
}

func (p *plugin) decideFor(pod *api.PodSandbox, ctr *api.Container) (decision, float64) {
	var cap capStats
	var lat latStats
	capFresh := readFresh(p.cfg.capJSON, p.cfg.staleSec, &cap)
	latFresh := readFresh(p.cfg.latJSON, p.cfg.staleSec, &lat)
	size := memLimitMB(ctr)

	if p.cfg.followAnno != "" {
		if !capFresh {
			return decision{"DEFER", "", "follow_capacity_stale"}, size
		}
		switch pod.GetAnnotations()[p.cfg.followAnno] {
		case "HOST":
			if cap.HostBufferMB >= size {
				return decision{"HOST", strconv.Itoa(cap.HostNode), "follow_scheduler"}, size
			}
		case "CXL":
			if cap.CxlFreeMB >= size {
				return decision{"CXL", strconv.Itoa(cap.CxlNode), "follow_scheduler"}, size
			}
		}
		d := decide(size, p.cfg.marginMB, p.cfg.latThresh, &cap, capFresh, &lat, latFresh)
		d.Reason = "follow_fallback_" + d.Reason
		return d, size
	}
	return decide(size, p.cfg.marginMB, p.cfg.latThresh, &cap, capFresh, &lat, latFresh), size
}

func (p *plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	if !managed(pod, p.cfg.manageAnnotation) {
		return nil, nil, nil
	}
	d, size := p.decideFor(pod, ctr)
	cpu := ""
	if p.cpus.enabled() {
		cpu = p.cpus.pick(ctr.GetId())
	}
	log.Printf("[mtier] CreateContainer pod=%s ctr=%s size=%.0fMB -> %s mems=%s cpus=%s (%s)",
		pod.GetName(), ctr.GetName(), size, d.Tier, d.Mems, cpu, d.Reason)
	if d.Mems == "" {
		if cpu == "" {
			return nil, nil, nil
		}
		adj := &api.ContainerAdjustment{}
		adj.SetLinuxCPUSetCPUs(cpu)
		return adj, nil, nil
	}
	appendBEUID(p.cfg.beListFile, pod.GetUid())

	if d.Tier == "HOST" {
		p.registerBEForRecovery(pod.GetUid())
	}
	adj := &api.ContainerAdjustment{}
	adj.SetLinuxCPUSetMems(d.Mems)
	if cpu != "" {
		adj.SetLinuxCPUSetCPUs(cpu)
	}
	return adj, nil, nil
}

func (p *plugin) Synchronize(ctx context.Context, pods []*api.PodSandbox, ctrs []*api.Container) ([]*api.ContainerUpdate, error) {
	n := 0
	if p.cpus.enabled() {
		mp := map[string]bool{}
		for _, pd := range pods {
			if managed(pd, p.cfg.manageAnnotation) {
				mp[pd.GetId()] = true
			}
		}
		for _, c := range ctrs {
			if mp[c.GetPodSandboxId()] && p.cpus.adopt(c.GetId(), c.GetLinux().GetResources().GetCpu().GetCpus()) {
				n++
			}
		}
	}
	log.Printf("[mtier] Synchronize: %d pods, %d containers, %d vCPU assignments recovered", len(pods), len(ctrs), n)
	return nil, nil
}

func (p *plugin) StopContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) ([]*api.ContainerUpdate, error) {
	p.cpus.release(ctr.GetId())
	return nil, nil
}

func (p *plugin) RemoveContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	p.cpus.release(ctr.GetId())
	return nil
}

func main() {
	var c config
	flag.StringVar(&c.capJSON, "cap-json", "/tmp/capacity_stats.json", "memory slack monitor JSON")
	flag.StringVar(&c.latJSON, "lat-json", "/tmp/probe_stats.json", "latency stats JSON (latency_ratio)")
	flag.Float64Var(&c.marginMB, "margin-mb", 512, "admission margin MB")
	flag.Float64Var(&c.latThresh, "lat-thresh", 1.2, "host latency_ratio threshold; at or above, new BE goes to CXL")
	flag.Float64Var(&c.staleSec, "stale-sec", 5, "stats freshness limit (s)")
	flag.StringVar(&c.manageAnnotation, "manage-annotation", "mtier.scheduler/managed", "pod opt-in annotation key (=true)")
	flag.StringVar(&c.beListFile, "be-list-file", "/tmp/mtier_be_pods.list", "managed BE pod UID list (read by the memory slack monitor)")
	flag.StringVar(&c.beSchedDir, "be-sched-dir", "/tmp/mtier_be_sched", "be_sched_* symlink dir for host-placed BEs (read by recovery_manager)")
	flag.StringVar(&c.beCPUs, "be-cpus", "", "BE vCPU list, e.g. 7,8,9 (least-assigned vCPU per BE; empty = off)")
	flag.StringVar(&c.followAnno, "follow-anno", "mtier.scheduler/expected-tier", "annotation holding the scheduler tier (HOST|CXL); followed when it fits, else decided locally; empty = local only")
	flag.Parse()

	p := &plugin{cfg: c, cpus: newCPUPool(c.beCPUs)}
	s, err := stub.New(p, stub.WithPluginName("mtier"), stub.WithPluginIdx("10"))
	if err != nil {
		log.Fatalf("stub.New: %v", err)
	}
	log.Printf("[mtier] starting (cap=%s lat=%s margin=%.0f lat_thresh=%.2f anno=%s be_list=%s be_sched=%s be_cpus=%s)",
		c.capJSON, c.latJSON, c.marginMB, c.latThresh, c.manageAnnotation, c.beListFile, c.beSchedDir, c.beCPUs)
	if err := s.Run(context.Background()); err != nil {
		log.Fatalf("plugin exited: %v", err)
	}
}
