# Kinetic Art: Mitigating Bandwidth Contention on CXL Pooled Memory

Kinetic Art is a workload placement system that reclaims host memory slack by selectively
demoting cold pages and unmapped page cache to CXL pooled memory, and places best-effort (BE)
workloads on host memory slack, considering bandwidth contention.

- The **demote manager** identifies and demotes unmapped page cache and provides DAMON with a
  cold page demotion policy.
- The **memory slack monitor** and the **bandwidth contention monitor** collect runtime
  information on memory usage and memory access latency.
- The **placement manager** selects a worker node and chooses between host memory and CXL
  pooled memory for each BE workload.
- The **recovery manager** limits the host memory usage and bandwidth consumption by BE
  workloads under host memory pressure and bandwidth contention.

## Repository Layout

| Directory | Contents |
|---|---|
| `src/demote_manager/` | Demote manager: cold page demotion policy, file classifier (eBPF), unmapped page cache demotion |
| `src/monitoring_units/` | Memory slack monitor and bandwidth contention monitor |
| `src/placement_manager/` | Placement manager: Kubernetes scheduler plugin, node agent, containerd NRI plugin |
| `src/recovery_manager/` | Recovery manager: BE migration and eviction, BE throttling |

## Requirements

- Linux 6.12 on x86-64 with DAMON and BTF
- CXL pooled memory exposed as a CPU-less NUMA node
- cgroup v2 with the systemd cgroup driver
- Kubernetes 1.29 and containerd with NRI enabled
- gcc, clang, bpftool, libbpf, libelf, zlib, jansson, and Go 1.26

## Build

```bash
make        # eBPF object and node programs
make go     # cxl-scheduler, mtier-agent, mtier-plugin
```
