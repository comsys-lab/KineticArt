#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} target_cgroup_map SEC(".maps");

struct file_access_info {
    __u64 inode_id;
    __u64 last_mmap_ns;
    __u64 last_syscall_ns;
    __u64 mmap_count;
    __u64 syscall_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u64);
    __type(value, struct file_access_info);
} file_access_map SEC(".maps");

struct stats {
    __u64 mmap_hits;
    __u64 syscall_hits;
    __u64 skipped_no_inode;
    __u64 skipped_not_target;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} stats_map SEC(".maps");

static __always_inline bool is_target_cgroup(void)
{
    __u32 key = 0;
    __u64 *target = bpf_map_lookup_elem(&target_cgroup_map, &key);
    if (!target || *target == 0)
        return false;

    __u64 current = bpf_get_current_cgroup_id();
    return current == *target;
}

static __always_inline void inc_stat(__u32 field, __u64 delta)
{
    __u32 key = 0;
    struct stats *s = bpf_map_lookup_elem(&stats_map, &key);
    if (!s) return;

    if (field == 0)
        __sync_fetch_and_add(&s->mmap_hits, delta);
    else if (field == 1)
        __sync_fetch_and_add(&s->syscall_hits, delta);
    else if (field == 2)
        __sync_fetch_and_add(&s->skipped_no_inode, delta);
    else if (field == 3)
        __sync_fetch_and_add(&s->skipped_not_target, delta);
}

static __always_inline void update_file_access(struct file *file, bool is_syscall)
{
    if (!file) {
        inc_stat(2, 1);
        return;
    }

    struct inode *inode = NULL;
    bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);
    if (!inode) {
        inc_stat(2, 1);
        return;
    }

    __u64 inode_id = 0;
    bpf_probe_read_kernel(&inode_id, sizeof(inode_id), &inode->i_ino);
    if (inode_id == 0) {
        inc_stat(2, 1);
        return;
    }

    __u64 now = bpf_ktime_get_ns();

    struct file_access_info *info = bpf_map_lookup_elem(&file_access_map, &inode_id);
    if (!info) {
        struct file_access_info new_info = {};
        new_info.inode_id = inode_id;
        if (is_syscall) {
            new_info.last_syscall_ns = now;
            new_info.syscall_count = 1;
        } else {
            new_info.last_mmap_ns = now;
            new_info.mmap_count = 1;
        }
        bpf_map_update_elem(&file_access_map, &inode_id, &new_info, BPF_ANY);
    } else {
        if (is_syscall) {
            __sync_fetch_and_add(&info->syscall_count, 1);
            info->last_syscall_ns = now;
        } else {
            __sync_fetch_and_add(&info->mmap_count, 1);
            info->last_mmap_ns = now;
        }
    }

    inc_stat(is_syscall ? 1 : 0, 1);
}

SEC("kprobe/filemap_get_pages")
int BPF_KPROBE(trace_filemap_get_pages, struct kiocb *iocb)
{
    if (!is_target_cgroup()) {
        inc_stat(3, 1);
        return 0;
    }
    struct file *file = BPF_CORE_READ(iocb, ki_filp);
    update_file_access(file, true);
    return 0;
}

SEC("kprobe/generic_perform_write")
int BPF_KPROBE(trace_generic_perform_write, struct kiocb *iocb)
{
    if (!is_target_cgroup()) {
        inc_stat(3, 1);
        return 0;
    }
    struct file *file = BPF_CORE_READ(iocb, ki_filp);
    update_file_access(file, true);
    return 0;
}

SEC("kprobe/do_mmap")
int BPF_KPROBE(trace_do_mmap, struct file *file)
{
    if (!is_target_cgroup()) {
        inc_stat(3, 1);
        return 0;
    }
    if (!file) return 0;
    update_file_access(file, false);
    return 0;
}
