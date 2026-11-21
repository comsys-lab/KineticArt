#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }

int main(int argc, char **argv)
{
    if (argc != 4) { fprintf(stderr, "usage: %s <bpf.o> <pin_dir> <cgroup dir>\n", argv[0]); return 2; }
    const char *obj_path = argv[1], *pin_dir = argv[2], *cg_dir = argv[3];

    struct stat st;
    if (stat(cg_dir, &st) != 0) { fprintf(stderr, "cgroup %s: %s\n", cg_dir, strerror(errno)); return 1; }
    __u64 cgid = (__u64)st.st_ino;
    if (mkdir(pin_dir, 0700) != 0 && errno != EEXIST) { fprintf(stderr, "mkdir %s: %s\n", pin_dir, strerror(errno)); return 1; }

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj)) { fprintf(stderr, "open %s failed\n", obj_path); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load failed\n"); return 1; }

    struct bpf_link *links[8]; int nlink = 0; char path[512];
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *l = bpf_program__attach(prog);
        if (libbpf_get_error(l)) { fprintf(stderr, "attach %s failed\n", bpf_program__name(prog)); goto out; }
        if (nlink < 8) links[nlink++] = l;
        printf("attached %s\n", bpf_program__name(prog));
    }
    struct bpf_map *m;
    bpf_object__for_each_map(m, obj) {
        snprintf(path, sizeof(path), "%s/map_%s", pin_dir, bpf_map__name(m));
        unlink(path);
        if (bpf_map__pin(m, path)) { fprintf(stderr, "pin %s failed: %s\n", path, strerror(errno)); goto out; }
        if (strcmp(bpf_map__name(m), "target_cgroup_map") == 0) {
            __u32 k = 0;
            if (bpf_map_update_elem(bpf_map__fd(m), &k, &cgid, BPF_ANY)) { fprintf(stderr, "set target cgroup failed: %s\n", strerror(errno)); goto out; }
        }
    }
    if (nlink != 3) { fprintf(stderr, "attached %d kprobes, expected 3 (filemap_get_pages, generic_perform_write, do_mmap)\n", nlink); goto out; }
    printf("loaded: %d kprobes, maps pinned in %s, target cgroup inode %llu (%s)\n", nlink, pin_dir, (unsigned long long)cgid, cg_dir);
    fflush(stdout);

    signal(SIGTERM, on_sig); signal(SIGINT, on_sig);
    while (!g_stop) pause();

out:
    for (int i = 0; i < nlink; i++) bpf_link__destroy(links[i]);
    bpf_object__for_each_map(m, obj) { snprintf(path, sizeof(path), "%s/map_%s", pin_dir, bpf_map__name(m)); unlink(path); }
    rmdir(pin_dir);
    bpf_object__close(obj);
    printf("unloaded: %d kprobes detached, %s removed\n", nlink, pin_dir);
    return g_stop ? 0 : 1;
}
