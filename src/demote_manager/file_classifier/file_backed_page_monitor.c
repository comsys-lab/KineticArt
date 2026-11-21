#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "monitor_common.h"

enum log_level g_log_level = LOG_INFO;
const char    *g_log_component = "monitor";

#define MAX_FILES 262144

struct config {
    pid_t       lc_pid;
    const char *bpf_base;
    double      interval_sec;
    const char *out_queue;
    const char *scan_dir;
    bool        consume;
};

static void config_defaults(struct config *c)
{
    c->lc_pid          = 0;
    c->bpf_base        = "/sys/fs/bpf/file_classifier";
    c->interval_sec    = 2.0;
    c->out_queue       = "/tmp/pagecache_demote_queue.json";
    c->scan_dir        = NULL;
    c->consume         = true;
}

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

struct bpf_handles {
    int file_access_fd;
    int stats_fd;
};

static int bpf_open_maps(const struct config *c, struct bpf_handles *h)
{
    char path[256];

    snprintf(path, sizeof(path), "%s/map_file_access_map", c->bpf_base);
    h->file_access_fd = bpf_obj_get(path);
    if (h->file_access_fd < 0) {
        LOG_E("bpf_obj_get(%s) failed: %s", path, strerror(errno));
        return -1;
    }

    snprintf(path, sizeof(path), "%s/map_stats_map", c->bpf_base);
    h->stats_fd = bpf_obj_get(path);
    if (h->stats_fd < 0) {
        LOG_E("bpf_obj_get(%s) failed: %s", path, strerror(errno));
        close(h->file_access_fd);
        return -1;
    }
    return 0;
}

static void bpf_close_maps(struct bpf_handles *h)
{
    if (h->file_access_fd >= 0) close(h->file_access_fd);
    if (h->stats_fd >= 0)       close(h->stats_fd);
}

static void bpf_read_stats(struct bpf_handles *h, struct bpf_stats *out)
{
    uint32_t key = 0;
    memset(out, 0, sizeof(*out));
    bpf_map_lookup_elem(h->stats_fd, &key, out);
}

struct file_entry {
    uint64_t inode;
    struct file_access_info info;
    char     path[512];
    enum file_class cls;
};

static void bpf_dump_file_access(struct bpf_handles *h, struct file_entry *arr,
                                 int max, int *count_out, bool consume)
{
    uint64_t key = 0, next_key = 0;
    int count = 0;
    int rc;

    rc = bpf_map_get_next_key(h->file_access_fd, NULL, &next_key);
    while (rc == 0 && count < max) {
        struct file_access_info info;
        if (bpf_map_lookup_elem(h->file_access_fd, &next_key, &info) == 0) {
            arr[count].inode = next_key;
            arr[count].info  = info;
            arr[count].path[0] = '\0';
            arr[count].cls = classify(info.mmap_count, info.syscall_count);
            count++;
        }
        key = next_key;
        rc = bpf_map_get_next_key(h->file_access_fd, &key, &next_key);
    }

    if (consume)
        for (int i = 0; i < count; i++)
            bpf_map_delete_elem(h->file_access_fd, &arr[i].inode);
    *count_out = count;
}

struct inode_path {
    uint64_t inode;
    char     path[512];
};

static int resolve_inode_paths(pid_t lc_pid, struct inode_path *arr, int max)
{
    int count = 0;
    char dirp[64];

    snprintf(dirp, sizeof(dirp), "/proc/%d/fd", lc_pid);
    DIR *d = opendir(dirp);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL && count < max) {
            if (de->d_name[0] == '.')
                continue;
            char linkp[320], target[512];
            snprintf(linkp, sizeof(linkp), "%s/%s", dirp, de->d_name);
            ssize_t n = readlink(linkp, target, sizeof(target) - 1);
            if (n <= 0)
                continue;
            target[n] = '\0';
            if (target[0] != '/')
                continue;
            if (strncmp(target, "/dev/", 5) == 0)
                continue;
            struct stat st;
            if (stat(target, &st) != 0)
                continue;
            arr[count].inode = st.st_ino;
            snprintf(arr[count].path, sizeof(arr[count].path), "%s", target);
            count++;
        }
        closedir(d);
    }

    char mapsp[64];
    snprintf(mapsp, sizeof(mapsp), "/proc/%d/maps", lc_pid);
    FILE *f = fopen(mapsp, "r");
    if (f) {
        char line[1024];
        while (fgets(line, sizeof(line), f) && count < max) {
            char *path = strchr(line, '/');
            if (!path)
                continue;

            size_t l = strlen(path);
            if (l && path[l - 1] == '\n')
                path[l - 1] = '\0';
            struct stat st;
            if (stat(path, &st) != 0)
                continue;

            bool dup = false;
            for (int i = 0; i < count; i++) {
                if (arr[i].inode == (uint64_t)st.st_ino) { dup = true; break; }
            }
            if (dup)
                continue;
            arr[count].inode = st.st_ino;
            snprintf(arr[count].path, sizeof(arr[count].path), "%s", path);
            count++;
        }
        fclose(f);
    }
    return count;
}

static const char *lookup_path(struct inode_path *ip, int n, uint64_t inode)
{
    for (int i = 0; i < n; i++)
        if (ip[i].inode == inode)
            return ip[i].path;
    return NULL;
}

static struct inode_path *g_dirmap = NULL;
static int g_dirmap_n = 0, g_dirmap_cap = 0;

static int cmp_inode(const void *a, const void *b)
{
    uint64_t ia = ((const struct inode_path*)a)->inode;
    uint64_t ib = ((const struct inode_path*)b)->inode;
    return (ia > ib) - (ia < ib);
}

static void dirmap_add(uint64_t inode, const char *path)
{
    if (g_dirmap_n >= g_dirmap_cap) {
        int nc = g_dirmap_cap ? g_dirmap_cap * 2 : 4096;
        struct inode_path *np = realloc(g_dirmap, (size_t)nc * sizeof(struct inode_path));
        if (!np) return;
        g_dirmap = np; g_dirmap_cap = nc;
    }
    g_dirmap[g_dirmap_n].inode = inode;
    snprintf(g_dirmap[g_dirmap_n].path, sizeof(g_dirmap[g_dirmap_n].path), "%s", path);
    g_dirmap_n++;
}

static void scan_dir_recursive(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    char p[1024];
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(p, &st) != 0) continue;
        if (S_ISDIR(st.st_mode))      scan_dir_recursive(p);
        else if (S_ISREG(st.st_mode)) dirmap_add((uint64_t)st.st_ino, p);
    }
    closedir(d);
}

static void dirmap_build(const char *dir)
{
    scan_dir_recursive(dir);
    if (g_dirmap_n > 1)
        qsort(g_dirmap, g_dirmap_n, sizeof(struct inode_path), cmp_inode);
    LOG_I("scan-dir: %s -> %d files indexed (inode->path)", dir, g_dirmap_n);
}

static const char *lookup_dirmap(uint64_t inode)
{
    if (g_dirmap_n == 0) return NULL;
    struct inode_path key; key.inode = inode;
    struct inode_path *r = bsearch(&key, g_dirmap, g_dirmap_n,
                                   sizeof(struct inode_path), cmp_inode);
    return r ? r->path : NULL;
}

static int write_file_atomic(const char *path, const char *content, size_t len)
{
    char tmp[600];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        LOG_E("open(%s) failed: %s", tmp, strerror(errno));
        return -1;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, content + off, len - off);
        if (n < 0) {
            LOG_E("write(%s) failed: %s", tmp, strerror(errno));
            close(fd);
            unlink(tmp);
            return -1;
        }
        off += n;
    }
    if (fsync(fd) != 0)
        LOG_W("fsync(%s) failed: %s", tmp, strerror(errno));
    close(fd);

    if (rename(tmp, path) != 0) {
        LOG_E("rename(%s -> %s) failed: %s", tmp, path, strerror(errno));
        unlink(tmp);
        return -1;
    }
    return 0;
}

#define DEMOTED_FILE "/tmp/pagecache_demoted_inodes"
static uint64_t *g_demoted = NULL;
static size_t    g_demoted_n = 0;
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
static void load_demoted(void) {
    g_demoted_n = 0;
    FILE *f = fopen(DEMOTED_FILE, "rb");
    if (!f) return;
    uint64_t cnt = 0;
    if (fread(&cnt, sizeof(cnt), 1, f) == 1 && cnt > 0 && cnt < 100000000u) {
        uint64_t *arr = realloc(g_demoted, cnt * sizeof(uint64_t));
        if (arr) {
            g_demoted = arr;
            g_demoted_n = fread(g_demoted, sizeof(uint64_t), cnt, f);
            qsort(g_demoted, g_demoted_n, sizeof(uint64_t), cmp_u64);
        }
    }
    fclose(f);
}
static bool is_demoted(uint64_t ino) {
    return g_demoted_n && bsearch(&ino, g_demoted, g_demoted_n, sizeof(uint64_t), cmp_u64);
}

static int write_demote_queue(const struct config *c, int cycle, double ts,
                              struct file_entry *files, int nfiles)
{
    load_demoted();

    size_t cap = 256 + (size_t)nfiles * (sizeof(files[0].path) + 256);
    char *buf = malloc(cap);
    if (!buf) {
        LOG_E("malloc(%zu) failed", cap);
        return -1;
    }
    size_t off = 0;
    off += snprintf(buf + off, cap - off,
                    "{\n  \"cycle\": %d,\n  \"timestamp\": %.6f,\n  \"candidates\": [\n",
                    cycle, ts);

    bool first = true;
    for (int i = 0; i < nfiles; i++) {
        if (files[i].cls != CLASS_SYSCALL_ONLY)
            continue;
        if (is_demoted(files[i].inode))
            continue;
        off += snprintf(buf + off, cap - off,
                        "%s    {\n"
                        "      \"inode\": %lu,\n"
                        "      \"path\": %s%s%s,\n"
                        "      \"syscall_count\": %lu,\n"
                        "      \"last_syscall_ns\": %lu,\n"
                        "      \"classification\": \"syscall-only\"\n"
                        "    }",
                        first ? "" : ",\n",
                        files[i].inode,
                        files[i].path[0] ? "\"" : "",
                        files[i].path[0] ? files[i].path : "null",
                        files[i].path[0] ? "\"" : "",
                        files[i].info.syscall_count,
                        files[i].info.last_syscall_ns);
        first = false;
    }
    off += snprintf(buf + off, cap - off, "\n  ]\n}\n");

    int rc = write_file_atomic(c->out_queue, buf, off);
    free(buf);
    return rc;
}

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --lc-pid PID [options]\n"
        "\n"
        "Required:\n"
        "  --lc-pid PID             LC process PID (for /proc/PID/fd scan)\n"
        "\n"
        "Options:\n"
        "  --bpf-base DIR           BPF pin base (default /sys/fs/bpf/file_classifier)\n"
        "  --interval SEC           polling interval (default 2.0)\n"
        "  --queue PATH             demote queue output (default /tmp/pagecache_demote_queue.json)\n"
        "  --no-consume             keep BPF map entries after reading (default: consume)\n"
        "  --scan-dir DIR           resolve inode->path by scanning DIR (for sendfile-style LC such as nginx)\n"
        "  --log-level LEVEL        debug|info|warn|error (default info)\n"
        "  --help\n",
        prog);
}

static enum log_level parse_log_level(const char *s)
{
    if (strcmp(s, "debug") == 0) return LOG_DEBUG;
    if (strcmp(s, "info")  == 0) return LOG_INFO;
    if (strcmp(s, "warn")  == 0) return LOG_WARN;
    if (strcmp(s, "error") == 0) return LOG_ERROR;
    return LOG_INFO;
}

int main(int argc, char **argv)
{
    struct config cfg;
    config_defaults(&cfg);

    static struct option longopts[] = {
        {"lc-pid",      required_argument, 0, 'p'},
        {"bpf-base",    required_argument, 0, 'b'},
        {"interval",    required_argument, 0, 'i'},
        {"queue",       required_argument, 0, 'q'},
        {"no-consume",  no_argument,       0, 'N'},
        {"scan-dir",    required_argument, 0, 'S'},
        {"log-level",   required_argument, 0, 'l'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:b:i:q:l:hS:N", longopts, NULL)) != -1) {
        switch (opt) {
        case 'p': cfg.lc_pid = atoi(optarg); break;
        case 'S': cfg.scan_dir = optarg; break;
        case 'b': cfg.bpf_base = optarg; break;
        case 'i': cfg.interval_sec = atof(optarg); break;
        case 'q': cfg.out_queue = optarg; break;
        case 'N': cfg.consume = false; break;
        case 'l': g_log_level = parse_log_level(optarg); break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (cfg.lc_pid <= 0) {
        fprintf(stderr, "ERROR: --lc-pid required\n");
        usage(argv[0]);
        return 1;
    }

    char procp[64];
    snprintf(procp, sizeof(procp), "/proc/%d", cfg.lc_pid);
    if (access(procp, F_OK) != 0) {
        LOG_E("LC PID %d not running", cfg.lc_pid);
        return 1;
    }

    libbpf_set_print(NULL);

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct bpf_handles bh = { -1, -1 };
    if (bpf_open_maps(&cfg, &bh) != 0) {
        LOG_E("BPF maps open failed - is the classifier loaded and pinned?");
        return 1;
    }

    LOG_I("started - LC PID=%d, interval=%.1fs, bpf_base=%s",
          cfg.lc_pid, cfg.interval_sec, cfg.bpf_base);
    LOG_I("queue=%s", cfg.out_queue);

    struct file_entry *files = calloc(MAX_FILES, sizeof(struct file_entry));
    struct inode_path *ipaths = calloc(MAX_FILES, sizeof(struct inode_path));
    if (!files || !ipaths) {
        LOG_E("buffer alloc failed");
        bpf_close_maps(&bh);
        free(files); free(ipaths);
        return 1;
    }

    if (cfg.scan_dir) dirmap_build(cfg.scan_dir);

    double wall_start = now_sec();

    int cycle = 0;
    while (!g_stop) {
        cycle++;
        double ts = now_sec();

        if (access(procp, F_OK) != 0) {
            LOG_W("LC PID %d gone, stopping", cfg.lc_pid);
            break;
        }

        double t_stage = now_sec();
        double ms_bpf = 0, ms_path = 0, ms_out = 0;

        struct bpf_stats bs;
        bpf_read_stats(&bh, &bs);
        int nfiles = 0;
        bpf_dump_file_access(&bh, files, MAX_FILES, &nfiles, cfg.consume);
        ms_bpf = (now_sec() - t_stage) * 1000.0; t_stage = now_sec();

        int npaths = cfg.scan_dir ? 0 : resolve_inode_paths(cfg.lc_pid, ipaths, MAX_FILES);
        for (int i = 0; i < nfiles; i++) {
            const char *p = cfg.scan_dir ? lookup_dirmap(files[i].inode)
                                         : lookup_path(ipaths, npaths, files[i].inode);
            if (p)
                snprintf(files[i].path, sizeof(files[i].path), "%s", p);
            else
                files[i].path[0] = '\0';
        }
        ms_path = (now_sec() - t_stage) * 1000.0; t_stage = now_sec();

        int counts[4] = {0, 0, 0, 0};
        int demote_candidates = 0;
        for (int i = 0; i < nfiles; i++) {
            counts[files[i].cls]++;
            if (files[i].cls == CLASS_SYSCALL_ONLY)
                demote_candidates++;
        }

        write_demote_queue(&cfg, cycle, ts, files, nfiles);
        ms_out = (now_sec() - t_stage) * 1000.0;

        if (cycle % 5 == 1 || g_log_level == LOG_DEBUG) {
            LOG_I("cycle=%d BPF[mmap=%lu sys=%lu] "
                  "files[mmap-only=%d sys-only=%d mixed=%d] queue=%d | "
                  "timing[bpf=%.1f path=%.1f out=%.1f]ms",
                  cycle, bs.mmap_hits, bs.syscall_hits,
                  counts[CLASS_MMAP_ONLY], counts[CLASS_SYSCALL_ONLY],
                  counts[CLASS_MIXED], demote_candidates,
                  ms_bpf, ms_path, ms_out);
        }

        double elapsed = now_sec() - ts;
        double sleep_s = cfg.interval_sec - elapsed;
        if (sleep_s > 0) {
            struct timespec req = {
                .tv_sec  = (time_t)sleep_s,
                .tv_nsec = (long)((sleep_s - (time_t)sleep_s) * 1e9),
            };
            nanosleep(&req, NULL);
        }
    }

    {
        double wall = now_sec() - wall_start;
        struct rusage ru;
        getrusage(RUSAGE_SELF, &ru);
        double utime = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6;
        double stime = ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6;
        double cpu = utime + stime;
        LOG_I("CPU self-report: utime=%.3fs stime=%.3fs total=%.3fs over wall=%.1fs "
              "= %.2f%% of 1 core (%d cycles, %.2f ms/cycle)",
              utime, stime, cpu, wall,
              wall > 0 ? 100.0 * cpu / wall : 0.0,
              cycle, cycle > 0 ? cpu * 1000.0 / cycle : 0.0);
    }

    LOG_I("stopping (cycle=%d), cleanup", cycle);
    bpf_close_maps(&bh);
    free(files);
    free(ipaths);
    return 0;
}
