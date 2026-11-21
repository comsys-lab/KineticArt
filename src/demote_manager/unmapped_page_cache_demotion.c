#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <dirent.h>

#include <jansson.h>

#include "file_classifier/monitor_common.h"

enum log_level g_log_level = LOG_INFO;
const char    *g_log_component = "manager";

#ifndef SYS_move_pages
#define SYS_move_pages 279
#endif

#define MPOL_MF_MOVE (1 << 1)

struct config {
    const char *queue;
    const char *cgroup;
    int         target_node;
    int         source_node;
    double      drip_mb;
    const char *lat_json;
    double      lat_k_gate;
    double      poll_interval_sec;
    bool        verbose;
};

static void config_defaults(struct config *c)
{
    c->queue               = "/tmp/pagecache_demote_queue.json";
    c->cgroup              = NULL;
    c->target_node         = -1;
    c->source_node         = -1;
    c->drip_mb             = 32.0;
    c->lat_json            = "/tmp/probe_stats.json";
    c->lat_k_gate          = 1.1;
    c->poll_interval_sec   = 1.0;
    c->verbose             = false;
}

static int node_cpulist_empty(int node) {
    char path[256], buf[64];
    snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/cpulist", node);
    FILE *f = fopen(path, "r"); if (!f) return -1;
    char *r = fgets(buf, sizeof(buf), f); fclose(f);
    if (!r) return 1;
    return (buf[0] == '\n' || buf[0] == '\0') ? 1 : 0;
}
static long node_mem_total_kb(int node) {
    char path[256], line[256];
    snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/meminfo", node);
    FILE *f = fopen(path, "r"); if (!f) return -1;
    long kb = -1;
    while (fgets(line, sizeof(line), f)) {
        char *p = strstr(line, "MemTotal:");
        if (p) { sscanf(p, "MemTotal: %ld", &kb); break; }
    }
    fclose(f); return kb;
}
static int node_distance_to(int from, int to) {
    char path[256], line[1024];
    snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/distance", from);
    FILE *f = fopen(path, "r"); if (!f) return -1;
    char *r = fgets(line, sizeof(line), f); fclose(f);
    if (!r) return -1;
    char *p = line; int idx = 0;
    while (*p) {
        char *end; long v = strtol(p, &end, 10);
        if (end == p) break;
        if (idx == to) return (int)v;
        idx++; p = end;
    }
    return -1;
}
static void detect_nodes(int *host, int *cxl) {
    if (*cxl < 0) {
        DIR *d = opendir("/sys/devices/system/node");
        if (d) {
            struct dirent *e; int best = -1;
            while ((e = readdir(d))) {
                int n;
                if (sscanf(e->d_name, "node%d", &n) != 1) continue;
                if (node_mem_total_kb(n) > 0 && node_cpulist_empty(n) == 1 && (best < 0 || n < best)) best = n;
            }
            closedir(d); *cxl = best;
        }
    }
    if (*host < 0 && *cxl >= 0) {
        DIR *d = opendir("/sys/devices/system/node");
        if (d) {
            struct dirent *e; int best = -1, bestd = 1 << 30;
            while ((e = readdir(d))) {
                int n;
                if (sscanf(e->d_name, "node%d", &n) != 1) continue;
                if (n == *cxl || node_cpulist_empty(n) != 0) continue;
                int dist = node_distance_to(*cxl, n);
                if (dist >= 0 && dist < bestd) { bestd = dist; best = n; }
            }
            closedir(d); *host = best;
        }
    }
}

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

static long move_pages_syscall(int pid, unsigned long count, void **pages,
                               const int *nodes, int *status, int flags)
{
    return syscall(SYS_move_pages, pid, count, pages, nodes, status, flags);
}

struct demote_result {
    bool     ok;
    char     errmsg[128];
    uint64_t total_pages;
    uint64_t size_bytes;
    uint64_t already_on_target;
    uint64_t moved;
    uint64_t ebusy;
    uint64_t enoent;
    double   query_ms;
    double   move_ms;
};

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void demote_file(const char *path, int target_node, struct demote_result *r)
{
    memset(r, 0, sizeof(*r));

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        snprintf(r->errmsg, sizeof(r->errmsg), "open: %s", strerror(errno));
        return;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        snprintf(r->errmsg, sizeof(r->errmsg), "fstat: %s", strerror(errno));
        close(fd);
        return;
    }
    if (st.st_size == 0) {
        snprintf(r->errmsg, sizeof(r->errmsg), "empty file");
        close(fd);
        return;
    }

    size_t size = (size_t)st.st_size;
    void *addr = mmap(NULL, size, PROT_READ, MAP_SHARED | MAP_POPULATE, fd, 0);
    if (addr == MAP_FAILED) {
        snprintf(r->errmsg, sizeof(r->errmsg), "mmap: %s", strerror(errno));
        close(fd);
        return;
    }

    uint64_t n_pages = (size + PAGE_SIZE_BYTES - 1) / PAGE_SIZE_BYTES;
    void **pages    = malloc(n_pages * sizeof(void *));
    int   *status_q = malloc(n_pages * sizeof(int));
    void **move_p   = malloc(n_pages * sizeof(void *));
    int   *move_n   = malloc(n_pages * sizeof(int));
    int   *move_s   = malloc(n_pages * sizeof(int));
    if (!pages || !status_q || !move_p || !move_n || !move_s) {
        snprintf(r->errmsg, sizeof(r->errmsg), "malloc failed for %lu pages", n_pages);
        goto out;
    }

    for (uint64_t i = 0; i < n_pages; i++) {
        pages[i]    = (char *)addr + i * PAGE_SIZE_BYTES;
        status_q[i] = -1;
    }

    double t0 = now_sec();
    long qret = move_pages_syscall(0, n_pages, pages, NULL, status_q, 0);
    double t1 = now_sec();
    if (qret < 0) {
        snprintf(r->errmsg, sizeof(r->errmsg), "move_pages(query): %s", strerror(errno));
        goto out;
    }

    uint64_t nmove = 0;
    for (uint64_t i = 0; i < n_pages; i++) {
        int s = status_q[i];
        if (s == target_node) {
            r->already_on_target++;
        } else if (s >= 0) {
            move_p[nmove] = pages[i];
            move_n[nmove] = target_node;
            nmove++;
        } else if (s == -ENOENT) {
            r->enoent++;
        }
    }

    double t2 = now_sec();
    if (nmove > 0) {
        long mret = move_pages_syscall(0, nmove, move_p, move_n, move_s, MPOL_MF_MOVE);
        if (mret < 0) {
            snprintf(r->errmsg, sizeof(r->errmsg), "move_pages(move): %s", strerror(errno));
            goto out;
        }
        for (uint64_t i = 0; i < nmove; i++) {
            int s = move_s[i];
            if (s == target_node)        r->moved++;
            else if (s == -EBUSY)        r->ebusy++;
            else if (s == -ENOENT)       r->enoent++;
        }
    }
    double t3 = now_sec();

    r->ok          = true;
    r->total_pages = n_pages;
    r->size_bytes  = size;
    r->query_ms    = (t1 - t0) * 1000.0;
    r->move_ms     = (t3 - t2) * 1000.0;

out:
    free(pages); free(status_q); free(move_p); free(move_n); free(move_s);
    munmap(addr, size);
    close(fd);
}

static uint64_t read_numa_file_bytes(const char *cgroup, int node)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/memory.numa_stat", cgroup);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;

    char line[4096];
    uint64_t result = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "file ", 5) != 0)
            continue;

        char key[16];
        snprintf(key, sizeof(key), "N%d=", node);
        char *p = strstr(line, key);
        if (p) {
            p += strlen(key);
            result = strtoull(p, NULL, 10);
        }
        break;
    }
    fclose(f);
    return result;
}

#define BYTES_TO_MB(b) ((b) / (1024.0 * 1024.0))

struct candidate {
    uint64_t inode;
    char     path[512];
};

static int parse_queue(const char *queue_path, struct candidate *arr, int max)
{
    json_error_t err;
    json_t *root = json_load_file(queue_path, 0, &err);
    if (!root) {
        LOG_W("queue parse failed (%s:%d): %s", queue_path, err.line, err.text);
        return -1;
    }

    json_t *cands = json_object_get(root, "candidates");
    if (!json_is_array(cands)) {
        LOG_W("queue has no candidates array");
        json_decref(root);
        return -1;
    }

    int n = 0;
    size_t idx;
    json_t *item;
    json_array_foreach(cands, idx, item) {
        if (n >= max)
            break;
        json_t *jinode = json_object_get(item, "inode");
        json_t *jpath  = json_object_get(item, "path");

        arr[n].inode = json_is_integer(jinode) ? (uint64_t)json_integer_value(jinode) : 0;
        if (json_is_string(jpath)) {
            strncpy(arr[n].path, json_string_value(jpath), sizeof(arr[n].path) - 1);
            arr[n].path[sizeof(arr[n].path) - 1] = '\0';
        } else {
            arr[n].path[0] = '\0';
        }
        n++;
    }

    json_decref(root);
    return n;
}

static double read_latency_ratio(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[2048];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    char *p = strstr(buf, "\"latency_ratio\"");
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    return strtod(p + 1, NULL);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  --queue PATH             demote queue input (default /tmp/pagecache_demote_queue.json)\n"
        "  --cgroup PATH            LC cgroup (required)\n"
        "  --target-node N          demote target = CXL node (default -1 = auto-detect)\n"
        "  --source-node N          host (LC DRAM) node for numa_stat logging (default -1 = auto-detect)\n"
        "  --drip-mb M              max MB demoted per cycle (default 32, 0 = unlimited)\n"
        "  --lat-json PATH          latency_ratio stats JSON (default /tmp/probe_stats.json)\n"
        "  --k-gate K               skip the cycle while latency_ratio >= K (default 1.1)\n"
        "  --poll-interval SEC      polling interval (default 1.0)\n"
        "  --verbose                log cycles that demoted nothing\n"
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

struct inode_set { uint64_t *slots; size_t cap; size_t count; };
static void iset_add(struct inode_set *s, uint64_t ino);
static void iset_init(struct inode_set *s, size_t cap0) {
    s->cap = cap0; s->count = 0; s->slots = calloc(s->cap, sizeof(uint64_t));
}
static bool iset_contains(const struct inode_set *s, uint64_t ino) {
    if (!s->slots || ino == 0) return false;
    size_t mask = s->cap - 1, i = ino & mask;
    while (s->slots[i]) { if (s->slots[i] == ino) return true; i = (i + 1) & mask; }
    return false;
}
static void iset_grow(struct inode_set *s) {
    size_t oldcap = s->cap; uint64_t *old = s->slots;
    uint64_t *ns = calloc(oldcap * 2, sizeof(uint64_t));
    if (!ns) return;
    s->slots = ns; s->cap = oldcap * 2; s->count = 0;
    for (size_t k = 0; k < oldcap; k++) if (old[k]) iset_add(s, old[k]);
    free(old);
}
static void iset_add(struct inode_set *s, uint64_t ino) {
    if (ino == 0 || !s->slots) return;
    if ((s->count + 1) * 10 >= s->cap * 7) iset_grow(s);
    size_t mask = s->cap - 1, i = ino & mask;
    while (s->slots[i]) { if (s->slots[i] == ino) return; i = (i + 1) & mask; }
    s->slots[i] = ino; s->count++;
}
static void iset_reset(struct inode_set *s) {
    if (s->slots) memset(s->slots, 0, s->cap * sizeof(uint64_t));
    s->count = 0;
}

#define DEMOTED_FILE "/tmp/pagecache_demoted_inodes"
static void write_demoted_file(const struct inode_set *s) {
    if (!s->slots) return;
    FILE *f = fopen(DEMOTED_FILE ".tmp", "wb");
    if (!f) return;
    uint64_t cnt = s->count;
    fwrite(&cnt, sizeof(cnt), 1, f);
    for (size_t i = 0; i < s->cap; i++)
        if (s->slots[i]) fwrite(&s->slots[i], sizeof(uint64_t), 1, f);
    fclose(f);
    rename(DEMOTED_FILE ".tmp", DEMOTED_FILE);
}

#define MAX_CANDIDATES 262144

int main(int argc, char **argv)
{
    struct config cfg;
    config_defaults(&cfg);

    static struct option longopts[] = {
        {"queue",               required_argument, 0, 'q'},
        {"cgroup",              required_argument, 0, 'c'},
        {"target-node",        required_argument, 0, 't'},
        {"source-node",        required_argument, 0, 's'},
        {"drip-mb",             required_argument, 0, 'D'},
        {"lat-json",            required_argument, 0, 'b'},
        {"k-gate",              required_argument, 0, 'B'},
        {"poll-interval",      required_argument, 0, 'i'},
        {"verbose",             no_argument,       0, 'v'},
        {"log-level",           required_argument, 0, 'l'},
        {"help",                no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "q:c:t:s:i:vl:hD:b:B:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'q': cfg.queue = optarg; break;
        case 'c': cfg.cgroup = optarg; break;
        case 't': cfg.target_node = atoi(optarg); break;
        case 's': cfg.source_node = atoi(optarg); break;
        case 'D': cfg.drip_mb = atof(optarg); break;
        case 'b': cfg.lat_json = optarg; break;
        case 'B': cfg.lat_k_gate = atof(optarg); break;
        case 'i': cfg.poll_interval_sec = atof(optarg); break;
        case 'v': cfg.verbose = true; break;
        case 'l': g_log_level = parse_log_level(optarg); break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    detect_nodes(&cfg.source_node, &cfg.target_node);
    if (cfg.source_node < 0 || cfg.target_node < 0) {
        LOG_E("NUMA node auto-detection failed (source/host=%d target/cxl=%d) - pass --source-node/--target-node",
              cfg.source_node, cfg.target_node);
        return 1;
    }

    if (!cfg.cgroup) {
        LOG_E("--cgroup required");
        usage(argv[0]);
        return 1;
    }
    if (access(cfg.cgroup, F_OK) != 0) {
        LOG_E("cgroup not found: %s", cfg.cgroup);
        return 1;
    }

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    LOG_I("started - cgroup=%s host=node%d cxl=node%d drip=%.0fMB/cycle k_gate=%.2f(lat) poll=%.1fs",
          cfg.cgroup, cfg.source_node, cfg.target_node, cfg.drip_mb, cfg.lat_k_gate, cfg.poll_interval_sec);
    LOG_I("queue=%s", cfg.queue);

    struct candidate *cands = calloc(MAX_CANDIDATES, sizeof(struct candidate));
    if (!cands) {
        LOG_E("candidate buffer alloc failed");
        return 1;
    }
    struct inode_set done;
    iset_init(&done, 1u << 16);
    if (!done.slots) { LOG_E("done-set alloc failed"); return 1; }

    struct candidate *delta = calloc(MAX_CANDIDATES, sizeof(struct candidate));
    struct inode_set pending_set;
    iset_init(&pending_set, 1u << 16);
    int n_pending = 0;
    if (!delta || !pending_set.slots) { LOG_E("pending buffer alloc failed"); return 1; }

    int      cycle = 0;
    double   wall_start = now_sec();

    while (!g_stop) {
        cycle++;
        double ts = now_sec();

        double host_mb = BYTES_TO_MB(read_numa_file_bytes(cfg.cgroup, cfg.source_node));
        double cxl_mb  = BYTES_TO_MB(read_numa_file_bytes(cfg.cgroup, cfg.target_node));

        double lat_ratio = read_latency_ratio(cfg.lat_json);
        if (lat_ratio < 0) {
            if (cfg.verbose) LOG_I("cycle=%d skip - latency NA (%s missing/stale)", cycle, cfg.lat_json);
            goto sleep_cycle;
        }
        if (lat_ratio >= cfg.lat_k_gate) {
            if (cfg.verbose) LOG_I("cycle=%d skip - latency_ratio=%.2f >= %.2f (LC latency degraded)",
                                   cycle, lat_ratio, cfg.lat_k_gate);
            goto sleep_cycle;
        }

        int ndelta = parse_queue(cfg.queue, delta, MAX_CANDIDATES);
        for (int d = 0; d < ndelta; d++) {
            uint64_t ino = delta[d].inode;
            if (ino == 0 || iset_contains(&done, ino) || iset_contains(&pending_set, ino))
                continue;
            if (n_pending >= MAX_CANDIDATES) break;
            cands[n_pending++] = delta[d];
            iset_add(&pending_set, ino);
        }
        if (n_pending <= 0)
            goto sleep_cycle;

        double moved_mb_cycle = 0.0;
        for (int i = 0; i < n_pending; i++) {
            if (g_stop)
                break;
            if (cfg.drip_mb > 0 && moved_mb_cycle >= cfg.drip_mb)
                break;
            if (cands[i].path[0] == '\0') {
                LOG_D("  skip inode=%lu (no path)", cands[i].inode);
                continue;
            }
            if (access(cands[i].path, F_OK) != 0) {
                LOG_D("  skip %s (gone)", cands[i].path);
                continue;
            }

            struct demote_result r;
            demote_file(cands[i].path, cfg.target_node, &r);

            if (!r.ok) {
                LOG_W("  FAIL %s: %s", cands[i].path, r.errmsg);
                continue;
            }

            if (r.ebusy == 0 && (r.already_on_target + r.moved) >= r.total_pages)
                iset_add(&done, cands[i].inode);

            double moved_mb = r.moved * PAGE_SIZE_BYTES / (1024.0 * 1024.0);
            moved_mb_cycle += moved_mb;
            if (r.moved > 0)
                LOG_I("  OK %s: moved %lu new pages (%.1fMB), already_on_N%d=%lu/%lu | "
                      "EBUSY=%lu ENOENT=%lu | query=%.1fms move=%.1fms (file %.1fMB)",
                      cands[i].path, r.moved, moved_mb,
                      cfg.target_node, r.already_on_target, r.total_pages,
                      r.ebusy, r.enoent, r.query_ms, r.move_ms,
                      r.size_bytes / (1024.0 * 1024.0));
        }

        int w = 0;
        for (int i = 0; i < n_pending; i++)
            if (!iset_contains(&done, cands[i].inode)) cands[w++] = cands[i];
        n_pending = w;
        iset_reset(&pending_set);
        for (int i = 0; i < n_pending; i++) iset_add(&pending_set, cands[i].inode);

        if (moved_mb_cycle > 0 || cfg.verbose)
            LOG_I("cycle=%d host=%.1fMB cxl=%.1fMB | drip moved %.1fMB (lat_ratio=%.2f) | done=%zu pending=%d",
                  cycle, host_mb, cxl_mb, moved_mb_cycle, lat_ratio, done.count, n_pending);
        if (moved_mb_cycle > 0)
            write_demoted_file(&done);

    sleep_cycle:
        {
            double elapsed = now_sec() - ts;
            double sleep_s = cfg.poll_interval_sec - elapsed;
            if (sleep_s > 0) {
                struct timespec req = {
                    .tv_sec  = (time_t)sleep_s,
                    .tv_nsec = (long)((sleep_s - (time_t)sleep_s) * 1e9),
                };
                nanosleep(&req, NULL);
            }
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
              "= %.2f%% of 1 core (%d cycles)",
              utime, stime, cpu, wall,
              wall > 0 ? 100.0 * cpu / wall : 0.0, cycle);
    }

    LOG_I("stopping (cycle=%d)", cycle);
    free(cands);
    return 0;
}
