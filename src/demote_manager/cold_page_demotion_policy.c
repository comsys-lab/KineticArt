#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <dirent.h>
#include <sched.h>

#define KD "/sys/kernel/mm/damon/admin/kdamonds"
#define WHOLE "1099511627776"
#define CAP_JSON "/tmp/capacity_stats.json"
#define DEMOTE_CYCLE_S 180
#define BURST_S 8
#define MAX_LC 16

static char g_dram_start[32], g_dram_end[32];

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s){ (void)s; g_stop = 1; }
static double now_sec(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec + t.tv_nsec/1e9; }

struct config {
    int    cxl_node;
    int    age_init;
    const char *pin_cpus;
    const char *cgroups_cli;
    double exhaust_mb;
    double tail_ratio;
};
static void defaults(struct config *c){
    c->cxl_node = -1;
    c->exhaust_mb = 847;
    c->tail_ratio = 0.30;
    c->age_init = 30;
    c->pin_cpus = NULL;
    c->cgroups_cli = NULL;
}

static int wr(const char *path, const char *val){
    int fd = open(path, O_WRONLY); if (fd < 0) return -1;
    ssize_t n = write(fd, val, strlen(val)); close(fd); return n < 0 ? -1 : 0;
}
static int wrp(const char *val, const char *fmt, ...){
    char path[600]; va_list a; va_start(a, fmt); vsnprintf(path, sizeof(path), fmt, a); va_end(a);
    return wr(path, val);
}
static long rd_long(const char *fmt, ...){
    char path[600]; va_list a; va_start(a, fmt); vsnprintf(path, sizeof(path), fmt, a); va_end(a);
    FILE *f = fopen(path, "r"); if (!f) return -1; long v = -1; if (fscanf(f, "%ld", &v) != 1) v = -1; fclose(f); return v;
}

static int node_cpulist_empty(int node){
    char p[256], b[64]; snprintf(p, sizeof(p), "/sys/devices/system/node/node%d/cpulist", node);
    FILE *f = fopen(p, "r"); if (!f) return -1; char *r = fgets(b, sizeof(b), f); fclose(f);
    if (!r) return 1;
    return (b[0] == '\n' || b[0] == '\0') ? 1 : 0;
}

static int detect_cxl_node(void){
    DIR *d = opendir("/sys/devices/system/node"); if (!d) return -1; struct dirent *e; int best = -1;
    while ((e = readdir(d))) { int n; if (sscanf(e->d_name, "node%d", &n) != 1) continue;
        if (node_cpulist_empty(n) == 1 && (best < 0 || n < best)) best = n; }
    closedir(d); return best;
}

static int dram_range(unsigned long long *start, unsigned long long *end){
    FILE *f = fopen("/sys/devices/system/memory/block_size_bytes", "r"); if (!f) return -1;
    unsigned long long blk = 0; if (fscanf(f, "%llx", &blk) != 1) blk = 0; fclose(f); if (!blk) return -1;
    long lo = -1, hi = -1;
    DIR *d = opendir("/sys/devices/system/node"); if (!d) return -1; struct dirent *e;
    while ((e = readdir(d))) { int n; if (sscanf(e->d_name, "node%d", &n) != 1) continue;
        if (node_cpulist_empty(n) != 0) continue;
        char p[300]; snprintf(p, sizeof(p), "/sys/devices/system/node/%s", e->d_name);
        DIR *m = opendir(p); if (!m) continue; struct dirent *b;
        while ((b = readdir(m))) { long i; if (sscanf(b->d_name, "memory%ld", &i) != 1) continue;
            if (lo < 0 || i < lo) lo = i;
            if (i > hi) hi = i; }
        closedir(m); }
    closedir(d);
    if (lo < 0) return -1;
    *start = (unsigned long long)lo * blk; *end = (unsigned long long)(hi + 1) * blk; return 0;
}

static double read_headroom(const char *path){
    FILE *f = fopen(path, "r"); if (!f) return -1; char buf[8192]; size_t n = fread(buf,1,sizeof(buf)-1,f); fclose(f);
    buf[n] = 0; char *p = strstr(buf, "\"host_buffer_mb\""); if (!p) return -1; p = strchr(p, ':'); return p ? atof(p+1) : -1;
}

static int discover(char cg[][512], int max){
    DIR *d = opendir("/proc"); if (!d) return 0; struct dirent *e; int n = 0;
    while ((e = readdir(d)) && n < max) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char p[300]; snprintf(p, sizeof(p), "/proc/%s/comm", e->d_name);
        FILE *f = fopen(p, "r"); if (!f) continue; char comm[64] = ""; if (!fgets(comm, sizeof(comm), f)) { fclose(f); continue; } fclose(f);
        comm[strcspn(comm, "\n")] = 0; if (strcmp(comm, "redis-server") != 0) continue;
        snprintf(p, sizeof(p), "/proc/%s/cgroup", e->d_name);
        f = fopen(p, "r"); if (!f) continue; char line[600];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "0::", 3) == 0) { char *g = line + 3; g[strcspn(g, "\n")] = 0;
                int dup = 0; for (int i = 0; i < n; i++) if (strcmp(cg[i], g) == 0) { dup = 1; break; }
                if (!dup) { strncpy(cg[n], g, 511); cg[n][511] = 0; n++; } break; }
        }
        fclose(f);
    }
    closedir(d); return n;
}
static int from_cli(const char *s, char cg[][512], int max){
    int n = 0; char buf[4096]; strncpy(buf, s, sizeof(buf)-1); buf[sizeof(buf)-1]=0;
    char *t = strtok(buf, ","); while (t && n < max) { strncpy(cg[n], t, 511); cg[n][511]=0; n++; t = strtok(NULL, ","); } return n;
}
static void parse_cpus(const char *s, cpu_set_t *set){
    CPU_ZERO(set); char b[256]; strncpy(b, s, sizeof(b)-1); b[sizeof(b)-1]=0;
    char *t = strtok(b, ","); while (t) { int a, z; if (sscanf(t, "%d-%d", &a, &z) == 2) { for (int i=a;i<=z;i++) CPU_SET(i,set); }
        else if (sscanf(t, "%d", &a) == 1) CPU_SET(a, set);
        t = strtok(NULL, ","); }
}

#define SP "%s/%d/contexts/0/schemes/0"

static int setup(struct config *c, char cg[][512], int n){
    char v[64];

    for (int a = 0; a < 6; a++) {
        long cur = rd_long(KD"/nr_kdamonds");
        if (cur <= 0) break;
        for (int j = 0; j < cur; j++) wrp("off", "%s/%d/state", KD, j);
        usleep(2000000);
        wr(KD"/nr_kdamonds", "0");
        usleep(500000);
    }
    snprintf(v, sizeof(v), "%d", n);
    if (wr(KD"/nr_kdamonds", v) < 0) { perror("nr_kdamonds"); return -1; } usleep(300000);
    for (int j = 0; j < n; j++) {
        wrp("1", "%s/%d/contexts/nr_contexts", KD, j);
        wrp("paddr", "%s/%d/contexts/0/operations", KD, j);
        wrp("100000",  "%s/%d/contexts/0/monitoring_attrs/intervals/sample_us", KD, j);
        wrp("2000000", "%s/%d/contexts/0/monitoring_attrs/intervals/aggr_us", KD, j);
        wrp("20000000","%s/%d/contexts/0/monitoring_attrs/intervals/update_us", KD, j);
        wrp("5000",  "%s/%d/contexts/0/monitoring_attrs/nr_regions/min", KD, j);
        wrp("20000", "%s/%d/contexts/0/monitoring_attrs/nr_regions/max", KD, j);
        wrp("1", "%s/%d/contexts/0/targets/nr_targets", KD, j);
        wrp("1", "%s/%d/contexts/0/targets/0/regions/nr_regions", KD, j);
        wrp(g_dram_start, "%s/%d/contexts/0/targets/0/regions/0/start", KD, j);
        wrp(g_dram_end,   "%s/%d/contexts/0/targets/0/regions/0/end", KD, j);
        wrp("1", "%s/%d/contexts/0/schemes/nr_schemes", KD, j);
        wrp("0", SP"/access_pattern/sz/min", KD, j); wrp(WHOLE, SP"/access_pattern/sz/max", KD, j);
        wrp("0", SP"/access_pattern/nr_accesses/min", KD, j); wrp("0", SP"/access_pattern/nr_accesses/max", KD, j);
        snprintf(v, sizeof(v), "%d", c->age_init); wrp(v, SP"/access_pattern/age/min", KD, j);
        wrp("4294967295", SP"/access_pattern/age/max", KD, j);
        wrp("migrate_cold", SP"/action", KD, j);
        snprintf(v, sizeof(v), "%d", c->cxl_node); wrp(v, SP"/target_nid", KD, j);
        wrp("2000000", SP"/apply_interval_us", KD, j);
        wrp("0", SP"/quotas/ms", KD, j);
        wrp("0", SP"/quotas/bytes", KD, j);
        wrp("2", SP"/filters/nr_filters", KD, j);
        wrp("memcg", SP"/filters/0/type", KD, j);
        wrp(cg[j], SP"/filters/0/memcg_path", KD, j);
        wrp("N", SP"/filters/0/matching", KD, j);
        wrp("young", SP"/filters/1/type", KD, j);
        wrp("Y",     SP"/filters/1/matching", KD, j);
    }

    for (int j = 0; j < n; j++) wrp("on", "%s/%d/state", KD, j);
    usleep(500000);

    if (!c->pin_cpus) return 0;
    cpu_set_t set; parse_cpus(c->pin_cpus, &set);
    for (int j = 0; j < n; j++) {
        long pid = rd_long("%s/%d/pid", KD, j);
        if (pid <= 0) { fprintf(stderr, "[anon] WARN kdamond%d has no pid - cannot pin\n", j); continue; }
        if (sched_setaffinity((pid_t)pid, sizeof(set), &set) < 0)
            fprintf(stderr, "[anon] WARN kdamond%d (pid %ld) pin failed: %s\n", j, pid, strerror(errno));
    }
    return 0;
}
static int g_nctx = 0;
static void cleanup(void){
    for (int j = 0; j < g_nctx; j++) wrp("off", "%s/%d/state", KD, j);
    for (int t = 0; t < 100; t++) {
        int alive = 0;
        for (int j = 0; j < g_nctx; j++) if (rd_long("%s/%d/pid", KD, j) > 0) alive = 1;
        if (!alive) break;
        usleep(100000);
    }
    for (int t = 0; t < 50 && wr(KD"/nr_kdamonds", "0") != 0; t++) usleep(200000);
}

int main(int argc, char **argv){
    struct config cfg; defaults(&cfg);
    static struct option lo[] = {
        {"cxl-node",required_argument,0,'x'},
        {"age-init",required_argument,0,'a'},
        {"cgroups",required_argument,0,'g'},
        {"exhaust-mb",required_argument,0,'X'},{"tail-ratio",required_argument,0,'T'},{"help",no_argument,0,'h'},
        {"pin-cpus",required_argument,0,'P'},{0,0,0,0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "x:a:g:X:T:P:h", lo, NULL)) != -1) {
        switch (opt) {
        case 'x': cfg.cxl_node=atoi(optarg); break;
        case 'a': cfg.age_init=atoi(optarg); break;
        case 'g': cfg.cgroups_cli=optarg; break;
        case 'X': cfg.exhaust_mb=atof(optarg); break;
        case 'T': cfg.tail_ratio=atof(optarg); break;
        case 'P': cfg.pin_cpus=optarg; break;
        default: fprintf(stderr,
            "Usage: %s [--cxl-node N] [--age-init 30] [--exhaust-mb 847] [--tail-ratio 0.30] [--cgroups a,b] [--pin-cpus LIST]\n"
            "  one kdamond per LC cgroup (migrate_cold, memcg + young filters), age threshold fixed at --age-init aggregation intervals.\n"
            "  --cgroups omitted: LC cgroups discovered from redis-server processes. --pin-cpus: pin kdamond threads off LC/BE cores.\n"
            "  stops when a cycle moves less than --exhaust-mb or less than --tail-ratio of the largest cycle. root required.\n", argv[0]);
            return opt=='h'?0:1;
        }
    }
    if (getuid()!=0){ fprintf(stderr,"root required\n"); return 1; }
    signal(SIGINT,on_sig); signal(SIGTERM,on_sig);

    if (cfg.cxl_node < 0) cfg.cxl_node = detect_cxl_node();
    if (cfg.cxl_node < 0){ fprintf(stderr,"[anon] no CXL node (node without CPUs) found - pass --cxl-node\n"); return 1; }
    { unsigned long long s, e;
      if (dram_range(&s, &e) != 0){ fprintf(stderr,"[anon] failed to compute DRAM physical range (/sys/devices/system/memory)\n"); return 1; }
      snprintf(g_dram_start, sizeof(g_dram_start), "%llu", s); snprintf(g_dram_end, sizeof(g_dram_end), "%llu", e);
      fprintf(stderr, "[anon] cxl=node%d DRAM physical range [%llu, %llu) = %.1f GiB\n", cfg.cxl_node, s, e, (e - s) / 1073741824.0); }

    static char cg[MAX_LC][512];
    int n = cfg.cgroups_cli ? from_cli(cfg.cgroups_cli, cg, MAX_LC) : discover(cg, MAX_LC);
    if (n <= 0){ fprintf(stderr,"[anon] no LC cgroup found (no redis-server? pass --cgroups)\n"); return 1; }
    fprintf(stderr, "[anon] %d LC cgroups -> %d kdamonds, pin=%s\n",
            n, n, cfg.pin_cpus ? cfg.pin_cpus : "none");
    for (int j=0;j<n;j++) fprintf(stderr, "[anon]   [%d] %s\n", j, cg[j]);

    g_nctx = n;
    if (setup(&cfg, cg, n) != 0){ cleanup(); return 1; }
    atexit(cleanup);
    fprintf(stderr, "[anon] kdamonds started. cycle=%ds (per-shard burst %ds, sequential), age threshold=%ds (fixed), stop when a cycle moves <%.0fMB or <%.2f x the largest cycle\n",
            DEMOTE_CYCLE_S, BURST_S, cfg.age_init*2, cfg.exhaust_mb, cfg.tail_ratio);

    int age = cfg.age_init; double t0 = now_sec(); char v[64];
    long prev_applied = 0, dapplied; int seen_progress = 0;
    long peak_mb = 0;

    while (!g_stop) {
        snprintf(v, sizeof(v), "%d", age);
        for (int j=0;j<n;j++){ wrp("stat", SP"/action", KD, j); wrp(v, SP"/access_pattern/age/min", KD, j); wrp("commit","%s/%d/state",KD,j); }

        { double s=0; int j=0;
          while (s < DEMOTE_CYCLE_S && !g_stop){
            wrp("migrate_cold", SP"/action", KD, j); wrp("commit","%s/%d/state",KD,j);
            { double bs=0; while (bs < BURST_S && !g_stop){ usleep(200000); bs+=0.2; } }
            wrp("stat", SP"/action", KD, j); wrp("commit","%s/%d/state",KD,j);
            fprintf(stderr, "[anon] burst shard%d done (t=%.0fs)\n", j, s+BURST_S);
            s += BURST_S + 0.4; j = (j+1) % n; usleep(400000); } }
        if (g_stop) break;
        long applied = 0;
        for (int j=0;j<n;j++){ wrp("update_schemes_stats","%s/%d/state",KD,j); }
        usleep(100000);
        for (int j=0;j<n;j++){ long a = rd_long(SP"/stats/sz_applied", KD, j); if (a>0) applied += a; }
        dapplied = applied - prev_applied; prev_applied = applied;
        long dmb = dapplied/1024/1024, pk_before = peak_mb;
        if ((double)dmb >= cfg.exhaust_mb) seen_progress = 1;
        if (dmb > peak_mb) peak_mb = dmb;

        double ts = now_sec() - t0;
        fprintf(stderr, "[anon] t=%.0f age=%ds demote=%ldMB(+%ld) slack=%.0fMB\n",
                ts, age*2, applied/1024/1024, dmb, read_headroom(CAP_JSON));

        if (cfg.exhaust_mb > 0 && seen_progress && (double)dmb < cfg.exhaust_mb) {
            fprintf(stderr, "[anon] cold exhausted: this cycle +%ldMB < %.0fMB -> stop\n",
                    dmb, cfg.exhaust_mb);
            break; }

        if (cfg.tail_ratio > 0 && seen_progress && pk_before > 0 && (double)dmb < cfg.tail_ratio * (double)pk_before) {
            fprintf(stderr, "[anon] tail detected: this cycle +%ldMB < largest cycle %ldMB x %.2f -> stop\n",
                    dmb, pk_before, cfg.tail_ratio);
            break; }
    }
    fprintf(stderr, "[anon] stopped\n"); return 0;
}
