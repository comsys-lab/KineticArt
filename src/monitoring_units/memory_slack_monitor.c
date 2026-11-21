#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/syscall.h>

#define MAX_CGROUPS 32
#define INTERVAL_SEC 0.3
#define R_SAMPLE_SEC 1.0
#define CALIB_WINDOW_SEC 3600.0
#define REACTION_WINDOW_SEC 5.0
#define R_PERCENTILE 0.99
#define BE_POD_LIST "/tmp/mtier_be_pods.list"
#define BE_SCHED_DIR "/tmp/mtier_be_sched"
#define OUT_JSON "/tmp/capacity_stats.json"

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s){ (void)s; g_stop = 1; }

static double now_sec(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec/1e9;
}

#define R_HIST_MAX 7200
struct r_calib {
    double samples[R_HIST_MAX];
    int    cap, head, count;
    double last_sample_t;
    double cached_R;
};
static struct r_calib g_rc = { .last_sample_t = -1.0 };

static int cmp_double(const void *a, const void *b){
    double x = *(const double*)a, y = *(const double*)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}
static void r_calib_push(struct r_calib *rc, double v){
    rc->samples[rc->head] = v;
    rc->head = (rc->head + 1) % rc->cap;
    if (rc->count < rc->cap) rc->count++;
}

static double r_calib_compute(struct r_calib *rc, int W, double pct){
    int n = rc->count;
    if (n < W + 2) return -1;
    static double ord[R_HIST_MAX], rise[R_HIST_MAX];
    int start = (rc->head - n + rc->cap) % rc->cap;
    for (int j = 0; j < n; j++) ord[j] = rc->samples[(start + j) % rc->cap];
    int m = 0;
    for (int j = W; j < n; j++) {
        double base = ord[j];
        for (int k = j - W; k < j; k++) if (ord[k] < base) base = ord[k];
        double r = ord[j] - base;
        rise[m++] = (r > 0) ? r : 0;
    }
    qsort(rise, m, sizeof(double), cmp_double);
    int idx = (int)(pct * (m - 1) + 0.5);
    if (idx < 0) idx = 0;
    if (idx >= m) idx = m - 1;
    return rise[idx];
}

struct config {
    int         host_node;
    int         cxl_node;
    const char *cgroups[MAX_CGROUPS];
    int         n_cgroups;
    double      reserve_mb;
    double      host_capacity_mb;
    double      be_fill_ratio;
    double      be_reserve_grace_sec;
};

static void defaults(struct config *c){
    c->host_node    = -1;
    c->cxl_node     = -1;
    c->n_cgroups    = 0;
    c->reserve_mb   = 1024.0;
    c->host_capacity_mb = -1.0;
    c->be_fill_ratio = 0.70;
    c->be_reserve_grace_sec = 120.0;
}

static int read_node_meminfo(int node, double *total_mb, double *free_mb)
{
    char path[256], line[256];
    snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/meminfo", node);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    *total_mb = -1; *free_mb = -1;
    while (fgets(line, sizeof(line), f)) {
        char *p;
        unsigned long kb;
        if ((p = strstr(line, "MemTotal:"))) {
            if (sscanf(p, "MemTotal: %lu", &kb) == 1) *total_mb = kb/1024.0;
        } else if ((p = strstr(line, "MemFree:"))) {
            if (sscanf(p, "MemFree: %lu", &kb) == 1) *free_mb = kb/1024.0;
        }
    }
    fclose(f);
    return (*total_mb >= 0 && *free_mb >= 0) ? 0 : -1;
}

static int node_cpulist_empty(int node)
{
    char path[256], buf[64];
    snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/cpulist", node);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char *r = fgets(buf, sizeof(buf), f);
    fclose(f);
    if (!r) return 1;
    return (buf[0] == '\n' || buf[0] == '\0') ? 1 : 0;
}

static int node_distance_to(int from, int to)
{
    char path[256], line[1024];
    snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/distance", from);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char *r = fgets(line, sizeof(line), f);
    fclose(f);
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

static void detect_nodes(int *host, int *cxl)
{
    if (*cxl < 0) {
        DIR *d = opendir("/sys/devices/system/node");
        if (d) {
            struct dirent *e; int best = -1;
            while ((e = readdir(d))) {
                int n; double tot, fr;
                if (sscanf(e->d_name, "node%d", &n) != 1) continue;
                if (read_node_meminfo(n, &tot, &fr) != 0 || tot <= 0) continue;
                if (node_cpulist_empty(n) == 1 && (best < 0 || n < best)) best = n;
            }
            closedir(d);
            *cxl = best;
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
            closedir(d);
            *host = best;
        }
        if (*host < 0) {
            unsigned cpu = 0, node = 0;
            if (syscall(SYS_getcpu, &cpu, &node, NULL) == 0) *host = (int)node;
        }
    }
}

static double read_cgroup_node_mb(const char *cgroup, int node, double *mapped_mb)
{
    char path[512], line[4096], key[16];
    snprintf(path, sizeof(path), "%s/memory.numa_stat", cgroup);
    FILE *f = fopen(path, "r");
    if (!f) { if (mapped_mb) *mapped_mb = -1; return -1; }
    snprintf(key, sizeof(key), "N%d=", node);
    unsigned long long total = 0, mapped = 0;
    while (fgets(line, sizeof(line), f)) {
        int is_anon = (strncmp(line, "anon ", 5) == 0);
        int is_file = (strncmp(line, "file ", 5) == 0);
        int is_fmap = (strncmp(line, "file_mapped ", 12) == 0);
        if (!is_anon && !is_file && !is_fmap) continue;
        char *p = strstr(line, key);
        if (!p) continue;
        unsigned long long v = strtoull(p + strlen(key), NULL, 10);
        if (is_anon)      { total += v; mapped += v; }
        else if (is_file) { total += v; }
        else              { mapped += v; }
    }
    fclose(f);
    if (mapped_mb) *mapped_mb = mapped / (1024.0*1024.0);
    return total / (1024.0*1024.0);
}

static double read_cgroup_psi_some(const char *cgroup){
    char p[600]; snprintf(p, sizeof(p), "%s/memory.pressure", cgroup);
    FILE *f = fopen(p, "r"); if (!f) return -1;
    char line[256]; double v = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "some ", 5) == 0) { char *q = strstr(line, "avg10="); if (q) v = strtod(q+6, NULL); break; }
    }
    fclose(f); return v;
}

static double sum_be_declared_reserve(const char *dir, int host_node, int cxl_node,
                                      double fill_ratio, double grace_sec)
{
    DIR *d = opendir(dir);
    if (!d) return 0.0;
    struct dirent *e;
    char p[512], mp[600], buf[64];
    double extra = 0.0;
    char cxlstr[16]; snprintf(cxlstr, sizeof(cxlstr), "%d", cxl_node);
    while ((e = readdir(d))) {
        if (strncmp(e->d_name, "be_sched_", 9) != 0) continue;
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        snprintf(mp, sizeof(mp), "%s/cpuset.mems", p);
        FILE *mf = fopen(mp, "r");
        if (mf) {
            if (fgets(buf, sizeof(buf), mf)) {
                buf[strcspn(buf, "\n")] = 0;
                if (strcmp(buf, cxlstr) == 0) { fclose(mf); continue; }
            }
            fclose(mf);
        }
        snprintf(mp, sizeof(mp), "%s/memory.max", p);
        FILE *lf = fopen(mp, "r");
        if (!lf) continue;
        double declared = -1;
        if (fgets(buf, sizeof(buf), lf) && buf[0] >= '0' && buf[0] <= '9')
            declared = strtod(buf, NULL) / (1024.0*1024.0);
        fclose(lf);
        if (declared <= 0) continue;
        double actual = read_cgroup_node_mb(p, host_node, NULL);
        if (actual < 0) actual = 0;
        if (declared > actual) {
            int settled = 0;
            if (fill_ratio > 0 && actual >= declared * fill_ratio) settled = 1;
            if (!settled && grace_sec > 0) {
                struct stat st;
                if (lstat(p, &st) == 0 &&
                    (double)(time(NULL) - st.st_mtime) > grace_sec) settled = 1;
            }
            if (!settled) extra += (declared - actual);
        }
    }
    closedir(d);
    return extra;
}

static double sum_be_pod_list(const char *path, int host_node)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0.0;
    char seen[64][80]; int nseen = 0;
    char line[128];
    double be_host = 0.0;
    while (fgets(line, sizeof(line), f)) {
        char uid[80]; int j = 0;
        for (int i = 0; line[i] && line[i] != '\n' && j < 78; i++) {
            if (line[i] == ' ' || line[i] == '\t' || line[i] == '\r') continue;
            uid[j++] = (line[i] == '-') ? '_' : line[i];
        }
        uid[j] = '\0';
        if (j == 0) continue;
        int dup = 0;
        for (int k = 0; k < nseen; k++) if (strcmp(seen[k], uid) == 0) { dup = 1; break; }
        if (dup) continue;
        if (nseen < 64) snprintf(seen[nseen++], 80, "%s", uid);
        char cand[3][512];
        snprintf(cand[0], 512, "/sys/fs/cgroup/kubepods.slice/kubepods-pod%s.slice", uid);
        snprintf(cand[1], 512, "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod%s.slice", uid);
        snprintf(cand[2], 512, "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod%s.slice", uid);
        for (int c = 0; c < 3; c++) {
            double h = read_cgroup_node_mb(cand[c], host_node, NULL);
            if (h < 0) continue;
            be_host += h;
            break;
        }
    }
    fclose(f);
    return be_host;
}

static int write_file_atomic(const char *path, const char *content, size_t len)
{
    char tmp[600];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int fd = open(tmp, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, content + off, len - off);
        if (n <= 0) { close(fd); unlink(tmp); return -1; }
        off += n;
    }
    close(fd);
    return rename(tmp, path);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --cgroup PATH [--cgroup PATH ...] [options]\n"
        "  slack(host_buffer) = host_capacity - (LC resident + placed BE) - (reserve + R_spike)\n"
        "  --cgroup PATH             LC cgroup to monitor (repeatable, summed)\n"
        "  --host-capacity-mb M      host budget for LC+BE (default -1 = host MemTotal)\n"
        "  --reserve-mb M            reserve floor; actual reserve = M + R_spike (default 1024)\n"
        "  --be-fill-ratio F         release a BE's declared reservation once usage/declared >= F (default 0.70)\n"
        "  --be-reserve-grace-sec S  release a BE's declared reservation S seconds after placement (default 120)\n"
        "  host/CXL node auto-detected (node without CPUs = CXL); tick %.1fs; R_spike: %.0fs samples over %.0fs, reaction %.0fs, p%.0f;\n"
        "  BE pods from %s, placed BE cgroups from %s, output %s\n",
        prog, INTERVAL_SEC, R_SAMPLE_SEC, CALIB_WINDOW_SEC, REACTION_WINDOW_SEC, R_PERCENTILE*100, BE_POD_LIST, BE_SCHED_DIR, OUT_JSON);
}

int main(int argc, char **argv)
{
    struct config cfg; defaults(&cfg);
    static struct option lo[] = {
        {"cgroup",     required_argument, 0, 'c'},
        {"host-capacity-mb", required_argument, 0, 'C'},
        {"reserve-mb", required_argument, 0, 'r'},
        {"be-fill-ratio",        required_argument, 0, 1001},
        {"be-reserve-grace-sec", required_argument, 0, 1002},
        {"help",       no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "c:C:r:h", lo, NULL)) != -1) {
        switch (opt) {
        case 'c': if (cfg.n_cgroups < MAX_CGROUPS) cfg.cgroups[cfg.n_cgroups++] = optarg; break;
        case 'C': cfg.host_capacity_mb = atof(optarg); break;
        case 'r': cfg.reserve_mb   = atof(optarg); break;
        case 1001: cfg.be_fill_ratio        = atof(optarg); break;
        case 1002: cfg.be_reserve_grace_sec = atof(optarg); break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }
    signal(SIGTERM, on_sig); signal(SIGINT, on_sig);

    if (cfg.n_cgroups == 0) { fprintf(stderr, "[cap] FATAL: --cgroup required\n"); usage(argv[0]); return 1; }

    detect_nodes(&cfg.host_node, &cfg.cxl_node);
    if (cfg.host_node < 0 || cfg.cxl_node < 0) {
        fprintf(stderr, "[cap] FATAL: NUMA node auto-detection failed (host=%d cxl=%d)\n", cfg.host_node, cfg.cxl_node);
        return 1;
    }

    double t_mb, f_mb;
    if (read_node_meminfo(cfg.host_node, &t_mb, &f_mb) != 0) {
        fprintf(stderr, "[cap] FATAL: node%d meminfo read failed\n", cfg.host_node); return 1;
    }
    if (read_node_meminfo(cfg.cxl_node, &t_mb, &f_mb) != 0) {
        fprintf(stderr, "[cap] FATAL: node%d meminfo read failed\n", cfg.cxl_node); return 1;
    }
    int have_cgroup = 0;
    for (int i = 0; i < cfg.n_cgroups; i++) {
        if (read_cgroup_node_mb(cfg.cgroups[i], cfg.host_node, NULL) >= 0) have_cgroup = 1;
        else fprintf(stderr, "[cap] WARN: cgroup %s unreadable, counted as 0\n", cfg.cgroups[i]);
    }
    if (!have_cgroup)
        fprintf(stderr, "[cap] WARN: no readable LC cgroup; available memory is overestimated\n");

    g_rc.cap = (int)(CALIB_WINDOW_SEC / R_SAMPLE_SEC);
    int reaction_W = (int)(REACTION_WINDOW_SEC / R_SAMPLE_SEC + 0.5);

    fprintf(stderr, "[cap] started - host=node%d cxl=node%d cgroups=%d interval=%.2fs reserve=%.0fMB host_capacity=%.0fMB(<0=auto MemTotal)\n",
            cfg.host_node, cfg.cxl_node, cfg.n_cgroups, INTERVAL_SEC, cfg.reserve_mb, cfg.host_capacity_mb);
    for (int i = 0; i < cfg.n_cgroups; i++) fprintf(stderr, "[cap]   cgroup[%d]=%s\n", i, cfg.cgroups[i]);
    if (cfg.host_capacity_mb < 0)
        fprintf(stderr, "[cap] WARN: host_capacity not given, using MemTotal; on a shared node pass --host-capacity-mb or raise reserve\n");
    fprintf(stderr, "[cap] R_spike: mapped-resident(anon+file_mapped) p%.0f, sample=%.1fs window=%.0fs reaction=%.1fs(W=%d) cap=%d\n",
            R_PERCENTILE*100, R_SAMPLE_SEC, CALIB_WINDOW_SEC, REACTION_WINDOW_SEC, reaction_W, g_rc.cap);

    int cg_dead[MAX_CGROUPS] = {0};

    while (!g_stop) {
        double ts = now_sec();
        double h_total, h_free, c_total, c_free;
        read_node_meminfo(cfg.host_node, &h_total, &h_free);
        read_node_meminfo(cfg.cxl_node,  &c_total, &c_free);
        double lc_mapped = 0, be_host = 0;
        double lc_psi = -1;
        for (int i = 0; i < cfg.n_cgroups; i++) {
            double mapped_h = -1;
            double h = read_cgroup_node_mb(cfg.cgroups[i], cfg.host_node, &mapped_h);
            if (mapped_h > 0) lc_mapped += mapped_h;
            double ps = read_cgroup_psi_some(cfg.cgroups[i]);
            if (ps > lc_psi) lc_psi = ps;
            if (h < 0) {
                if (!cg_dead[i]) { fprintf(stderr, "[cap] WARN: cgroup %s unreadable, counted as 0\n", cfg.cgroups[i]); cg_dead[i] = 1; }
            } else if (cg_dead[i]) { fprintf(stderr, "[cap] cgroup back: %s\n", cfg.cgroups[i]); cg_dead[i] = 0; }
        }

        be_host = sum_be_pod_list(BE_POD_LIST, cfg.host_node);
        double be_reserved = sum_be_declared_reserve(BE_SCHED_DIR, cfg.host_node, cfg.cxl_node,
                                                     cfg.be_fill_ratio, cfg.be_reserve_grace_sec);
        be_host += be_reserved;

        if (g_rc.last_sample_t < 0 || ts - g_rc.last_sample_t >= R_SAMPLE_SEC) {
            r_calib_push(&g_rc, lc_mapped);
            g_rc.last_sample_t = ts;
            double r = r_calib_compute(&g_rc, reaction_W, R_PERCENTILE);
            if (r >= 0) g_rc.cached_R = r;
        }
        double R_spike = g_rc.cached_R;
        double effective_reserve = cfg.reserve_mb + R_spike;

        double host_cap = (cfg.host_capacity_mb >= 0) ? cfg.host_capacity_mb : h_total;
        double lc_resident = lc_mapped + be_host;

        double host_buffer = host_cap - lc_resident - effective_reserve;
        if (host_buffer < 0) host_buffer = 0;
        double host_free_buffer = h_free - effective_reserve;
        if (host_free_buffer < 0) host_free_buffer = 0;

        char buf[1024];
        int n = snprintf(buf, sizeof(buf),
            "{\n"
            "  \"ts\": %.3f,\n"
            "  \"host_node\": %d, \"cxl_node\": %d,\n"
            "  \"host_capacity_mb\": %.1f, \"host_buffer_mb\": %.1f, \"host_free_buffer_mb\": %.1f,\n"
            "  \"cxl_free_mb\": %.1f,\n"
            "  \"lc_mapped_host_mb\": %.1f, \"lc_resident_mb\": %.1f, \"lc_psi_some\": %.2f,\n"
            "  \"R_spike_mb\": %.1f, \"effective_reserve_mb\": %.1f\n"
            "}\n",
            ts, cfg.host_node, cfg.cxl_node,
            host_cap, host_buffer, host_free_buffer,
            c_free,
            lc_mapped, lc_resident, lc_psi,
            R_spike, effective_reserve);
        write_file_atomic(OUT_JSON, buf, n);

        double elapsed = now_sec() - ts;
        double sl = INTERVAL_SEC - elapsed;
        if (sl > 0) {
            struct timespec req = { (time_t)sl, (long)((sl - (time_t)sl)*1e9) };
            nanosleep(&req, NULL);
        }
    }
    fprintf(stderr, "[cap] stopped\n");
    return 0;
}
