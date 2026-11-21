#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <limits.h>

#ifndef SYS_migrate_pages
#define SYS_migrate_pages 256
#endif

#define MAX_BE 64
#define R_LOW_PCT  0.25
#define SETTLE_TIMEOUT_SEC 15.0
#define POLL_SEC 0.5
#define STALE_SEC 5.0
#define PSI_COOLDOWN_SEC 3.0
#define PSI_ESCALATE_SEC 10.0
#define CAPACITY_JSON "/tmp/capacity_stats.json"
#define OUT_CSV "/tmp/recovery_metrics.csv"
#define KILLED_FILE "/tmp/mtier_killed.list"

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s){ (void)s; g_stop = 1; }
static double now_sec(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec + t.tv_nsec/1e9; }

struct config {
    int         host_node, cxl_node;
    const char *be_cgroup_dir;
    const char *be_cgroups[MAX_BE];
    int         n_be_cgroups;
    double      r_low_mb;
    double      r_high_mb;
    double      psi_threshold;
    int         dry_run;
};
static void defaults(struct config *c){
    c->host_node=-1; c->cxl_node=-1;
    c->be_cgroup_dir=NULL;
    c->n_be_cgroups=0;
    c->r_low_mb=3500.0;
    c->r_high_mb=5000.0;
    c->psi_threshold=20.0;
    c->dry_run=0;
}

static long node_mem_total_kb(int node){
    char p[256],l[256]; snprintf(p,sizeof(p),"/sys/devices/system/node/node%d/meminfo",node);
    FILE *f=fopen(p,"r"); if(!f) return -1; long kb=-1;
    while(fgets(l,sizeof(l),f)){ char *q=strstr(l,"MemTotal:"); if(q){ sscanf(q,"MemTotal: %ld",&kb); break; } }
    fclose(f); return kb;
}
static int node_cpulist_empty(int node){
    char p[256],b[64]; snprintf(p,sizeof(p),"/sys/devices/system/node/node%d/cpulist",node);
    FILE *f=fopen(p,"r"); if(!f) return -1; char *r=fgets(b,sizeof(b),f); fclose(f);
    if(!r) return 1;
    return (b[0]=='\n'||b[0]=='\0')?1:0;
}
static int node_distance_to(int from,int to){
    char p[256],l[1024]; snprintf(p,sizeof(p),"/sys/devices/system/node/node%d/distance",from);
    FILE *f=fopen(p,"r"); if(!f) return -1; char *r=fgets(l,sizeof(l),f); fclose(f); if(!r) return -1;
    char *q=l; int idx=0; while(*q){ char *e; long v=strtol(q,&e,10); if(e==q) break; if(idx==to) return (int)v; idx++; q=e; }
    return -1;
}
static void detect_nodes(int *host,int *cxl){
    if(*cxl<0){ DIR *d=opendir("/sys/devices/system/node"); if(d){ struct dirent *e; int best=-1;
        while((e=readdir(d))){ int n; if(sscanf(e->d_name,"node%d",&n)!=1) continue;
            if(node_mem_total_kb(n)>0 && node_cpulist_empty(n)==1 && (best<0||n<best)) best=n; }
        closedir(d); *cxl=best; } }
    if(*host<0 && *cxl>=0){ DIR *d=opendir("/sys/devices/system/node"); if(d){ struct dirent *e; int best=-1,bd=1<<30;
        while((e=readdir(d))){ int n; if(sscanf(e->d_name,"node%d",&n)!=1) continue;
            if(n==*cxl||node_cpulist_empty(n)!=0) continue;
            int dist=node_distance_to(*cxl,n);
            if(dist>=0&&dist<bd){bd=dist;best=n;} } closedir(d); *host=best; } }
}

static int json_get_double(const char *buf,const char *key,double *out){
    char pat[64]; snprintf(pat,sizeof(pat),"\"%s\"",key);
    const char *p=strstr(buf,pat); if(!p) return -1;
    p=strchr(p+strlen(pat),':'); if(!p) return -1;
    *out=strtod(p+1,NULL); return 0;
}

static int read_file(const char *path,char *buf,size_t cap){
    FILE *f=fopen(path,"r"); if(!f) return -1;
    size_t n=fread(buf,1,cap-1,f); fclose(f); buf[n]='\0'; return (int)n;
}

static double read_cgroup_node_mb(const char *cgroup,int node){
    char path[512],line[4096],key[16];
    snprintf(path,sizeof(path),"%s/memory.numa_stat",cgroup);
    FILE *f=fopen(path,"r"); if(!f) return -1;
    snprintf(key,sizeof(key),"N%d=",node);
    unsigned long long sum=0;
    while(fgets(line,sizeof(line),f)){
        if(strncmp(line,"anon ",5)!=0 && strncmp(line,"file ",5)!=0) continue;
        char *p=strstr(line,key); if(p) sum+=strtoull(p+strlen(key),NULL,10);
    }
    fclose(f); return sum/(1024.0*1024.0);
}

static int write_str(const char *path,const char *s){
    int fd=open(path,O_WRONLY); if(fd<0) return -1;
    ssize_t n=write(fd,s,strlen(s)); close(fd); return (n<0)?-1:0;
}

static double demote_be_cgroup(const char *cg,int host,int cxl,int dry){
    double before=read_cgroup_node_mb(cg,host);
    if(before<=1.0) return 0.0;

    char mpath[600]; snprintf(mpath,sizeof(mpath),"%s/cpuset.mems",cg);
    char curmems[64]=""; int has_mems=0;
    FILE *mf=fopen(mpath,"r");
    if(mf){ if(fgets(curmems,sizeof(curmems),mf)){ curmems[strcspn(curmems,"\n")]=0; has_mems=1; } fclose(mf); }

    char ppath[600],line[64];
    snprintf(ppath,sizeof(ppath),"%s/cgroup.procs",cg);
    FILE *pf=fopen(ppath,"r"); if(!pf) return 0.0;
    int pids[256],npid=0;
    while(fgets(line,sizeof(line),pf) && npid<256){ int pid=atoi(line); if(pid>0) pids[npid++]=pid; }
    fclose(pf);

    if(dry){
        fprintf(stderr,"[rec] DRY: %s host=%.0fMB, %d procs, cpuset.mems=%s -> would allow CXL(%d) and demote\n",
                cg,before,npid,has_mems?curmems:"none",cxl);
        return before;
    }

    char want[16]; snprintf(want,sizeof(want),"%d",cxl);
    if(has_mems && strcmp(curmems,want)!=0){
        if(write_str(mpath,want)!=0)
            fprintf(stderr,"[rec]   WARN cpuset.mems %s->%s failed: %s (migration may be blocked)\n",curmems,want,strerror(errno));
        else
            fprintf(stderr,"[rec]   cpuset.mems %s->%s\n",curmems,want);
    }

    unsigned long oldm=(1UL<<host), newm=(1UL<<cxl);
    unsigned long maxnode=(unsigned long)((host>cxl?host:cxl)+2);
    int nok=0;
    for(int i=0;i<npid;i++){
        long r=syscall(SYS_migrate_pages,pids[i],maxnode,&oldm,&newm);
        if(r>=0) nok++;
        else fprintf(stderr,"[rec]   migrate_pages(pid=%d): %s\n",pids[i],strerror(errno));
    }
    double after=read_cgroup_node_mb(cg,host);
    double moved=before-after; if(moved<0) moved=0;
    fprintf(stderr,"[rec] demote %s: mems %s->%d, %d/%d procs ok, host %.0f->%.0fMB (moved~%.0f)\n",
            cg,has_mems?curmems:"(none)",cxl,nok,npid,before,after,moved);
    return moved;
}

static void kill_be_cgroup(const char *cg,int dry){
    if(dry){ fprintf(stderr,"[rec] DRY: would KILL %s (cgroup.kill)\n",cg); return; }
    char kp[600]; snprintf(kp,sizeof(kp),"%s/cgroup.kill",cg);
    if(write_str(kp,"1")==0){ fprintf(stderr,"[rec] KILL %s (cgroup.kill)\n",cg); return; }
    fprintf(stderr,"[rec]   cgroup.kill failed (%s) -> oom_score_adj=1000 + SIGKILL fallback\n",strerror(errno));
    char ppath[600],line[64]; snprintf(ppath,sizeof(ppath),"%s/cgroup.procs",cg);
    FILE *pf=fopen(ppath,"r"); if(!pf) return;
    int killed=0;
    while(fgets(line,sizeof(line),pf)){
        int pid=atoi(line); if(pid<=0) continue;
        char op[64]; snprintf(op,sizeof(op),"/proc/%d/oom_score_adj",pid); write_str(op,"1000");
        if(kill(pid,SIGKILL)==0) killed++;
    }
    fclose(pf);
    fprintf(stderr,"[rec] KILL %s (%d procs SIGKILL)\n",cg,killed);
}

static int enumerate_be(const struct config *c, char paths[][512], int max){
    int n=0;
    for(int i=0;i<c->n_be_cgroups && n<max;i++) snprintf(paths[n++],512,"%s",c->be_cgroups[i]);
    if(c->be_cgroup_dir){
        DIR *d=opendir(c->be_cgroup_dir);
        if(d){ struct dirent *e;
            while((e=readdir(d)) && n<max){
                if(strncmp(e->d_name,"be_sched_",9)!=0) continue;
                snprintf(paths[n++],512,"%s/%s",c->be_cgroup_dir,e->d_name);
            }
            closedir(d);
        }
    }
    return n;
}

static double pick_busiest_be(const struct config *c,char *buf,size_t bufsz){
    char paths[MAX_BE][512]; int n=enumerate_be(c,paths,MAX_BE);
    double best=0; buf[0]='\0';
    for(int i=0;i<n;i++){ double u=read_cgroup_node_mb(paths[i],c->host_node);
        if(u>best){ best=u; snprintf(buf,bufsz,"%s",paths[i]); } }
    return best;
}

static double pick_busiest_total(const struct config *c,char *buf,size_t bufsz){
    char paths[MAX_BE][512]; int n=enumerate_be(c,paths,MAX_BE);
    double best=0; buf[0]='\0';
    for(int i=0;i<n;i++){
        double a=read_cgroup_node_mb(paths[i],c->host_node), b=read_cgroup_node_mb(paths[i],c->cxl_node);
        double t=(a<0?0:a)+(b<0?0:b);
        if(t>best){ best=t; snprintf(buf,bufsz,"%s",paths[i]); } }
    return best;
}
static void csv_header(const char *path){
    if(access(path,F_OK)==0) return;
    FILE *f=fopen(path,"w"); if(!f) return;
    fprintf(f,"ts,headroom_mb,state,psi_avg10,cap_mb,lc_resident_mb,eff_reserve_mb,r_spike_mb,target_cgroup,acted_mb,wm_low_mb,wm_high_mb,credit_mb\n");
    fclose(f);
}

static void usage(const char *p){
    fprintf(stderr,
      "Usage: %s (--be-cgroup-dir DIR | --be-cgroup PATH) [options]\n"
      "  headroom = host_capacity - lc_resident - effective_reserve (from %s)\n"
      "  --be-cgroup-dir DIR   DIR/be_sched_* = BE cgroups eligible for demotion (written by the NRI plugin)\n"
      "  --be-cgroup PATH      explicit BE cgroup (repeatable)\n"
      "  --r-low MB            lower bound of the demote trigger: trigger = max(%.2f x buffer, r-low) (default 3500)\n"
      "  --r-high MB           stop = trigger + (r-high - r-low) (default 5000)\n"
      "  --psi-threshold P     LC memory PSI avg10 above P -> kill a BE (default 20)\n"
      "  --dry-run             log triggers and targets only\n"
      "  poll %.1fs, stale %.0fs, kill escalation %.0fs, kill cooldown %.0fs, metrics %s, killed list %s\n",
      p, CAPACITY_JSON, R_LOW_PCT, POLL_SEC, STALE_SEC, PSI_ESCALATE_SEC, PSI_COOLDOWN_SEC, OUT_CSV, KILLED_FILE);
}

int main(int argc,char **argv){
    struct config cfg; defaults(&cfg);
    static struct option lo[]={
        {"be-cgroup-dir",required_argument,0,'b'},
        {"be-cgroup",required_argument,0,'c'},
        {"r-low",required_argument,0,'l'},
        {"r-high",required_argument,0,2003},
        {"psi-threshold",required_argument,0,2004},
        {"dry-run",no_argument,0,'d'},
        {"help",no_argument,0,'h'},
        {0,0,0,0}
    };
    int opt;
    while((opt=getopt_long(argc,argv,"b:c:l:dh",lo,NULL))!=-1){
        switch(opt){
        case 'b': cfg.be_cgroup_dir=optarg; break;
        case 'c': if(cfg.n_be_cgroups<MAX_BE) cfg.be_cgroups[cfg.n_be_cgroups++]=optarg; break;
        case 'l': cfg.r_low_mb=atof(optarg); break;
        case 2003: cfg.r_high_mb=atof(optarg); break;
        case 2004: cfg.psi_threshold=atof(optarg); break;
        case 'd': cfg.dry_run=1; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 1;
        }
    }
    signal(SIGTERM,on_sig); signal(SIGINT,on_sig);
    if(!cfg.be_cgroup_dir && cfg.n_be_cgroups==0){ fprintf(stderr,"[rec] FATAL: --be-cgroup-dir or --be-cgroup required\n"); usage(argv[0]); return 1; }
    if(cfg.r_high_mb<=cfg.r_low_mb){ fprintf(stderr,"[rec] FATAL: r-high(%.0f) must exceed r-low(%.0f)\n",cfg.r_high_mb,cfg.r_low_mb); return 1; }

    detect_nodes(&cfg.host_node,&cfg.cxl_node);
    if(cfg.host_node<0||cfg.cxl_node<0){ fprintf(stderr,"[rec] FATAL: NUMA node auto-detection failed\n"); return 1; }
    {
        char jb0[4096]; double v0; int ok=0;
        for(int t=0;t<20 && !ok && !g_stop;t++){ if(read_file(CAPACITY_JSON,jb0,sizeof(jb0))>0 && json_get_double(jb0,"lc_psi_some",&v0)==0) ok=1; else usleep(500000); }
        if(!ok){ fprintf(stderr,"[rec] FATAL: %s has no lc_psi_some - memory slack monitor not running?\n",CAPACITY_JSON); return 1; }
    }

    fprintf(stderr,"[rec] started - host=node%d cxl=node%d be_dir=%s trigger=max(%.2f x buffer, %.0f)MB stop=trigger+%.0fMB poll=%.1fs%s\n",
            cfg.host_node,cfg.cxl_node,cfg.be_cgroup_dir?cfg.be_cgroup_dir:"(none)",
            R_LOW_PCT,cfg.r_low_mb,cfg.r_high_mb-cfg.r_low_mb,POLL_SEC, cfg.dry_run?" [DRY-RUN]":"");
    fprintf(stderr,"[rec] kill: lc_psi_some avg10>%.0f -> cgroup.kill, cooldown=%.0fs\n",
            cfg.psi_threshold,PSI_COOLDOWN_SEC);
    csv_header(OUT_CSV);

    int demoting=0;
    double psi_high_since=-1;
    double last_kill_t=-1e9;
    double pend_mb=0;
    double pend_lc=0;
    double pend_since=0;
    char jbuf[4096];

    while(!g_stop){
        double ts=now_sec();
        double cap=-1,lc=-1,eff=-1,rsp=0,hfb=1e18,wm_lo=-1,wm_hi=-1,credit=0;
        const char *state="no_cap";
        double headroom=0, acted_mb=0; char target_cg[512]="-";
        double psi = -1;

        if(read_file(CAPACITY_JSON,jbuf,sizeof(jbuf))>0 &&
           json_get_double(jbuf,"host_capacity_mb",&cap)==0 &&
           json_get_double(jbuf,"effective_reserve_mb",&eff)==0 &&
           json_get_double(jbuf,"lc_resident_mb",&lc)==0){
            json_get_double(jbuf,"R_spike_mb",&rsp);
            json_get_double(jbuf,"lc_psi_some",&psi);
            headroom = cap - lc - eff;
            json_get_double(jbuf,"host_free_buffer_mb",&hfb);

            double jts=-1; json_get_double(jbuf,"ts",&jts);
            if(jts>0 && ts-jts>STALE_SEC){
                state="stale_cap";
            } else {
            double gap = cfg.r_high_mb - cfg.r_low_mb;
            if (gap < 500) gap = 500;
            double rl = R_LOW_PCT * eff;
            if (rl < cfg.r_low_mb) rl = cfg.r_low_mb;
            double rh = rl + gap;
            wm_lo = rl; wm_hi = rh;

            if(pend_mb>0){
                if(ts-pend_since > SETTLE_TIMEOUT_SEC){
                    fprintf(stderr,"[rec]   WARN in-flight %.0fMB not reflected within %.0fs - dropping credit\n",
                            pend_mb, SETTLE_TIMEOUT_SEC);
                    pend_mb=0;
                } else {
                    double shown = pend_lc - lc;
                    credit = pend_mb - shown;
                    if(credit <= 0){ credit=0; pend_mb=0; }
                    else if(credit > pend_mb) credit = pend_mb;
                }
            }
            headroom += credit;

            if(!demoting && headroom < rl) demoting=1;
            if(demoting && headroom >= rh) demoting=0;

            char be[512];
            double busy_host=pick_busiest_be(&cfg,be,sizeof(be));
            int psi_over = (psi>=0 && psi>cfg.psi_threshold);
            if(psi_over){ if(psi_high_since<0) psi_high_since=ts; } else psi_high_since=-1;

            int psi_kill = psi_over && (ts-last_kill_t)>PSI_COOLDOWN_SEC
                           && (busy_host<=1.0 || ts-psi_high_since>=PSI_ESCALATE_SEC);

            if(psi_kill){
                char bk[512]; double busy_tot=pick_busiest_total(&cfg,bk,sizeof(bk));
                if(busy_tot>1.0){
                    state="KILLING";
                    snprintf(target_cg,sizeof(target_cg),"%s",bk);
                    kill_be_cgroup(bk,cfg.dry_run);
                    if(!cfg.dry_run){
                        last_kill_t=ts;
                        char rp[PATH_MAX]; const char *cgp = realpath(bk, rp) ? rp : bk;
                        FILE *kf=fopen(KILLED_FILE,"a");
                        if(kf){ struct timespec rt; clock_gettime(CLOCK_REALTIME,&rt);
                                fprintf(kf,"%ld %s\n",(long)rt.tv_sec,cgp); fclose(kf); }
                        else fprintf(stderr,"[rec]   WARN killed-file %s write failed: %s\n",KILLED_FILE,strerror(errno));
                    }
                    acted_mb=busy_tot;
                } else state="NO_BE";
            } else if(demoting && busy_host>1.0){
                state="DEMOTING";
                snprintf(target_cg,sizeof(target_cg),"%s",be);
                acted_mb=demote_be_cgroup(be,cfg.host_node,cfg.cxl_node,cfg.dry_run);
                if(!cfg.dry_run && acted_mb>0){
                    pend_mb=acted_mb; pend_lc=lc; pend_since=ts;
                }
            } else if(demoting){
                state="DEMOTE_EXHAUSTED";
            } else {
                state="IDLE";
            }
            }
        }

        FILE *f=fopen(OUT_CSV,"a");
        if(f){ fprintf(f,"%.3f,%.1f,%s,%.2f,%.1f,%.1f,%.1f,%.1f,%s,%.1f,%.1f,%.1f,%.1f\n",
                       ts,headroom,state,psi,cap,lc,eff,rsp,target_cg,acted_mb,wm_lo,wm_hi,credit); fclose(f); }
        fprintf(stderr,"[rec] headroom=%.0f(credit %.0f) wm=%.0f/%.0f psi=%.1f state=%s cap=%.0f lc(resident)=%.0f buffer=%.0f(floor %.0f + R_spike %.0f) host_free_buf=%.0f\n",
                headroom,credit,wm_lo,wm_hi,psi,state,cap,lc,eff,eff-rsp,rsp,hfb);

        double sl=POLL_SEC-(now_sec()-ts);
        if(sl>0){ struct timespec rq={(time_t)sl,(long)((sl-(time_t)sl)*1e9)}; nanosleep(&rq,NULL); }
    }
    fprintf(stderr,"[rec] stopped\n");
    return 0;
}
