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
#include <sys/stat.h>

#define MAX_BE 64
#define POD_LIST "/tmp/mtier_be_pods.list"
#define STALE_SEC 5.0
#define POLL_SEC 0.5
#define IDLE_FRAC 0.20
#define INEFFECTIVE_WINDOWS 6
#define COOLDOWN_WINDOWS 20
#define RELEASE_DEBOUNCE 4

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s){ (void)s; g_stop = 1; }
static double now_sec(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec + t.tv_nsec/1e9; }

struct config {
    const char *sig_json, *sig_key, *tier, *state_file, *cluster_json, *level_file;
    int    host_node, cxl_node;
    double sig_high, step_wait, up_wait;
    int    dry_run, verbose;
    int    levels[16], nlev;
};
static void defaults(struct config *c){
    c->sig_json="/tmp/probe_stats.json"; c->sig_key="cxl_latency_ratio"; c->tier="cxl";
    c->state_file=NULL; c->cluster_json=NULL; c->level_file=NULL;
    c->host_node=-1; c->cxl_node=-1;
    c->sig_high=1.299; c->step_wait=12; c->up_wait=15;
    c->nlev=10; for(int i=0;i<10;i++) c->levels[i]=100-10*i;
    c->dry_run=0; c->verbose=0;
}

static int read_file(const char *p,char *b,size_t cap){ FILE *f=fopen(p,"r"); if(!f) return -1; size_t n=fread(b,1,cap-1,f); fclose(f); b[n]=0; return (int)n; }
static int write_str(const char *p,const char *s){ int fd=open(p,O_WRONLY); if(fd<0) return -1; ssize_t n=write(fd,s,strlen(s)); close(fd); return n<0?-1:0; }
static int json_get_double(const char *buf,const char *key,double *out){
    char pat[64]; snprintf(pat,sizeof(pat),"\"%s\"",key); const char *p=strstr(buf,pat); if(!p) return -1;
    p=strchr(p+strlen(pat),':'); if(!p) return -1; if(strncmp(p+1," null",5)==0||strncmp(p+1,"null",4)==0) return -1; *out=strtod(p+1,NULL); return 0;
}

static int cpulist_empty(int n){ char p[128],b[64]; snprintf(p,sizeof(p),"/sys/devices/system/node/node%d/cpulist",n);
    FILE *f=fopen(p,"r"); if(!f) return -1; char *r=fgets(b,sizeof(b),f); fclose(f); return (!r||b[0]=='\n'||!b[0])?1:0; }
static void detect_nodes(int *host,int *cxl){
    DIR *d=opendir("/sys/devices/system/node"); if(!d) return; struct dirent *e; int c=-1;
    while((e=readdir(d))){ int n; if(sscanf(e->d_name,"node%d",&n)==1 && cpulist_empty(n)==1 && (c<0||n<c)) c=n; }
    closedir(d); if(*cxl<0) *cxl=c; if(c<0) return;
    char p[128],l[512]; snprintf(p,sizeof(p),"/sys/devices/system/node/node%d/distance",c);
    if(read_file(p,l,sizeof(l))<0) return;
    int best=-1,bd=1<<30,i=0; char *q=l;
    while(*q){ char *e2; long v=strtol(q,&e2,10); if(e2==q) break; if(i!=c && cpulist_empty(i)==0 && v<bd){bd=v;best=i;} i++; q=e2; }
    if(*host<0) *host=best;
}

static int pod_cgroup(const char *uid,char *out,size_t sz){
    char u[64]; snprintf(u,sizeof(u),"%s",uid); for(char *x=u;*x;x++) if(*x=='-') *x='_';
    const char *fmt[]={"/sys/fs/cgroup/kubepods.slice/kubepods-pod%s.slice",
                       "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod%s.slice",
                       "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod%s.slice"};
    for(int i=0;i<3;i++){ snprintf(out,sz,fmt[i],u); struct stat st; if(stat(out,&st)==0 && S_ISDIR(st.st_mode)) return 0; }
    return -1;
}
static double node_mb(const char *cg,int node){
    char p[600],l[4096],k[16]; snprintf(p,sizeof(p),"%s/memory.numa_stat",cg); FILE *f=fopen(p,"r"); if(!f) return -1;
    snprintf(k,sizeof(k),"N%d=",node); unsigned long long s=0;
    while(fgets(l,sizeof(l),f)){ if(strncmp(l,"anon ",5)&&strncmp(l,"file ",5)) continue; char *q=strstr(l,k); if(q) s+=strtoull(q+strlen(k),NULL,10); }
    fclose(f); return s/1048576.0;
}
static long long cpu_usage_us(const char *cg){
    char p[600],l[256]; snprintf(p,sizeof(p),"%s/cpu.stat",cg); FILE *f=fopen(p,"r"); if(!f) return -1; long long v=-1;
    while(fgets(l,sizeof(l),f)) if(sscanf(l,"usage_usec %lld",&v)==1) break;
    fclose(f); return v;
}

#define ORIG_DIR "/tmp/mtier_thr_orig"
struct thr { char cg[512]; char orig[64]; };
static struct thr g_thr[MAX_BE]; static int g_nthr=0;
static const struct config *g_cfg;

static void orig_path(const char *cg,char *out,size_t sz){ const char *b=strrchr(cg,'/'); snprintf(out,sz,ORIG_DIR"/%s",b?b+1:cg); }

static int get_orig(const char *cg,char *orig,size_t sz){
    char op[700]; orig_path(cg,op,sizeof(op)); mkdir(ORIG_DIR,0755);
    for(int t=0;t<3;t++){
        if(read_file(op,orig,sz)>0){ orig[strcspn(orig,"\n")]=0; if(orig[0]) return 0; }
        char p[600],b[64]; snprintf(p,sizeof(p),"%s/cpu.max",cg); if(read_file(p,b,sizeof(b))<0) return -1; b[strcspn(b,"\n")]=0;
        int fd=open(op,O_WRONLY|O_CREAT|O_EXCL,0644);
        if(fd>=0){ ssize_t w=write(fd,b,strlen(b)); close(fd); if(w<0) return -1; snprintf(orig,sz,"%s",b); return 0; }
        usleep(2000);
    }
    return -1;
}
static void save_state(void){
    char tmp[600]; snprintf(tmp,sizeof(tmp),"%s.tmp",g_cfg->state_file);
    FILE *f=fopen(tmp,"w"); if(!f) return; for(int i=0;i<g_nthr;i++) fprintf(f,"%s %s\n",g_thr[i].cg,g_thr[i].orig); fclose(f); rename(tmp,g_cfg->state_file);
}
static void restore_one(int i){
    char p[600]; snprintf(p,sizeof(p),"%s/cpu.max",g_thr[i].cg);
    if(!g_cfg->dry_run && write_str(p,g_thr[i].orig)!=0 && errno!=ENOENT){
        fprintf(stderr,"[thr] WARN cpu.max restore failed %s: %s (kept, retry later)\n",g_thr[i].cg,strerror(errno)); return; }
    g_thr[i]=g_thr[--g_nthr];
}
static void restore_all(void){ for(int i=g_nthr-1;i>=0;i--) restore_one(i); save_state(); }
static int find_thr(const char *cg){ for(int i=0;i<g_nthr;i++) if(!strcmp(g_thr[i].cg,cg)) return i; return -1; }

static void set_pct(const char *cg,int pct){
    int k=find_thr(cg); char o[64];
    if(k>=0) snprintf(o,sizeof(o),"%s",g_thr[k].orig);
    else { if(g_nthr>=MAX_BE || get_orig(cg,o,sizeof(o))) return;
           snprintf(g_thr[g_nthr].cg,sizeof(g_thr[0].cg),"%s",cg); snprintf(g_thr[g_nthr].orig,sizeof(g_thr[0].orig),"%s",o); g_nthr++; save_state(); }
    long long q=-1,per=100000; char qs[32]="";
    if(sscanf(o,"%31s %lld",qs,&per)<1) return;
    if(strcmp(qs,"max")) q=atoll(qs);
    long long nq=(q>0?q:per)*pct/100; if(nq<1000) nq=1000;
    char v[64],cur[64]="",p[600]; snprintf(v,sizeof(v),"%lld %lld",nq,per); snprintf(p,sizeof(p),"%s/cpu.max",cg);
    if(read_file(p,cur,sizeof(cur))>0){ cur[strcspn(cur,"\n")]=0; if(!strcmp(cur,v)) return; }
    if(!g_cfg->dry_run && write_str(p,v)!=0){ fprintf(stderr,"[thr] WARN cpu.max write %s failed %s: %s\n",v,cg,strerror(errno)); return; }
    if(g_cfg->verbose) fprintf(stderr,"[thr]   %s cpu.max %s -> %s\n",cg,cur,v);
}

static double allowed_cores(char tg[][512],int nt){
    double a=0; for(int i=0;i<nt;i++){ char p[600],b[64]; snprintf(p,sizeof(p),"%s/cpu.max",tg[i]); if(read_file(p,b,sizeof(b))<0) continue;
        long long q,per; char qs[32]; if(sscanf(b,"%31s %lld",qs,&per)==2 && strcmp(qs,"max") && per>0){ q=atoll(qs); a+=(double)q/per; } else a+=1.0; }
    return a;
}

static int targets(const struct config *c,char out[][512],int max){
    FILE *f=fopen(POD_LIST,"r"); if(!f) return 0; char l[128]; int n=0; int want_cxl=!strcmp(c->tier,"cxl");
    while(fgets(l,sizeof(l),f) && n<max){ l[strcspn(l," \n")]=0; if(!l[0]) continue; char cg[512]; if(pod_cgroup(l,cg,sizeof(cg))) continue;
        int dup=0; for(int i=0;i<n;i++) if(!strcmp(out[i],cg)) dup=1; if(dup) continue;
        double h=node_mb(cg,c->host_node), x=node_mb(cg,c->cxl_node); if(h+x<1) continue;
        int is_cxl=-1; { DIR *d=opendir(cg); struct dirent *e;
            if(d){ while((e=readdir(d))){ if(strncmp(e->d_name,"cri-containerd-",15)) continue; char mp[900],b[64];
                    snprintf(mp,sizeof(mp),"%s/%s/cpuset.mems.effective",cg,e->d_name);
                    if(read_file(mp,b,sizeof(b))>0){ b[strcspn(b,"\n")]=0; char cs[16]; snprintf(cs,sizeof(cs),"%d",c->cxl_node); is_cxl=!strcmp(b,cs); break; } }
                closedir(d); } }
        if(is_cxl<0) is_cxl = x>h;
        if(want_cxl==is_cxl) snprintf(out[n++],512,"%s",cg); }
    fclose(f); return n;
}

int main(int argc,char **argv){
    struct config cfg; defaults(&cfg); g_cfg=&cfg;
    static struct option lo[]={{"tier",required_argument,0,'t'},{"signal-key",required_argument,0,'k'},{"sig-high",required_argument,0,'H'},
        {"signal-json",required_argument,0,'j'},{"levels",required_argument,0,'L'},{"cluster-json",required_argument,0,'C'},{"step-wait",required_argument,0,'S'},{"up-wait",required_argument,0,'U'},
        {"dry-run",no_argument,0,'d'},{"verbose",no_argument,0,'v'},{"help",no_argument,0,'h'},{0,0,0,0}};
    int opt;
    while((opt=getopt_long(argc,argv,"t:k:H:j:L:S:U:C:dvh",lo,NULL))!=-1){
        switch(opt){
        case 't': cfg.tier=optarg; break; case 'k': cfg.sig_key=optarg; break; case 'H': cfg.sig_high=atof(optarg); break;
        case 'j': cfg.sig_json=optarg; break; case 'C': cfg.cluster_json=optarg; break; case 'S': cfg.step_wait=atof(optarg); break; case 'U': cfg.up_wait=atof(optarg); break;
        case 'L': { cfg.nlev=0; char b[128]; snprintf(b,sizeof(b),"%s",optarg); for(char *t=strtok(b,",");t&&cfg.nlev<16;t=strtok(NULL,",")) cfg.levels[cfg.nlev++]=atoi(t); } break;
        case 'd': cfg.dry_run=1; break; case 'v': cfg.verbose=1; break;
        default: fprintf(stderr,
            "Usage: %s --tier cxl|host [--signal-json FILE] [--signal-key cxl_latency_ratio|latency_ratio] [--sig-high 1.299] [--levels 100,90,...,10] [--step-wait 12] [--up-wait 15] [--cluster-json FILE] [--dry-run] [--verbose]\n"
            "  signal >= sig-high: lower cpu.max of the tier's managed BEs one level per step-wait; signal below for up-wait: raise one level.\n"
            "  --cluster-json replaces signal-json/signal-key with the cluster-wide cxl_latency_ratio. root required.\n",argv[0]);
            return opt=='h'?0:1; }
    }
    if(cfg.nlev<2 || cfg.levels[0]!=100){ fprintf(stderr,"[thr] FATAL --levels must start at 100 and have at least 2 levels\n"); return 1; }
    if(strcmp(cfg.tier,"cxl") && strcmp(cfg.tier,"host")){ fprintf(stderr,"[thr] FATAL --tier cxl|host\n"); return 1; }
    static char sf[128], lf[128];
    snprintf(sf,sizeof(sf),"/tmp/mtier_thr_%s.state",cfg.tier); cfg.state_file=sf;
    snprintf(lf,sizeof(lf),"/tmp/mtier_thr_%s.level",cfg.tier); cfg.level_file=lf;
    if(cfg.cluster_json){ cfg.sig_json=cfg.cluster_json; cfg.sig_key="cxl_latency_ratio"; }

    { FILE *f=fopen(cfg.state_file,"r"); if(f){ char cg[512],o[64],l[700]; int k=0;
        while(fgets(l,sizeof(l),f) && g_nthr<MAX_BE){ if(sscanf(l,"%511s %63[^\n]",cg,o)==2){ snprintf(g_thr[g_nthr].cg,512,"%s",cg); snprintf(g_thr[g_nthr].orig,64,"%s",o); g_nthr++; k++; } }
        fclose(f); if(k){ fprintf(stderr,"[thr] WARN restoring %d leftover cpu.max entries\n",k); restore_all(); } } }
    detect_nodes(&cfg.host_node,&cfg.cxl_node);
    if(cfg.host_node<0||cfg.cxl_node<0){ fprintf(stderr,"[thr] FATAL NUMA node auto-detection failed\n"); return 1; }
    signal(SIGTERM,on_sig); signal(SIGINT,on_sig);

    fprintf(stderr,"[thr] started - tier=%s host=node%d cxl=node%d signal=%s:%s high=%.3f levels=%d..%d%% (%d) step-wait=%.0fs up-wait=%.0fs%s%s\n",
            cfg.tier,cfg.host_node,cfg.cxl_node,cfg.sig_json,cfg.sig_key,cfg.sig_high,cfg.levels[0],cfg.levels[cfg.nlev-1],cfg.nlev,cfg.step_wait,cfg.up_wait,cfg.cluster_json?" [cluster signal]":"",cfg.dry_run?" [DRY-RUN]":"");

    int lev=0, floor_high_cnt=0, cooldown=0, be_idle_cnt=0;
    double last_step=-1e9, below_since=-1;
    long long prev_use=-1; double prev_t=0; char jbuf[4096]; static char tg[MAX_BE][512];
    #define RELEASE() do{ lev=0; restore_all(); floor_high_cnt=be_idle_cnt=0; below_since=-1; }while(0)
    while(!g_stop){
        double ts=now_sec();
        double sig=-1; int stale=0;
        double allfl=-1;
        if(read_file(cfg.sig_json,jbuf,sizeof(jbuf))>0){ json_get_double(jbuf,cfg.sig_key,&sig); if(cfg.cluster_json) json_get_double(jbuf,"all_floor",&allfl); }
        { struct stat st; if(stat(cfg.sig_json,&st)!=0 || time(NULL)-st.st_mtime>(time_t)STALE_SEC) stale=1; }
        int nt=targets(&cfg,tg,MAX_BE);

        long long use=0; for(int i=0;i<nt;i++){ long long u=cpu_usage_us(tg[i]); if(u>0) use+=u; }
        double be_cpu=-1; static int prev_nt=-1;
        if(prev_use>=0 && nt==prev_nt && use>=prev_use && ts>prev_t) be_cpu=(use-prev_use)/1e6/(ts-prev_t);
        prev_use=use; prev_t=ts; prev_nt=nt;
        double allow=allowed_cores(tg,nt);
        int idle = (be_cpu>=0 && nt>0 && be_cpu < IDLE_FRAC*allow);
        const char *state;
        if(cooldown>0){ cooldown--; state="COOLDOWN"; }
        else if(sig<0 || stale){ if(lev){ RELEASE(); state=stale?"STALE_RELEASE":"NA_RELEASE"; } else state=stale?"STALE":"NA"; }
        else if(lev==0){
            if(sig>=cfg.sig_high){
                if(nt==0) state="NO_TARGET";
                else if(idle) state="LC_BOUND";
                else { lev=1; for(int i=0;i<nt;i++) set_pct(tg[i],cfg.levels[lev]); save_state(); last_step=ts; below_since=-1; state="STEP_DOWN"; }
            } else state="IDLE";
        } else {
            for(int i=g_nthr-1;i>=0;i--){ int in=0; for(int j=0;j<nt;j++) if(!strcmp(tg[j],g_thr[i].cg)) in=1; if(!in) restore_one(i); }
            for(int i=0;i<nt;i++) set_pct(tg[i],cfg.levels[lev]);
            if(idle){ be_idle_cnt++; floor_high_cnt=0;
                if(be_idle_cnt>=RELEASE_DEBOUNCE){ RELEASE(); state="IDLE_RELEASE"; } else state="HOLD_BE_IDLE"; }
            else if(sig>=cfg.sig_high){ be_idle_cnt=0; below_since=-1;
                if(lev==cfg.nlev-1 && cfg.cluster_json && allfl!=1){ floor_high_cnt=0; state="HOLD_FLOOR_WAIT_CLUSTER"; }
                else if(lev==cfg.nlev-1){
                    floor_high_cnt++;
                    if(floor_high_cnt>=INEFFECTIVE_WINDOWS){ RELEASE();
                        int cw=(int)((cfg.nlev-1)*cfg.step_wait/POLL_SEC); cooldown = cw>COOLDOWN_WINDOWS? cw : COOLDOWN_WINDOWS;
                        state="INEFFECTIVE_RELEASE"; }
                    else state="HOLD_FLOOR_HIGH";
                } else if(ts-last_step>=cfg.step_wait){ lev++; for(int i=0;i<nt;i++) set_pct(tg[i],cfg.levels[lev]); save_state(); last_step=ts; state="STEP_DOWN"; }
                else state="HOLD_WAIT_EFFECT";
            } else { be_idle_cnt=floor_high_cnt=0;
                if(below_since<0) below_since=ts;
                double pred = 1.0 + (sig-1.0) * cfg.levels[lev-1] / (double)cfg.levels[lev];
                if(ts-below_since>=cfg.up_wait && pred>=cfg.sig_high){ state="HOLD_PREDICT_HIGH"; }
                else if(ts-below_since>=cfg.up_wait){
                    lev--; below_since=ts; last_step=ts;
                    if(lev==0){ RELEASE(); state="STEP_UP_RELEASE"; }
                    else { for(int i=0;i<nt;i++) set_pct(tg[i],cfg.levels[lev]); save_state(); state="STEP_UP"; }
                } else state="HOLD_THROTTLED";
            }
        }
        int cur_pct=cfg.levels[lev];
        { char tmp[160]; snprintf(tmp,sizeof(tmp),"%s.tmp",cfg.level_file); FILE *lf2=fopen(tmp,"w");
          int cant = lev==cfg.nlev-1 || cooldown>0 || nt==0 || !strcmp(state,"LC_BOUND") || !strcmp(state,"HOLD_BE_IDLE");
          if(lf2){ fprintf(lf2,"%d %d %d\n",cur_pct,nt,cant); fclose(lf2); rename(tmp,cfg.level_file); } }
        if(cfg.verbose || !strncmp(state,"STEP",4) || strstr(state,"RELEASE") || !strcmp(state,"LC_BOUND"))
            fprintf(stderr,"[thr] %s=%.4f be_cpu=%.3f allowed=%.3f target=%d throttled=%d pct=%d state=%s\n",cfg.sig_key,sig,be_cpu,allow,nt,g_nthr,cur_pct,state);
        double sl=POLL_SEC-(now_sec()-ts);
        if(sl>0){ struct timespec rq={(time_t)sl,(long)((sl-(time_t)sl)*1e9)}; nanosleep(&rq,NULL); }
    }
    restore_all(); fprintf(stderr,"[thr] stopped (cpu.max restored)\n"); return 0;
}
