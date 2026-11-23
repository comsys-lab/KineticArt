#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <emmintrin.h>

#define MAXN 4
#define MPOL_BIND_ 2
#define LOADS_PER_PERIOD 32768

static double mono(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec + t.tv_nsec/1e9; }
static double wall(void){ struct timespec t; clock_gettime(CLOCK_REALTIME,&t); return t.tv_sec + t.tv_nsec/1e9; }
static int cmpd(const void *a,const void *b){ double x=*(const double*)a,y=*(const double*)b; return x<y?-1:x>y; }

static void *mkbuf(int node, size_t bytes){
    char *buf = mmap(NULL, bytes, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(buf==MAP_FAILED){ perror("mmap"); exit(1); }
    madvise(buf, bytes, MADV_NOHUGEPAGE);
    unsigned long mask = 1UL<<node;
    if(syscall(SYS_mbind, buf, bytes, MPOL_BIND_, &mask, sizeof(mask)*8, 0)!=0){ perror("mbind"); exit(1); }
    memset(buf, 0, bytes);
    size_t n = bytes/64; uint32_t *perm = malloc(n*sizeof(uint32_t));
    if(!perm){ perror("malloc"); exit(1); }
    for(uint32_t i=0;i<n;i++) perm[i]=i;
    srand(777); for(size_t i=n-1;i>0;i--){ size_t j=(size_t)(((uint64_t)rand()<<31 ^ rand())% i); uint32_t t=perm[i]; perm[i]=perm[j]; perm[j]=t; }
    for(size_t k=0;k<n;k++) *(void**)(buf+(size_t)perm[k]*64) = buf+(size_t)perm[(k+1)%n]*64;
    free(perm);
    return buf;
}

static void sleep_until(double want){
    double now0=mono();
    if(want>now0){ struct timespec w={(time_t)(want-now0),(long)(((want-now0)-(time_t)(want-now0))*1e9)}; nanosleep(&w,NULL); }
}

int main(int argc, char **argv){
    int nodes[MAXN]={0,1}, nn=2, chunks=5, basep=20, avgn=10, kb=4; double spread=100, jitter=50;
    double period=500, burst=20, base_fix[MAXN]={0};
    const char *json=NULL;
    static struct option lo[]={{"nodes",1,0,'n'},{"kb",1,0,'K'},{"period-ms",1,0,'p'},{"burst-ms",1,0,'b'},
        {"chunks",1,0,'c'},{"json",1,0,'j'},{"base-periods",1,0,'B'},{"base",1,0,'F'},{"avg",1,0,'A'},{"spread-ms",1,0,'S'},{"jitter-ms",1,0,'J'},{0,0,0,0}};
    int o;
    while((o=getopt_long(argc,argv,"",lo,NULL))!=-1){
        if(o=='n'){ nn=0; for(char *s=strtok(optarg,","); s && nn<MAXN; s=strtok(NULL,",")) nodes[nn++]=atoi(s); }
        else if(o=='K') kb=atoi(optarg); else if(o=='p') period=atof(optarg); else if(o=='b') burst=atof(optarg);
        else if(o=='c') chunks=atoi(optarg); else if(o=='j') json=optarg; else if(o=='B') basep=atoi(optarg);
        else if(o=='F'){ int k=0; for(char *s=strtok(optarg,","); s && k<MAXN; s=strtok(NULL,",")) base_fix[k++]=atof(s); }
        else if(o=='A') avgn=atoi(optarg);
        else if(o=='S') spread=atof(optarg);
        else if(o=='J') jitter=atof(optarg);
        else { fprintf(stderr,"usage: --nodes N,N --kb K --period-ms P --burst-ms B --chunks C [--json FILE] [--base-periods N] [--base NS,NS] [--avg N] [--spread-ms S] [--jitter-ms J]\n"); return 1; }
    }
    if(kb<=0 || kb%4){ fprintf(stderr,"--kb must be a positive multiple of 4\n"); return 1; }
    if(chunks<1) chunks=1;
    if(chunks>64) chunks=64;
    if(avgn<1) avgn=1;
    if(avgn>64) avgn=64;
    size_t bytes=(size_t)kb*1024;
    void *buf[MAXN];
    for(int k=0;k<nn;k++) buf[k]=mkbuf(nodes[k],bytes);
    fprintf(stderr,"[probe] buffer=%d KB/node nodes=%d spread=%.0fms jitter=%.0fms period=%.0fms burst=%.0fms chunks=%d avg=%d\n",
            kb, nn, spread, jitter, period, burst, chunks, avgn);
    setvbuf(stdout,NULL,_IOLBF,0);
    srand((unsigned)(wall()*1000) ^ (unsigned)getpid());
    double base[MAXN]={0}, acc[MAXN][256]; int nacc=0;
    for(int k=0;k<nn;k++) base[k]=base_fix[k];
    double hist[MAXN][64]; int nh=0;
    double next=mono();
    for(;;){
        double mean[MAXN];
        for(int k=0;k<nn;k++){
            double ns[64]; uint64_t tot=0; void *q=NULL;
            char *b=(char*)buf[k]; uint64_t lines=bytes/64, per=LOADS_PER_PERIOD/chunks; double gap=spread/1000.0/chunks, ts0=mono();
            for(int c=0;c<chunks;c++){
                sleep_until(ts0+c*gap);
                double tt=0; uint64_t ld=0;
                while(ld<per){ for(uint64_t o2=0;o2<bytes;o2+=64) _mm_clflush(b+o2); _mm_mfence(); q=b;
                    double t0=mono(); for(uint64_t i=0;i<lines;i++) q=*(void**)q; tt+=mono()-t0; ld+=lines; }
                ns[c]=tt*1e9/ld; tot+=ld; }
            if(q==NULL) fprintf(stderr,"x");
            double sm=0; for(int c=0;c<chunks;c++) sm+=ns[c]; mean[k]=sm/chunks;
            qsort(ns,chunks,sizeof(double),cmpd);
            printf("P %.3f %d %.2f %.2f %.2f %llu\n", wall(), nodes[k], mean[k], ns[0], ns[chunks-1], (unsigned long long)tot);
        }
        for(int k=0;k<nn;k++) hist[k][nh%avgn]=mean[k];
        nh++;
        double av[MAXN]; int na = nh<avgn?nh:avgn;
        for(int k=0;k<nn;k++){ av[k]=0; for(int i=0;i<na;i++) av[k]+=hist[k][i]; av[k]/=na; }
        if(nacc<basep && nacc<256){ for(int k=0;k<nn;k++) acc[k][nacc]=mean[k]; nacc++;
            if(nacc==basep) for(int k=0;k<nn;k++) if(base[k]<=0){ qsort(acc[k],nacc,sizeof(double),cmpd); base[k]=acc[k][nacc/2]; } }
        if(json){
            char tmp[512]; snprintf(tmp,sizeof tmp,"%s.tmp",json);
            FILE *f=fopen(tmp,"w");
            if(f){ fprintf(f,"{\"ts\":%.3f",wall());
                for(int k=0;k<nn;k++) fprintf(f,",\"node%d_ns\":%.2f,\"node%d_base_ns\":%.2f,\"node%d_ratio\":%.4f",
                    nodes[k],av[k],nodes[k],base[k],nodes[k],base[k]>0?av[k]/base[k]:-1.0);
                if(nn>=1) fprintf(f,",\"latency_ratio\":%.4f",base[0]>0?av[0]/base[0]:-1.0);
                if(nn>=2) fprintf(f,",\"cxl_latency_ratio\":%.4f",base[1]>0?av[1]/base[1]:-1.0);
                fprintf(f,"}\n"); fclose(f); rename(tmp,json); }
        }
        next += period/1000.0 + ((double)rand()/RAND_MAX*2-1)*jitter/1000.0;
        double now=mono();
        if(next>now) sleep_until(next); else next=now;
    }
}
