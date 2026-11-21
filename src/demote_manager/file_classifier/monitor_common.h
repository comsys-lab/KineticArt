#ifndef MONITOR_COMMON_H
#define MONITOR_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

struct file_access_info {
    uint64_t inode_id;
    uint64_t last_mmap_ns;
    uint64_t last_syscall_ns;
    uint64_t mmap_count;
    uint64_t syscall_count;
};

struct bpf_stats {
    uint64_t mmap_hits;
    uint64_t syscall_hits;
    uint64_t skipped_no_inode;
    uint64_t skipped_not_target;
};

enum file_class {
    CLASS_UNTOUCHED = 0,
    CLASS_MMAP_ONLY,
    CLASS_SYSCALL_ONLY,
    CLASS_MIXED,
};

static inline enum file_class classify(uint64_t mmap_count, uint64_t syscall_count)
{
    if (mmap_count > 0 && syscall_count == 0)
        return CLASS_MMAP_ONLY;
    if (mmap_count == 0 && syscall_count > 0)
        return CLASS_SYSCALL_ONLY;
    if (mmap_count > 0 && syscall_count > 0)
        return CLASS_MIXED;
    return CLASS_UNTOUCHED;
}

enum log_level {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
};

extern enum log_level g_log_level;
extern const char    *g_log_component;

static inline const char *log_level_str(enum log_level l)
{
    switch (l) {
    case LOG_DEBUG: return "DEBUG";
    case LOG_INFO:  return "INFO ";
    case LOG_WARN:  return "WARN ";
    case LOG_ERROR: return "ERROR";
    default:        return "?????";
    }
}

static inline void log_msg(enum log_level level, const char *fmt, ...)
{
    if (level < g_log_level)
        return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_buf;
    localtime_r(&ts.tv_sec, &tm_buf);

    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", &tm_buf);

    fprintf(stderr, "[%s.%03ld] [%s] [%s] ",
            tbuf, ts.tv_nsec / 1000000,
            log_level_str(level), g_log_component);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
    fflush(stderr);
}

#define LOG_D(...) log_msg(LOG_DEBUG, __VA_ARGS__)
#define LOG_I(...) log_msg(LOG_INFO,  __VA_ARGS__)
#define LOG_W(...) log_msg(LOG_WARN,  __VA_ARGS__)
#define LOG_E(...) log_msg(LOG_ERROR, __VA_ARGS__)

#define PAGE_SIZE_BYTES 4096UL

#endif
