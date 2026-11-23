CC        ?= gcc
CLANG     ?= clang
BPFTOOL   ?= bpftool
GO        ?= go
CFLAGS    ?= -O2 -Wall -Wno-format-truncation -Wno-stringop-truncation
BUILD     ?= build

LIBBPF_CFLAGS ?=
LIBBPF_LIBS   ?= -lbpf -lelf -lz

DEMOTE  := src/demote_manager
FC      := $(DEMOTE)/file_classifier
MONITOR := src/monitoring_units
RECOVER := src/recovery_manager
PLACE   := src/placement_manager

BINS := $(addprefix $(BUILD)/, \
	cold_page_demotion_policy unmapped_page_cache_demotion \
	pc_bpf_loader file_backed_page_monitor file_access_classifier.bpf.o \
	memory_slack_monitor bw_contention_monitor \
	recovery_manager throttle_manager)

GOBINS := $(addprefix $(BUILD)/, cxl-scheduler mtier-agent mtier-plugin)

.PHONY: all node go clean
all: node go
node: $(BINS)
go: $(GOBINS)

$(BUILD):
	mkdir -p $@

$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD)/file_access_classifier.bpf.o: $(FC)/file_access_classifier.bpf.c $(BUILD)/vmlinux.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 -I$(BUILD) $(LIBBPF_CFLAGS) -c $< -o $@

$(BUILD)/pc_bpf_loader: $(FC)/pc_bpf_loader.c | $(BUILD)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -o $@ $< $(LIBBPF_LIBS)

$(BUILD)/file_backed_page_monitor: $(FC)/file_backed_page_monitor.c $(FC)/monitor_common.h | $(BUILD)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -o $@ $< $(LIBBPF_LIBS)

$(BUILD)/unmapped_page_cache_demotion: $(DEMOTE)/unmapped_page_cache_demotion.c $(FC)/monitor_common.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< -ljansson

$(BUILD)/cold_page_demotion_policy: $(DEMOTE)/cold_page_demotion_policy.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/memory_slack_monitor: $(MONITOR)/memory_slack_monitor.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/bw_contention_monitor: $(MONITOR)/bw_contention_monitor.c | $(BUILD)
	$(CC) $(CFLAGS) -msse2 -o $@ $<

$(BUILD)/recovery_manager: $(RECOVER)/recovery_manager.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/throttle_manager: $(RECOVER)/throttle_manager.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/cxl-scheduler: | $(BUILD)
	cd $(PLACE)/cxl-scheduler && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o "$(CURDIR)/$@" ./cmd/scheduler

$(BUILD)/mtier-agent: | $(BUILD)
	cd $(PLACE)/cxl-scheduler && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o "$(CURDIR)/$@" ./cmd/agent

$(BUILD)/mtier-plugin: | $(BUILD)
	cd $(PLACE)/nri-mtier && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o "$(CURDIR)/$@" .

clean:
	rm -rf $(BUILD)
