# Makefile
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

# Flags
CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# Targets
all: blackbox

# 1. Generate vmlinux.h (Kernel Type Definitions)
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. Compile eBPF Code -> Object File
src/main.bpf.o: src/main.bpf.c vmlinux.h src/blackbox.h
	$(CLANG) $(BPF_CFLAGS) -c src/main.bpf.c -o src/main.bpf.o

# 3. Generate BPF Skeleton (Userspace helper)
src/main.skel.h: src/main.bpf.o
	$(BPFTOOL) gen skeleton src/main.bpf.o > src/main.skel.h

# 4. Compile Userspace Loader
blackbox: src/main.c src/main.skel.h src/blackbox.h
	$(CLANG) $(CFLAGS) -I src src/main.c -lbpf -lelf -lz -lpthread -o blackbox

clean:
	rm -f blackbox src/*.o src/*.skel.h vmlinux.h