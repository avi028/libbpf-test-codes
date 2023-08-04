APP=tc_perf_ipc

.PHONY: $(APP)
$(APP): skel
	clang tc_perf_ipc.c -Wno-unsequenced -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -c tc_perf_ipc.bpf.c -o tc_perf_ipc.bpf.o

.PHONY: skel
skel: bpf
	bpftool gen skeleton tc_perf_ipc.bpf.o name tc_perf_ipc > tc_perf_ipc.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	-rm -rf *.o *.skel.h vmlinux.h $(APP)
