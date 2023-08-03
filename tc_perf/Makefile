APP=tc_perf

.PHONY: $(APP)
$(APP): skel
	clang tc_perf.c -Wno-unsequenced -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -c tc_perf.bpf.c -o tc_perf.bpf.o

.PHONY: skel
skel: bpf
	bpftool gen skeleton tc_perf.bpf.o name tc_perf > tc_perf.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	-rm -rf *.o *.skel.h vmlinux.h $(APP)
