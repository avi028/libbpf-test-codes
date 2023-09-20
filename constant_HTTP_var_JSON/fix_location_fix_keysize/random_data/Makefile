APP=sc

.PHONY: $(APP)
$(APP): skel
	clang sc.c -Wno-unsequenced -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c sc.bpf.c -o sc.bpf.o

.PHONY: skel
skel: bpf
	bpftool gen skeleton sc.bpf.o name sc > sc.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	-rm -rf *.o *.skel.h vmlinux.h $(APP)
