APP=perfbuf

.PHONY: $(APP)
$(APP): skel
	clang perfbuf.c -Wno-unsequenced -lbpf -lelf -o $(APP)

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -c perfbuf.bpf.c -o perfbuf.bpf.o

.PHONY: skel
skel: bpf
	bpftool gen skeleton perfbuf.bpf.o name perfbuf > perfbuf.skel.h

.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	-rm -rf *.o *.skel.h vmlinux.h $(APP)
