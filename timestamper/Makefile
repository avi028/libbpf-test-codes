.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: bpf
bpf: vmlinux
	clang -g -O1 -target bpf -D__TARGET_ARCH_x86_64 -c timestamp.bpf.c -o timestamp.bpf.o

.PHONY: load
load: bpf
	sudo xdp-loader load -m skb -s xdp ens259f1 timestamp.bpf.o

.PHONY: unload
unload:
	sudo xdp-loader unload -a ens259f1

.PHONY: status
status:
	sudo xdp-loader status

.PHONY: clean
clean: unload
	-rm -rf *.o *.skel.h vmlinux.h $(APP)
