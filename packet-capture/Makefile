GCC = gcc -Wno-write-strings
APP = packet-capture.c

all: packet-capture

packet-capture: $(APP)
	$(GCC) $(APP) -g -o packet-capture -lpcap

clean:
	rm -f packet-capture