APP=libpcap

.PHONY: $(APP)
$(APP):
	clang libpcap.c  -Wno-unsequenced -lpcap -o $(APP)

.PHONY: run
run: $(APP)
	sudo ./$(APP)

.PHONY: clean
clean:
	-rm -rf *.o $(APP)
