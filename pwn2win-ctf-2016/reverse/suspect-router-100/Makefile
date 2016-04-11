OPENWRT_SDK_ROOT ?= $(HOME)/Software/openwrt-sdk-ar71xx
QEMU_LD_PREFIX = $(OPENWRT_SDK_ROOT)/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2

all:
	@echo "Please type 'make emu' or 'make bruteforce'"
emu:
	QEMU_LD_PREFIX=$(QEMU_LD_PREFIX) qemu-mips $(QEMU_FLAGS) ./admpanel
bruteforce:
	./bruteforce.py
