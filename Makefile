CC := gcc
FASM := fasm

STUB := phork
UTILS_DIR := utils
TEST_DIR := test
PACK_TOOL_ASM := /tmp/phork_mkpack
SPACK_TOOL_ASM := /tmp/phork_spack_tool

PACK_TEST := /tmp/phork_test
PACK_TLS_ARGV := /tmp/phork_tls_argv
PACK_ASM := /tmp/phork_asm

SHELF_TEST := /tmp/phork_input_test
SHELF_TLS_ARGV := /tmp/phork_input_tls_argv
SHELF_ASM := /tmp/phork_input_asm

COMMON_CFLAGS := -Wall -Wextra -fno-asynchronous-unwind-tables -fno-unwind-tables
SHELF_LDFLAGS := -static-pie -Wl,--no-eh-frame-hdr -Wl,-T,$(TEST_DIR)/static-pie.ld

.PHONY: all clean inspect inspect-pack validate-pack extract-pack run corrupt-tests pack-tool-asm spack-tool-asm FORCE

# FORCE is defined ahead of "all" below, and make's default goal is otherwise
# the first target in the file. Without this, a bare "make" silently builds
# nothing instead of the stub
.DEFAULT_GOAL := all

# Rebuild stable /tmp pack names whenever the pack tool is evaluated, so make
# does not reuse a pack made by a stale build
FORCE:

define run_expect
	@$(1); \
	status=$$?; \
	if [ $$status -ne $(2) ]; then \
		echo "FAIL: $(1) exited $$status, expected $(2)"; \
		exit $$status; \
	fi
endef

all: $(STUB)

$(STUB): phork.asm utils.inc loader/reloc.inc loader/stack.inc loader/rwdata.inc loader/rodata.inc
	$(FASM) phork.asm
	chmod +x $(STUB)

$(SHELF_TEST): $(TEST_DIR)/test.c $(TEST_DIR)/static-pie.ld
	$(CC) $(COMMON_CFLAGS) $(SHELF_LDFLAGS) -o $@ $(TEST_DIR)/test.c

$(SHELF_TLS_ARGV): $(TEST_DIR)/test_argv_tls.c $(TEST_DIR)/static-pie.ld
	$(CC) $(COMMON_CFLAGS) $(SHELF_LDFLAGS) -o $@ $(TEST_DIR)/test_argv_tls.c

$(SHELF_ASM): $(TEST_DIR)/payload_asm.asm
	$(FASM) $(TEST_DIR)/payload_asm.asm $@
	chmod +x $@

pack-tool-asm: $(UTILS_DIR)/mkpack.asm utils.inc
	$(FASM) $(UTILS_DIR)/mkpack.asm $(PACK_TOOL_ASM)
	chmod +x $(PACK_TOOL_ASM)

spack-tool-asm: $(UTILS_DIR)/spack_tool.asm utils.inc
	$(FASM) $(UTILS_DIR)/spack_tool.asm $(SPACK_TOOL_ASM)
	chmod +x $(SPACK_TOOL_ASM)

$(PACK_TEST): FORCE $(STUB) $(SHELF_TEST) $(UTILS_DIR)/mkpack.asm utils.inc
	$(MAKE) pack-tool-asm
	$(PACK_TOOL_ASM) ./$(STUB) $(SHELF_TEST) $(PACK_TEST)

$(PACK_TLS_ARGV): FORCE $(STUB) $(SHELF_TLS_ARGV) $(UTILS_DIR)/mkpack.asm utils.inc
	$(MAKE) pack-tool-asm
	$(PACK_TOOL_ASM) ./$(STUB) $(SHELF_TLS_ARGV) $(PACK_TLS_ARGV)

$(PACK_ASM): FORCE $(STUB) $(SHELF_ASM) $(UTILS_DIR)/mkpack.asm utils.inc
	$(MAKE) pack-tool-asm
	$(PACK_TOOL_ASM) ./$(STUB) $(SHELF_ASM) $(PACK_ASM)

inspect: $(PACK_TEST) $(PACK_TLS_ARGV) $(PACK_ASM)
	file $(PACK_TEST)
	readelf -h $(PACK_TEST)
	echo
	file $(PACK_TLS_ARGV)
	readelf -h $(PACK_TLS_ARGV)
	echo
	file $(PACK_ASM)
	readelf -h $(PACK_ASM)

inspect-pack: $(PACK_TEST) $(PACK_TLS_ARGV) $(PACK_ASM) spack-tool-asm
	$(SPACK_TOOL_ASM) inspect $(PACK_TEST)
	echo
	$(SPACK_TOOL_ASM) inspect $(PACK_TLS_ARGV)
	echo
	$(SPACK_TOOL_ASM) inspect $(PACK_ASM)

validate-pack: $(PACK_TEST) $(PACK_TLS_ARGV) $(PACK_ASM) spack-tool-asm
	$(SPACK_TOOL_ASM) validate $(PACK_TEST)
	$(SPACK_TOOL_ASM) validate $(PACK_TLS_ARGV)
	$(SPACK_TOOL_ASM) validate $(PACK_ASM)

extract-pack: $(PACK_TEST) spack-tool-asm
	$(SPACK_TOOL_ASM) extract $(PACK_TEST) /tmp/phork_test.meta /tmp/phork_test.payload
	file /tmp/phork_test.meta /tmp/phork_test.payload

run: $(PACK_TEST) $(PACK_TLS_ARGV) $(PACK_ASM)
	$(call run_expect,$(PACK_TEST),7)
	$(call run_expect,$(PACK_TLS_ARGV) alpha beta,7)
	$(call run_expect,$(PACK_ASM),7)

corrupt-tests: $(PACK_TEST) spack-tool-asm
	@cp $(PACK_TEST) /tmp/phork_bad_truncated
	@truncate -s -8 /tmp/phork_bad_truncated
	@! $(SPACK_TOOL_ASM) validate /tmp/phork_bad_truncated >/tmp/spack.corrupt.out 2>/tmp/spack.corrupt.err
	@cp $(PACK_TEST) /tmp/phork_bad_magic
	@size=$$(wc -c < /tmp/phork_bad_magic | tr -d ' '); \
	printf 'BROKEN!!' | dd of=/tmp/phork_bad_magic bs=1 seek=$$((size - 48)) conv=notrunc 2>/dev/null
	@! $(SPACK_TOOL_ASM) validate /tmp/phork_bad_magic >/tmp/spack.corrupt.out 2>/tmp/spack.corrupt.err
	@cp $(PACK_TEST) /tmp/phork_bad_meta_magic
	@meta_off=$$($(SPACK_TOOL_ASM) inspect $(PACK_TEST) | awk '/^meta_off:/ {print $$2}'); \
	printf 'X' | dd of=/tmp/phork_bad_meta_magic bs=1 seek=$$meta_off conv=notrunc 2>/dev/null
	@! $(SPACK_TOOL_ASM) validate /tmp/phork_bad_meta_magic >/tmp/spack.corrupt.out 2>/tmp/spack.corrupt.err
	@cp $(PACK_TEST) /tmp/phork_bad_payload_len
	@size=$$(wc -c < /tmp/phork_bad_payload_len | tr -d ' '); \
	printf '\001' | dd of=/tmp/phork_bad_payload_len bs=1 seek=$$((size - 16)) conv=notrunc 2>/dev/null
	@! $(SPACK_TOOL_ASM) validate /tmp/phork_bad_payload_len >/tmp/spack.corrupt.out 2>/tmp/spack.corrupt.err
	@cp $(PACK_TEST) /tmp/phork_bad_offset_overflow
	@size=$$(wc -c < /tmp/phork_bad_offset_overflow | tr -d ' '); \
	printf '\377\377\377\377\377\377\377\377' | dd of=/tmp/phork_bad_offset_overflow bs=1 seek=$$((size - 40)) conv=notrunc 2>/dev/null
	@! $(SPACK_TOOL_ASM) validate /tmp/phork_bad_offset_overflow >/tmp/spack.corrupt.out 2>/tmp/spack.corrupt.err
	@cp $(PACK_TEST) /tmp/phork_bad_flags
	@size=$$(wc -c < /tmp/phork_bad_flags | tr -d ' '); \
	printf '\200' | dd of=/tmp/phork_bad_flags bs=1 seek=$$((size - 8)) conv=notrunc 2>/dev/null
	@! $(SPACK_TOOL_ASM) validate /tmp/phork_bad_flags >/tmp/spack.corrupt.out 2>/tmp/spack.corrupt.err
	@cp $(PACK_TEST) /tmp/phork_bad_payload_limit
	@size=$$(wc -c < /tmp/phork_bad_payload_limit | tr -d ' '); \
	printf '\001\000\020\000\000\000\000\000' | dd of=/tmp/phork_bad_payload_limit bs=1 seek=$$((size - 16)) conv=notrunc 2>/dev/null
	@! /tmp/phork_bad_payload_limit >/tmp/spack.corrupt.out 2>/tmp/spack.corrupt.err
	@echo "phork corrupt tests: ok"

clean:
	rm -f $(STUB) $(PACK_TEST) $(PACK_TLS_ARGV) $(PACK_ASM) $(SHELF_TEST) $(SHELF_TLS_ARGV) $(SHELF_ASM) $(PACK_TOOL_ASM) $(SPACK_TOOL_ASM) /tmp/phork_test.meta /tmp/phork_test.payload /tmp/phork_bad_truncated /tmp/phork_bad_magic /tmp/phork_bad_meta_magic /tmp/phork_bad_payload_len /tmp/phork_bad_offset_overflow /tmp/phork_bad_flags /tmp/phork_bad_payload_limit /tmp/spack.corrupt.out /tmp/spack.corrupt.err
