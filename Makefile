CC = gcc
PYTHON ?= python3
CFLAGS = -O3 -Wall -Wextra -Werror -fno-pie -fno-stack-protector -fcf-protection=none -fno-asynchronous-unwind-tables -fno-unwind-tables
KFLAGS = -fno-tree-vectorize -fno-tree-loop-distribute-patterns -mno-red-zone
.PHONY: all test bench perf-stat perf-record perf-sweep perf-doctor fork-test mibench-build mibench-test mibench-perf mibench-binary-build mibench-binary-test mibench-binary-perf clean
KERNEL ?= chase
SIZE ?= 32K
SECONDS ?= 3
PROFILE_ARGS ?=
all: build/original build/rewritten build/reencoded
build:
	mkdir -p build
build/kernels.o: src/kernels.c src/kernels.h | build
	$(CC) $(CFLAGS) $(KFLAGS) -c $< -o $@
build/harness.o: src/harness.c src/kernels.h | build
	$(CC) $(CFLAGS) -c $< -o $@
build/original: build/kernels.o build/harness.o slots.ld
	$(CC) -no-pie -Wl,--build-id=none -Wl,-T,slots.ld build/kernels.o build/harness.o -o $@
build/rewritten: build/original rewrite.py
	$(PYTHON) rewrite.py $< $@ --report build/rewrite.json
build/reencoded: build/original rewrite.py
	$(PYTHON) rewrite.py $< $@ --no-gs --report build/reencoded.json
test: all
	$(PYTHON) -m unittest discover -s tests -v
	$(PYTHON) validate.py
	$(PYTHON) fork_validate.py
bench: test
	$(PYTHON) benchmark.py --output results
perf-stat: all
	$(PYTHON) profile.py stat --kernel $(KERNEL) --size $(SIZE) --seconds $(SECONDS) $(PROFILE_ARGS)
perf-record: all
	$(PYTHON) profile.py record --kernel $(KERNEL) --size $(SIZE) --seconds $(SECONDS) $(PROFILE_ARGS)
perf-sweep: all
	$(PYTHON) profile.py sweep --kernel $(KERNEL) --seconds $(SECONDS) $(PROFILE_ARGS)
perf-doctor:
	$(PYTHON) profile.py doctor $(PROFILE_ARGS)
fork-test:
	$(PYTHON) fork_validate.py
mibench-build:
	$(PYTHON) mibench_build.py $(if $(MIBENCH_SOURCE),--source $(MIBENCH_SOURCE),)
mibench-test: mibench-build
	@cpu=`$(PYTHON) -c 'import os; print(min(os.sched_getaffinity(0)))'`; \
	for bench in "crc 1048576" "fft 4096" "adpcm 1048576"; do \
		set -- $$bench; \
		for variant in baseline gs0 gsshift; do \
			build/mibench/mibench-$$variant $$1 $$2 2 $$cpu; \
		done; \
	done
mibench-perf: mibench-build
	$(PYTHON) mibench_profile.py $(PROFILE_ARGS)
mibench-binary-build:
	$(PYTHON) mibench_binary_build.py $(if $(MIBENCH_SOURCE),--source $(MIBENCH_SOURCE),)
mibench-binary-test: mibench-binary-build
	@cpu=`$(PYTHON) -c 'import os; print(min(os.sched_getaffinity(0)))'`; \
	for bench in "crc 1048576" "fft 4096" "adpcm 1048576"; do \
		set -- $$bench; \
		for variant in baseline gs0 gsshift; do \
			build/mibench-binary/mibench-$$variant $$1 $$2 2 $$cpu; \
		done; \
	done
mibench-binary-perf: mibench-binary-build
	$(PYTHON) mibench_profile.py --binary-dir build/mibench-binary $(PROFILE_ARGS)
clean:
	rm -rf build
