PYTHON ?= .venv/bin/python
GLIBC_BUILD ?= ../../glibc-2.35/build
REWRITTEN_LD ?= build/glibc/ld.gs
REWRITTEN_LIBC ?= build/glibc/libc.gs

.PHONY: install test check glibc-check
install:
	python3 -m venv .venv
	.venv/bin/python -m pip install -e .

test:
	$(PYTHON) -m unittest discover -s tests -v

check: test
	$(PYTHON) -m compileall -q gsfork_elf tests
	$(PYTHON) -m pip check

glibc-check:
	$(PYTHON) tests/check_glibc.py --build "$(GLIBC_BUILD)" \
		--loader "$(REWRITTEN_LD)" --libc "$(REWRITTEN_LIBC)" \
		$(if $(CXX_RUNTIME),--cxx-runtime "$(CXX_RUNTIME)")
