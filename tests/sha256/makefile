# Autotest Makefile

# ----------------------------
# Makefile Options
# ----------------------------

PYTHON = python3
CEDEV_ROOT = $(call cedev-config --prefix)
CRYPTO_ROOT = ../../src/internetce/crypto
AUTOTESTER_ROM = $(shell echo $$AUTOTESTER_ROM)

# For program compilation
NAME = SHA256
COMPRESSED = NO
ARCHIVED = NO
EXTRA_ASM_SOURCES = $(CRYPTO_ROOT)/ports.asm
EXTRA_C_SOURCES = $(CRYPTO_ROOT)/sha256.c
CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz

# ----------------------------
# Targets
# ----------------------------

all: autotest.json build autotest

build: autotest.json
	@$(MAKE) -f $(shell cedev-config --makefile) NAME="$(NAME)" COMPRESSED="$(COMPRESSED)" ARCHIVED="$(ARCHIVED)" EXTRA_ASM_SOURCES="$(EXTRA_ASM_SOURCES)" EXTRA_C_SOURCES="$(EXTRA_C_SOURCES)" CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)"

autotest.json: gen_sha256_autotest.py
	@$(PYTHON) gen_sha256_autotest.py autotest.json

autotest:
	@if [ -z "${AUTOTESTER_ROM}" ]; then \
		echo "\033[31mYou need to define the AUTOTESTER_ROM variable to your CEmu ROM\033[0m"; \
	else \
		$(MAKE) -f $(shell cedev-config --makefile) test; \
	fi
