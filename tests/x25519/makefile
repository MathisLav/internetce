# Autotest Makefile

# ----------------------------
# Makefile Options
# ----------------------------

PYTHON = python3
CEDEV_ROOT = $(call cedev-config --prefix)
CRYPTO_ROOT = ../../src/internetce/crypto
AUTOTESTER_ROM = $(shell echo $$AUTOTESTER_ROM)

# For program compilation
NAME = X25519
COMPRESSED = NO
ARCHIVED = NO
EXTRA_ASM_SOURCES = $(CRYPTO_ROOT)/x25519.asm
CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz

# ----------------------------
# Targets
# ----------------------------

all: $(CRYPTO_ROOT)/mult256.asm autotest.json build autotest

$(CRYPTO_ROOT)/mult256.asm: $(CRYPTO_ROOT)/generate_mult.py
	@$(PYTHON) $(CRYPTO_ROOT)/generate_mult.py $(CRYPTO_ROOT)/mult256.asm 32 32 > /dev/null

autotest.json: gen_x25519_autotest.py
	@$(PYTHON) gen_x25519_autotest.py autotest.json

build:
	@$(MAKE) -f $(shell cedev-config --makefile) NAME="$(NAME)" COMPRESSED="$(COMPRESSED)" ARCHIVED="$(ARCHIVED)" EXTRA_ASM_SOURCES="$(EXTRA_ASM_SOURCES)" CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)"

autotest:
	@if [ -z "${AUTOTESTER_ROM}" ]; then \
		echo "\033[31mYou need to define the AUTOTESTER_ROM variable to your CEmu ROM\033[0m"; \
	else \
		$(MAKE) -f $(shell cedev-config --makefile) test; \
	fi
