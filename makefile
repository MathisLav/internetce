# ----------------------------
# Makefile Options
# ----------------------------

NAME = INTERNET
COMPRESSED = NO
ARCHIVED = NO

CFLAGS = -Wall -Wextra -Oz
CXXFLAGS = -Wall -Wextra -Oz

PYTHON = python3
CRYPTO_ROOT = src/internetce/crypto

# ----------------------------
# Generate crypto files
# ----------------------------

all: $(CRYPTO_ROOT)/mult256.asm

$(CRYPTO_ROOT)/mult256.asm: $(CRYPTO_ROOT)/generate_mult.py
	@$(PYTHON) $(CRYPTO_ROOT)/generate_mult.py $(CRYPTO_ROOT)/mult256.asm 32 32 > /dev/null

autotest:
	@$(MAKE) -C tests/

clean: clean_all

clean_all:
	@git clean -Xfd

# ----------------------------
# Includes
# ----------------------------

include $(shell cedev-config --makefile)
