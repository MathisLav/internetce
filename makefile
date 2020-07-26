# ----------------------------
# Program Options
# ----------------------------

NAME         ?= INTERNET
MAIN_ARGS    ?= NO
COMPRESSED   ?= NO
ARCHIVED     ?= NO
CEDEV		 ?= ../../

# ----------------------------
# Compile Options
# ----------------------------

OPT_MODE     ?= -Oz
EXTRA_CFLAGS ?= -Wall -Wextra

# ----------------------------
# Debug Options
# ----------------------------

OUTPUT_MAP   ?= NO

include $(CEDEV)/include/.makefile
