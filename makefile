# ----------------------------
# Program Options
# ----------------------------

NAME         ?= INTERNET
#ICON         ?= icon.png
#DESCRIPTION  ?= "Browse the internet like a boss 8)"
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
