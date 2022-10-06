# ----------------------------
# Makefile Options
# ----------------------------

NAME = INTERNET
COMPRESSED = NO
ARCHIVED = NO

# In the v10.2 of the toolchain, the optimization parameters don't work
CFLAGS = -Wall -Wextra #-Oz
CXXFLAGS = -Wall -Wextra #-Oz

# ----------------------------

include $(shell cedev-config --makefile)

