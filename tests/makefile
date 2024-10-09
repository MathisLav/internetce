# Makefile for the autotests

SUBDIRS := $(shell find . -mindepth 1 -maxdepth 1 -type d)

.PHONY: all autotest $(SUBDIRS)
all: $(SUBDIRS)
autotest: $(SUBDIRS)

$(SUBDIRS):
	@$(MAKE) -C $@ $(MAKECMDGOALS)
