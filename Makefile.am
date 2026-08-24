
ACLOCAL_AMFLAGS = -I cf

SUBDIRS  = bin lib test

EXTRA_DIST = \
	contrib/systemd/README \
	contrib/systemd/knc-rsync.service \
	contrib/systemd/knc-rsync.socket

.PHONY: check-knc-exec
check-knc-exec:
	$(MAKE) all
	$(MAKE) -C test check-knc-exec
