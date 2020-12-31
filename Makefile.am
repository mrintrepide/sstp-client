ACLOCAL_AMFLAGS = -I m4
SUBDIRS = \
          src/libsstp-log   \
          src/libsstp-api   \
          src/pppd-plugin   \
          include           \
          src

pkgconfigdir   = $(libdir)/pkgconfig
pkgconfig_DATA = sstp-client-1.0.pc

man8_MANS = sstpc.8
EXTRA_DIST = $(man8_MANS) support debian

dist-hook:
	for i in $(EXTRA_DIST) ; do \
        if [ -d $i ] ; then \
            rm -rf `find $(distdir)/$i -type d -name .svn` ; \
        fi ; \
	done
