if DOC_TOOLCHAIN_PRESENT
DOC_DIR = doc
endif
SUBDIRS = include wrapper src examples pyutils tools $(DOC_DIR)
pcdatadir = $(libdir)/pkgconfig
pcdata_DATA = libTO.pc

# Redist archive
# - no Autotools generated files
# - (MCU) no Autotools files, no Python utils and tools
nodist_include_HEADERS = libTO_config.h
dist-hook:
	rm -rf `find $(distdir) -type f -name Makefile.in`
	cd $(distdir) && rm -rf .git aclocal.m4 *compile config.* configure \
		depcomp install-sh ltmain.sh missing INSTALL
if DIST_PROFILE_MCU
	rm -rf `find $(distdir) -type f -name Makefile.am`
	cd $(distdir) && rm -rf configure.ac libTO.pc.in libTO_config.h.in \
		pyutils tools NEWS
endif
