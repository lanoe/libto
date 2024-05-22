bin_PROGRAMS = get_sn ecies hooks
get_sn_CFLAGS = ${CFLAGS} -I${top_srcdir}/include
get_sn_SOURCES = get_sn.c
get_sn_LDADD = ../src/libTO.la ../wrapper/libTO_i2c_wrapper.la
ecies_CFLAGS = ${CFLAGS} -I${top_srcdir}/include -DTO_ECIES_SERVER
ecies_SOURCES = ecies.c ecies_fd.c
ecies_LDADD = ../src/libTO.la ../wrapper/libTO_i2c_wrapper.la
hooks_CFLAGS = ${CFLAGS} -I${top_srcdir}/include
hooks_SOURCES = hooks.c
hooks_LDADD = ../src/libTO.la ../wrapper/libTO_i2c_wrapper.la
if ENABLE_SECLINK_ARC4
bin_PROGRAMS += seclink
seclink_CFLAGS = ${CFLAGS} -I${top_srcdir}/include
seclink_SOURCES = seclink.c
seclink_LDADD = ../src/libTO.la ../wrapper/libTO_i2c_wrapper.la
endif
if ENABLE_SECLINK_AESHMAC
bin_PROGRAMS += seclink
seclink_CFLAGS = ${CFLAGS} -I${top_srcdir}/include
seclink_SOURCES = seclink.c
seclink_LDADD = ../src/libTO.la ../wrapper/libTO_i2c_wrapper.la
endif
if !DISABLE_TLS_HELPER
bin_PROGRAMS += tls_handshake
tls_handshake_CFLAGS = ${CFLAGS} -I${top_srcdir}/include
tls_handshake_SOURCES = tls_handshake.c
tls_handshake_LDADD = ../src/libTO.la ../wrapper/libTO_i2c_wrapper.la
endif

# Redist archive
# - not compiled source files
# - internal header files
EXTRA_DIST = ecies_mbed.cpp
dist_include_HEADERS = ecies.h
if DIST_PROFILE_MCU
dist-hook:
	cd $(distdir) && rm -rf ecies_fd.c
endif
