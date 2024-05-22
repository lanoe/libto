lib_LTLIBRARIES = libTO.la
libTO_la_CFLAGS = ${CFLAGS} -I${top_srcdir}/include
libTO_la_LDFLAGS = -no-undefined -shared -avoid-version
libTO_la_SOURCES = core.c seclink.c api_auth.c api_hash.c api_lora.c api_nvm.c \
		      api_tls.c api_encrypt.c api_keys.c api_mac.c \
		      api_system.c helper_ecies.c helper_tls.c helper_certs.c
if ENABLE_SECLINK_ARC4
libTO_la_SOURCES += seclink_arc4.c crc.c
else
if ENABLE_SECLINK_AESHMAC
libTO_la_LDFLAGS += -ltinycrypt
libTO_la_SOURCES += seclink_aeshmac.c
else
libTO_la_SOURCES += seclink_none.c
endif
endif
libTO_la_LIBADD = ../wrapper/libTO_i2c_wrapper.la

# Redist archive
# - internal header files
dist_include_HEADERS = core.h seclink.h crc.h
# - for MCU, redistribute only the relevant SecLink implementation ('none'
#   implementation is always distributed)
#   Note: nodist_libTO_la_SOURCES can't be used because libTO_la_SOURCES has
#   precendence on it, then using dist-hook
if DIST_PROFILE_MCU
dist-hook:
if !ENABLE_SECLINK_ARC4
	rm $(distdir)/seclink_arc4.c
	rm $(distdir)/crc.*
endif
if !ENABLE_SECLINK_AESHMAC
	rm $(distdir)/seclink_aeshmac.c
endif
endif
