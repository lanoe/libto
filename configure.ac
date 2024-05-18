AC_INIT([libTO], [4.6.4], [])
AC_CONFIG_AUX_DIR([.])
LT_INIT
AM_INIT_AUTOMAKE([subdir-objects])
AM_PATH_PYTHON([3.0])

AC_PROG_CC
AC_PROG_INSTALL

AC_CANONICAL_HOST
case "$host_os" in
mingw* | cygwin* | msys*)
	OS="windows"
	;;
*)
	OS="linux"
	;;
esac
AM_CONDITIONAL(WINDOWS_BUILD, test x$OS = xwindows)

WARN_OPT="-Wall -Wextra -Wstrict-prototypes -Wno-implicit-fallthrough"

EXPORT_CFLAGS=""
AC_DEFUN([SET_EXPORT_CFLAGS], [
	  EXPORT_CFLAGS="$EXPORT_CFLAGS $1"
])

AC_MSG_NOTICE(...................... libTO settings .......................)

AC_CHECK_HEADER(stdint.h, , [AC_DEFINE([HAVE_NO_STDINT_H], [1], [stdint.h missing])])

#
# I2C settings
#

AC_MSG_CHECKING(I2C wrapper)
AC_ARG_VAR(i2c, [select I2C wrapper
		 [default=net_bridge, cp2112, raspberrypi, or linux_generic]])
AS_IF([test x$i2c = x], [I2C="net_bridge"], [I2C="$i2c"])
AM_CONDITIONAL(ENABLE_I2C_CP2112, test x$I2C = xcp2112)
AM_CONDITIONAL(ENABLE_I2C_RASPBERRYPI, test x$I2C = xraspberrypi)
AM_CONDITIONAL(ENABLE_I2C_NET_BRIDGE, test x$I2C = xnet_bridge)
AM_CONDITIONAL(ENABLE_I2C_LINUX_GENERIC, test x$I2C = xlinux_generic)
AC_MSG_RESULT($I2C)
if test x$I2C = xcp2112 && test x$OS = xlinux; then
	PKG_CHECK_MODULES([LIBUDEV], [libudev])
fi
if test x$I2C = xcp2112 || test x$I2C = xraspberrypi \
	|| test x$I2C = xnet_bridge || test x$I2C = xlinux_generic;
then
	AC_DEFINE([TO_I2C_WRAPPER_CONFIG], [1],
		  [wrapper accepts I2C configuration])
fi
if test x$I2C = xlinux_generic;
then
	AC_ARG_VAR(i2c_dev, [Selects which I2C device to use])
	AS_IF([test x$i2c_dev = x], [I2C_DEV="/dev/i2c-0"],
	      [I2C_DEV="$i2c_dev"])
	AC_DEFINE_UNQUOTED([TO_I2C_DEVICE], ["$I2C_DEV"],
			    [wrapper Linux I2C device to use])
	AC_MSG_CHECKING(I2C device)
	AC_MSG_RESULT($I2C_DEV)
fi
if test x$I2C = xnet_bridge;
then
	AC_MSG_CHECKING(I2C net_bridge TLS)
	AC_ARG_ENABLE(i2c_net_bridge_tls,
		      [AS_HELP_STRING([--enable-i2c-net-bridge-tls],
				      [TLS for I2C net_bridge [default=no]])],
		      [], [enable_i2c_net_bridge_tls=no])
	if test x$enable_i2c_net_bridge_tls = xyes; then
		AC_DEFINE([TO_ENABLE_I2C_NET_BRIDGE_TLS], [1],
			  [I2C net_bridge TLS enabled])
		AC_MSG_RESULT(enabled)
	else
		AC_MSG_RESULT(disabled)
	fi
fi
if test x$I2C = xraspberrypi || test x$I2C = xnet_bridge;
then
	AC_DEFINE([TO_I2C_WRAPPER_LAST_COMMAND_DURATION], [1],
		  [wrapper accepts I2C last command duration])
fi
AM_CONDITIONAL(ENABLE_I2C_NET_BRIDGE_TLS,
	       test x$enable_i2c_net_bridge_tls = xyes)

#
# Endianness
#

AC_CHECK_HEADERS([endian.h], [SET_EXPORT_CFLAGS([-DHAVE_ENDIAN_H])])
AC_CHECK_HEADERS([byteswap.h])

AC_ARG_VAR(endian, [select appropriate endianess [big, little]])
AS_IF([test x$endian = x], [], [ENDIAN="$endian"])
if test x$ENDIAN = xbig; then
	AC_DEFINE([TO_BIG_ENDIAN], [1],
		  [endianness accepts ENDIAN configuration])
	AC_MSG_CHECKING(forced endianness)
	AC_MSG_RESULT(big)
fi
if test x$ENDIAN = xlittle; then
	AC_DEFINE([TO_LITTLE_ENDIAN], [1],
		  [endianness accepts ENDIAN configuration])
	AC_MSG_CHECKING(forced endianness)
	AC_MSG_RESULT(little)
fi

#
# Secure link
#

AC_MSG_CHECKING(secure link)
AC_ARG_VAR(seclink, [select secure link mode [default=none, arc4, aeshmac]])
AS_IF([test x$seclink = x], [SECLINK="none"], [SECLINK="$seclink"])
AM_CONDITIONAL(ENABLE_SECLINK_ARC4, test x$SECLINK = xarc4)
AM_CONDITIONAL(ENABLE_SECLINK_AESHMAC, test x$SECLINK = xaeshmac)
AC_SUBST([SECLINK_PROTOCOL], [$SECLINK])
AS_IF([test x$seclink = xarc4], [
       AC_DEFINE([ENABLE_SECLINK_ARC4], [1], [ARC4 secure link protocol])
       AC_SUBST([ENABLE_SECLINK_ARC4], [1])
       ], [])
AS_IF([test x$seclink = xaeshmac], [
       AC_DEFINE([ENABLE_SECLINK_AESHMAC], [1], [AES/HMAC secure link protocol])
       AC_SUBST([ENABLE_SECLINK_AESHMAC], [1])
       ], [])
AC_MSG_RESULT($SECLINK)

#
# Misc. settings
#

AC_MSG_CHECKING(debug)
AC_ARG_ENABLE(debug,
	      [AS_HELP_STRING([--enable-debug], [turns on debug [default=no]])],
	      [], [enable_debug=no])
AM_CONDITIONAL(ENABLE_DEBUG, test x$enable_debug = xyes)
if test x$enable_debug = xyes; then
	CFLAGS="$CFLAGS -ggdb $WARN_OPT -O0"
	AC_DEFINE([TO_DEBUG], [1], [logs enabled])
	AC_MSG_RESULT(enabled)
else
	CFLAGS="$CFLAGS $WARN_OPT"
	AC_MSG_RESULT(disabled)
fi

#
# Features enabling
#

AC_MSG_NOTICE(.............. libTO enabled features summary ...............)

AC_MSG_CHECKING(LoRa)
AC_ARG_ENABLE(lora, [AS_HELP_STRING([--enable-lora],
	      [LoRa [default=no]])],
	      [], [enable_lora=no])
if test x$enable_lora = xno; then
	AC_DEFINE([TO_DISABLE_LORA], [1], [disable LoRa APIs])
	AC_SUBST([DISABLE_LORA], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi
AM_CONDITIONAL(DISABLE_LORA, test x$enable_lora = xno)

AC_MSG_CHECKING(LoRa optimized)
AC_ARG_ENABLE(lora-optimized, [AS_HELP_STRING([--enable-lora-optimized],
	      [LoRa optimized [default=yes]])],
	      [], [enable_lora_optimized=yes])
if test x$enable_lora_optimized = xno; then
	AC_DEFINE([TO_DISABLE_LORA_OPTIMIZED], [1], [disable LoRa optimized APIs])
	AC_SUBST([DISABLE_LORA_OPTIMIZED], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(TLS)
AC_ARG_ENABLE(tls, [AS_HELP_STRING([--enable-tls],
	      [TLS [default=no]])],
	      [], [enable_tls=no])
if test x$enable_tls = xno; then
	AC_DEFINE([TO_DISABLE_TLS], [1], [disable TLS])
	AC_SUBST([DISABLE_TLS], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(TLS optimized)
AC_ARG_ENABLE(tls-optimized, [AS_HELP_STRING([--enable-tls-optimized],
	      [TLS optimized [default=yes]])],
	      [], [enable_tls_optimized=yes])
if test x$enable_tls_optimized = xno; then
	AC_DEFINE([TO_DISABLE_TLS_OPTIMIZED], [1], [disable TLS optimized APIs])
	AC_SUBST([DISABLE_TLS_OPTIMIZED], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(DTLS)
AC_ARG_ENABLE(dtls, [AS_HELP_STRING([--enable-dtls],
	      [DTLS [default=no]])],
	      [], [enable_dtls=no])
if test x$enable_dtls = xyes; then
	AC_DEFINE([TO_ENABLE_DTLS], [1], [enable DTLS])
	AC_SUBST([ENABLE_DTLS], [1])
	AC_MSG_RESULT(enabled)
else
	AC_MSG_RESULT(disabled)
fi

AC_MSG_CHECKING(DTLS retransmission)
AC_ARG_ENABLE(dtls-retransmission, [AS_HELP_STRING([--enable-dtls-retransmission],
	      [DTLS retransmissionmission [default=yes]])],
	      [], [enable_dtls_retransmission=yes])
if test x$enable_dtls_retransmission = xno; then
	AC_DEFINE([TO_DISABLE_DTLS_RETRANSMISSION], [1], [disable DTLS retransmission])
	AC_SUBST([DISABLE_DTLS_RETRANSMISSION], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(TLS helper)
AC_ARG_ENABLE(tls-helper, [AS_HELP_STRING([--enable-tls-helper],
	      [TLS helper [default=yes]])],
	      [], [enable_tls_helper=yes])
if test x$enable_tls_helper = xno; then
	AC_DEFINE([TO_DISABLE_TLS_HELPER], [1], [disable TLS helper])
	AC_SUBST([DISABLE_TLS_HELPER], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi
AM_CONDITIONAL(DISABLE_TLS_HELPER, test x$enable_tls_helper = xno)

AC_MSG_CHECKING(ECIES helper)
AC_ARG_ENABLE(ecies-helper, [AS_HELP_STRING([--enable-ecies-helper],
	      [ECIES helper [default=yes]])],
	      [], [enable_ecies_helper=yes])
if test x$enable_ecies_helper = xno; then
	AC_DEFINE([TO_DISABLE_ECIES_HELPER], [1], [disable ECIES helper])
	AC_SUBST([DISABLE_ECIES_HELPER], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(Secure Element information)
AC_ARG_ENABLE(TO-info, [AS_HELP_STRING([--enable-TO-info],
	      [Secure Element information [default=yes]])],
	      [], [enable_TO_info=yes])
if test x$enable_TO_info = xno; then
	AC_DEFINE([TO_DISABLE_TO_INFO], [1], [disable Secure Element info APIs])
	AC_SUBST([DISABLE_TO_INFO], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(random number generator API)
AC_ARG_ENABLE(get-random, [AS_HELP_STRING([--enable-get-random],
	      [get_random [default=yes]])],
	      [], [enable_get_random=yes])
if test x$enable_get_random = xno; then
	AC_DEFINE([TO_DISABLE_API_GET_RANDOM], [1], [disable get_random API])
	AC_SUBST([DISABLE_API_GET_RANDOM], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(Secure Element status notification PIO configuration)
AC_ARG_ENABLE(status-pio-config, [AS_HELP_STRING([--enable-status-pio-config],
	      [Secure Element status notification PIO configuration
	       [default=yes]])],
	      [], [enable_status_pio_config=yes])
if test x$enable_status_pio_config = xno; then
	AC_DEFINE([TO_DISABLE_STATUS_PIO_CONFIG], [1],
		  [disable Secure Element status notification PIO configuration])
	AC_SUBST([DISABLE_STATUS_PIO_CONFIG], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(certificates management)
AC_ARG_ENABLE(cert, [AS_HELP_STRING([--enable-cert],
	      [Certificates management [default=yes]])],
	      [], [enable_cert=yes])
if test x$enable_cert = xno; then
	AC_DEFINE([TO_DISABLE_CERT_MGMT], [1], [disable certificates APIs])
	AC_SUBST([DISABLE_CERT_MGMT], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(signing tools)
AC_ARG_ENABLE(signing, [AS_HELP_STRING([--enable-signing],
	      [Signature tools [default=yes]])],
	      [], [enable_signing=yes])
if test x$enable_signing = xno; then
	AC_DEFINE([TO_DISABLE_SIGNING], [1], [disable signing APIs])
	AC_SUBST([DISABLE_SIGNING], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(AES encryption)
AC_ARG_ENABLE(aes-encrypt, [AS_HELP_STRING([--enable-aes-encrypt],
	      [AES encryption [default=yes]])],
	      [], [enable_aes_encrypt=yes])
if test x$enable_aes_encrypt = xno; then
	AC_DEFINE([TO_DISABLE_AES_ENCRYPT], [1], [disable AES encrypt APIs])
	AC_SUBST([DISABLE_AES_ENCRYPT], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(secure messaging)
AC_ARG_ENABLE(sec-msg, [AS_HELP_STRING([--enable-sec-msg],
	      [Secure mesaging [default=yes]])],
	      [], [enable_sec_msg=yes])
if test x$enable_sec_msg = xno; then
	AC_DEFINE([TO_DISABLE_SEC_MSG], [1], [disable secure messaging APIs])
	AC_SUBST([DISABLE_SEC_MSG], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(SHA256)
AC_ARG_ENABLE(sha256, [AS_HELP_STRING([--enable-sha256],
	      [SHA256 [default=yes]])],
	      [], [enable_sha256=yes])
if test x$enable_sha256 = xno; then
	AC_DEFINE([TO_DISABLE_SHA256], [1], [disable SHA256 APIs])
	AC_SUBST([DISABLE_SHA256], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(keys management)
AC_ARG_ENABLE(keys, [AS_HELP_STRING([--enable-keys],
	      [Keys management [default=yes]])],
	      [], [enable_keys=yes])
if test x$enable_keys = xno; then
	AC_DEFINE([TO_DISABLE_KEYS_MGMT], [1], [disable keys APIs])
	AC_SUBST([DISABLE_KEYS_MGMT], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(fingerprint)
AC_ARG_ENABLE(fingerprint, [AS_HELP_STRING([--enable-fingerprint],
	      [Fingerprint [default=no]])],
	      [], [enable_fingerprint=no])
if test x$enable_fingerprint = xno; then
	AC_DEFINE([TO_DISABLE_FINGERPRINT], [1], [disable fingerprint APIs])
	AC_SUBST([DISABLE_FINGERPRINT], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(HMAC)
AC_ARG_ENABLE(hmac, [AS_HELP_STRING([--enable-hmac],
	      [HMAC [default=yes]])],
	      [], [enable_hmac=yes])
if test x$enable_hmac = xno; then
	AC_DEFINE([TO_DISABLE_HMAC], [1], [disable HMAC APIs])
	AC_SUBST([DISABLE_HMAC], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(CMAC)
AC_ARG_ENABLE(cmac, [AS_HELP_STRING([--enable-cmac],
	      [CMAC [default=yes]])],
	      [], [enable_cmac=yes])
if test x$enable_cmac = xno; then
	AC_DEFINE([TO_DISABLE_CMAC], [1], [disable CMAC APIs])
	AC_SUBST([DISABLE_CMAC], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

AC_MSG_CHECKING(NVM secure storage)
AC_ARG_ENABLE(nvm, [AS_HELP_STRING([--enable-nvm],
	      [NVM [default=yes]])],
	      [], [enable_nvm=yes])
if test x$enable_nvm = xno; then
	AC_DEFINE([TO_DISABLE_NVM], [1], [disable NVM storage APIs])
	AC_SUBST([DISABLE_NVM], [1])
	AC_MSG_RESULT(disabled)
else
	AC_MSG_RESULT(enabled)
fi

#
# Expert options
#

AC_MSG_CHECKING(internal I/O buffer size)
AC_ARG_VAR(io_buffer_size, [Configure internal I/O buffer size])
if test x$io_buffer_size = x; then
	IO_BUFFER_SIZE="640"
else
	IO_BUFFER_SIZE="$io_buffer_size"
fi
AC_DEFINE_UNQUOTED([TO_LIB_INTERNAL_IO_BUFFER_SIZE], [$IO_BUFFER_SIZE],
		   [internal I/O buffer size])
AC_MSG_RESULT($IO_BUFFER_SIZE bytes)

AC_MSG_CHECKING(command maximum parameters number)
AC_ARG_VAR(cmd_max_params_nb, [Configure command max. parameters number])
if test x$cmd_max_params_nb = x; then
	AC_MSG_RESULT(default)
else
	CMD_MAX_PARAMS="$cmd_max_params_nb"
	AC_DEFINE_UNQUOTED([TO_CMD_MAX_PARAMS], [$CMD_MAX_PARAMS],
			   [command max. parameters number])
	AC_MSG_RESULT($CMD_MAX_PARAMS)
fi

AC_MSG_CHECKING(TLS I/O buffer size)
AC_ARG_VAR(tls_io_buffer_size, [Configure internal TLS I/O buffer size])
if test x$tls_io_buffer_size = x; then
	TLS_IO_BUFFER_SIZE="1024"
else
	TLS_IO_BUFFER_SIZE="$tls_io_buffer_size"
fi
AC_DEFINE_UNQUOTED([TO_LIB_INTERNAL_TLS_IO_BUFFER_SIZE], [$TLS_IO_BUFFER_SIZE],
		   [internal TLS I/O buffer size])
AC_MSG_RESULT($TLS_IO_BUFFER_SIZE bytes)

AC_MSG_CHECKING(TLS flight buffer size)
AC_ARG_VAR(tls_flight_buffer_size, [Configure internal TLS fligth buffer size])
if test x$tls_flight_buffer_size = x; then
	TLS_FLIGHT_BUFFER_SIZE="2048"
else
	TLS_FLIGHT_BUFFER_SIZE="$tls_flight_buffer_size"
fi
AC_DEFINE_UNQUOTED([TO_LIB_INTERNAL_TLS_FLIGHT_BUFFER_SIZE], [$TLS_FLIGHT_BUFFER_SIZE],
		   [internal TLS flight buffer size])
AC_MSG_RESULT($TLS_FLIGHT_BUFFER_SIZE bytes)

#
# Distribution
#

AC_MSG_CHECKING(Distribution profile)
AC_ARG_VAR(dist_profile,
	   [Select distribution profile: full*, mcu, autotools])
AS_IF([test x$dist_profile = x], [DIST_PROFILE="full"],
      [DIST_PROFILE="$dist_profile"])
AM_CONDITIONAL(DIST_PROFILE_FULL,
	       test x$DIST_PROFILE = xfull || test x$DIST_PROFILE = xautotools)
AM_CONDITIONAL(DIST_PROFILE_MCU,
	       test x$DIST_PROFILE = xmcu)
AC_MSG_RESULT($DIST_PROFILE)

#
# Generate outputs
#

AC_MSG_NOTICE(................................................................)
AC_SUBST([EXPORT_CFLAGS], [$EXPORT_CFLAGS])
AC_CONFIG_FILES([Makefile
		include/Makefile
		wrapper/Makefile
		src/Makefile
		examples/Makefile
		pyutils/Makefile
		tools/Makefile
		libTO.pc
		pyutils/config.py])

AC_CONFIG_HEADERS([libTO_config.h])
CFLAGS="$CFLAGS -include libTO_config.h"

AC_CHECK_FILE($srcdir/doc/configure.ac,
	      AC_CONFIG_SUBDIRS([doc])
	      DOC_TOOLCHAIN="yes")
AM_CONDITIONAL(DOC_TOOLCHAIN_PRESENT, test x$DOC_TOOLCHAIN = xyes)

AC_OUTPUT
