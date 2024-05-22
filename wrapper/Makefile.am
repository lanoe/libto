lib_LTLIBRARIES = libTO_i2c_wrapper.la
libTO_i2c_wrapper_la_CFLAGS = ${CFLAGS} -I${top_srcdir}/include
libTO_i2c_wrapper_la_LDFLAGS = -no-undefined -shared -avoid-version
if ENABLE_I2C_CP2112
if WINDOWS_BUILD
libTO_i2c_wrapper_la_SOURCES = cp2112-win.c
libTO_i2c_wrapper_la_CFLAGS += -I${top_srcdir}/wrapper/cp2112-win-res
libTO_i2c_wrapper_la_LDFLAGS += -L${top_srcdir}/wrapper/cp2112-win-res \
			     -lSLABHIDDevice -lSLABHIDtoSMBus
cp2112bindir = $(libdir)
cp2112bin_SCRIPTS = cp2112-win-res/SLABHIDDevice.dll \
		    cp2112-win-res/SLABHIDtoSMBus.dll \
		    cp2112-win-res/libSLABHIDDevice.dll \
		    cp2112-win-res/libSLABHIDtoSMBus.dll
else
libTO_i2c_wrapper_la_SOURCES = cp2112.c
libTO_i2c_wrapper_la_CFLAGS += ${LIBUDEV_CFLAGS}
libTO_i2c_wrapper_la_LDFLAGS += ${LIBUDEV_LIBS}
endif # WINDOWS_BUILD
endif # ENABLE_I2C_CP2112
if ENABLE_I2C_RASPBERRYPI
libTO_i2c_wrapper_la_SOURCES = raspberrypi/rpi_gpio.c raspberrypi.c
libTO_i2c_wrapper_la_CFLAGS += -I${top_srcdir}/wrapper/raspberrypi
endif
if ENABLE_I2C_NET_BRIDGE
libTO_i2c_wrapper_la_SOURCES = net_bridge.c
if ENABLE_I2C_NET_BRIDGE_TLS
libTO_i2c_wrapper_la_LDFLAGS += -lmbedtls -lmbedcrypto -lmbedx509
endif
if WINDOWS_BUILD
libTO_i2c_wrapper_la_LDFLAGS += -lws2_32
endif
endif
if ENABLE_I2C_LINUX_GENERIC
libTO_i2c_wrapper_la_SOURCES = linux_generic.c
endif

# Redist archive
# - add MCU wrappers sources
# - (Full) add CP2112 windows resources
# - (MCU) Remove non-MCU wrappers
EXTRA_DIST = mbed_os.cpp stm32_hal.c
if DIST_PROFILE_FULL
EXTRA_DIST += cp2112-win-res
dist_include_HEADERS = raspberrypi/rpi_gpio.h
endif
if DIST_PROFILE_MCU
dist-hook:
	cd $(distdir) && rm -rf cp2112.c cp2112-win.c linux_generic.c \
		net_bridge.c raspberrypi*
endif
