#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([libfb],[2.0.0],[bcarrington@red-fone.com])
AC_CONFIG_SRCDIR([libfb/fb_lib.c])
AC_CONFIG_HEADER([libfb/fb_config.h])
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_RANLIB

# Checks for header files, some of these are duplicated but that doesn't break anything
AC_HEADER_STDC

# fb_lib.h
AC_CHECK_HEADERS([string.h stdbool.h inttypes.h time.h sys/time.h arpa/inet.h netinet/in.h libnet.h pcap.h stdio.h])

# fb_lib.c
AC_CHECK_HEADERS([stdlib.h unistd.h time.h])

# poll.c
AC_CHECK_HEADERS([poll.h])

# ethernet.c
AC_CHECK_HEADERS([sys/ioctl.h netpacket/packet.h net/ethernet.h time.h stdlib.h])
AC_CHECK_HEADERS([sys/socket.h net/if.h], [], [],
			       [[ #ifdef HAVE_SYS_SOCKET_H
				  # include <sys/socket.h>
				  #endif
			       ]])
# utility.c
AC_CHECK_HEADERS([time.h stdlib.h])

# readthread (currently not used )
# AC_CHECK_HEADERS([pthread.h])


# Check for libraries that we depend on
LIBNET=
	AC_CHECK_LIB([net], [libnet_write],
		     [AC_SUBST([LIBNET], ["-lnet"])
		     AC_DEFINE([HAVE_LIBNET], [1], [Define if you have libnet])
		     ],
		     AC_MSG_FAILURE([test for libnet failed (required)]))


LIBPCAP=
	AC_CHECK_LIB([pcap], [pcap_next],
		     [AC_SUBST([LIBPCAP], ["-lpcap"])
		     AC_DEFINE([HAVE_LIBPCAP], [1], [Define if you have libpcap])
		     ],
		     AC_MSG_FAILURE([test for libpcap failed (required)]))


# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE

AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

AC_STRUCT_TM

AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T



# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_CHECK_FUNCS([memset socket strtol gethostbyaddr gethostbyname])

AC_OUTPUT
