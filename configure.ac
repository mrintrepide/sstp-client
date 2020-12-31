AC_PREREQ([2.67])
AC_INIT([sstp-client], 
        [1.0], 
        [http://sourceforge.net/projects/sstp-client])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AC_LANG(C)
AC_CONFIG_SRCDIR([src/sstp-client.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Check for libevent, macro doesn't save result for LIBS
AX_CHECK_LIBRARY([LIBEVENT], [event.h], [event], [],
        [AC_MSG_ERROR([Required library libevent not found])])
if test "x$ax_cv_have_LIBEVENT" = xyes; then
    AC_CHECK_LIB([event], [event_init])
fi


# Check for OpenSSL
AX_CHECK_OPENSSL([], 
    [AC_MSG_ERROR([OpenSSL not found, Hint: apt-get install libssl-dev])])
LIBS="$LIBS $OPENSSL_LIBS"
CFLAGS="$CFLAGS $OPENSSL_INCLUDES"
LDFLAGS="$LD_FLAGS $OPENSSL_LDFLAGS"


# Check for openpty
AC_CHECK_LIB([util], [openpty])


# Check to see if we enabled PPP plug-in support (default:yes)
AC_ARG_ENABLE(pppd-plugin, 
    AC_HELP_STRING([--enable-pppd-plugin], [enable PPP Plugin support]),
    [enable_ppp_plugin=${enableval}], [enable_ppp_plugin=yes])
if (test "${enable_ppp_plugin}" = "yes"); then
    AC_CHECK_HEADER(pppd/pppd.h,,
            AC_MSG_ERROR(pppd.h missing, Hint: apt-get install ppp-dev))
    AC_DEFINE(WITH_PPP, 1, [Define if you have PPP support])
fi


# Check to see if the plugin directory was set
AM_CONDITIONAL(WITH_PPP, test "${enable_ppp_plugin}" = "yes")
AC_ARG_WITH([pppd-plugin-dir], 
    AS_HELP_STRING([--with-pppd-plugin-dir=DIR], [path to the pppd plugins directory]))
if test -n "$with_pppd_plugin_dir" ; then
    PPPD_PLUGIN_DIR="$with_pppd_plugin_dir"
else
    PPPD_PLUGIN_DIR="${libdir}/pppd/2.4.5"
fi
AC_SUBST(PPPD_PLUGIN_DIR)


# Checks for header files.
AC_CHECK_HEADERS([  \
    arpa/inet.h     \
    fcntl.h         \
    netdb.h         \
    paths.h         \
    stdint.h        \
    stdlib.h        \
    string.h        \
    syslog.h        \
    sys/types.h     \
    sys/socket.h    \
    unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([    \
    dup2            \
    gethostname     \
    localtime_r     \
    memmove         \
    memset          \
    socket          \
    strcasecmp      \
    strchr          \
    strdup          \
    strrchr         \
    strstr          \
    strtoul         \
    strtoull])
    
AC_CONFIG_FILES([Makefile
                 sstp-client-1.0.pc
                 src/Makefile
                 include/Makefile
                 src/libsstp-log/Makefile
                 src/libsstp-api/Makefile
                 src/pppd-plugin/Makefile])
AC_OUTPUT

echo "
$PACKAGE_NAME version $PACKAGE_VERSION
   Prefix.........: $prefix
   Using OpenSSL..: $OPENSSL_INCLUDES $OPENSSL_LDFLAGS $OPENSSL_LIBS
   Using Event....: $LIBEVENT_INCLUDE $LIBEVENT_LIBS
   C Compiler.....: $CC $CFLAGS
   Linker.........: $LD $LDFLAGS $LIBS
   "

