                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([libtremolo],[0.0])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([-Wall foreign])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
AM_PROG_AS

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h memory.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_STRUCT_TM

case "$host_cpu" in
  x86_64)
    simd_arch=x86_64
    ;;
  i*86 | x86 | ia32)
    simd_arch=i386
    ;;
  arm*)
    simd_arch=arm
    ;;
esac

case "$simd_arch" in
  arm)
    PKG_CHECK_MODULES(MMLOG, mm-log)
    AC_SUBST(MMLOG_CFLAGS)
    AC_SUBST(MMLOG_LIBS)
    CCAS=" $CC"
    AC_SUBST(CCAS)
    
    PKG_CHECK_MODULES(MMCOMMON, mm-common)
    AC_SUBST(MMCOMMON_CFLAGS)
    AC_SUBST(MMCOMMON_LIBS)

    PKG_CHECK_MODULES(GLIB, glib-2.0)
    AC_SUBST(GLIB_CFLAGS)
    AC_SUBST(GLIB_LIBS)
    ;;
  i386)
    ;;
esac

AM_CONDITIONAL([ARMv5], [test "x$simd_arch" = "xarm"])
AM_CONDITIONAL([i386], [test "x$simd_arch" = "xi386"])

AC_CONFIG_FILES([Makefile
tremolo/Makefile
tremolo/libtremolo.pc
])
AC_OUTPUT

CCASFLAGS=" O0"
AC_SUBST(CCASFLAGS)

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup])
