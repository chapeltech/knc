#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.62])
AC_INIT([knc], [1.13], [elric@imrryr.org])
AC_CONFIG_SRCDIR([bin/gssstdio.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([cf])

AM_INIT_AUTOMAKE([foreign 1.10.1])
AM_MAINTAINER_MODE

dnl Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_LIBTOOL

LT_PREREQ([2.2])
LT_INIT([shared static win32-dll])

AM_CONDITIONAL(ENABLE_SHARED, test "$enable_shared" = "yes")

AC_ARG_WITH([gssapi],
	    [AS_HELP_STRING([--with-gssapi=DIR],
			    [choose the GSSAPI/Kerberos installation prefix])],
	    [case "$withval" in
	     yes|no) ;;
	     *) gssdir=$withval ;;
	     esac])

AC_ARG_WITH([gss-dir],
	    [AC_HELP_STRING([--with-gss-dir=<DIR>],
			    [choose the GSSAPI dir])],
	    [gssdir=$withval])

AC_ARG_WITH([krb5-config],
	    [AS_HELP_STRING([--with-krb5-config=PATH],
			    [path to krb5-config])],
	    [case "$withval" in
	     yes|no) AC_MSG_ERROR([--with-krb5-config requires a path]) ;;
	     *) KRB5_CONFIG=$withval
		krb5_config_explicit=yes ;;
	     esac])

AC_ARG_VAR([KRB5_CONFIG], [path to krb5-config])
AC_ARG_VAR([GSSAPI_CFLAGS], [C compiler flags for GSSAPI])
AC_ARG_VAR([GSSAPI_LIBS], [linker flags for GSSAPI])

if test "x$gssdir" != "x" && test ! -d "$gssdir"; then
	AC_MSG_ERROR([GSSAPI prefix does not exist: $gssdir])
fi

if test "x$KRB5_CONFIG" != "x"; then
	krb5_config_explicit=yes
fi

gssapi_pc_modules="krb5-gssapi mit-krb5-gssapi heimdal-gssapi"

if test "x$GSSAPI_LIBS" = "x"; then
	if test "x$KRB5_CONFIG" = "x" &&
	   test "x$gssdir" != "x" &&
	   test -x "$gssdir/bin/krb5-config"; then
		KRB5_CONFIG="$gssdir/bin/krb5-config"
		krb5_config_explicit=yes
	fi

	if test "x$KRB5_CONFIG" = "x" &&
	   test "x$gssdir" = "x"; then
		AC_PATH_PROG([KRB5_CONFIG], [krb5-config], [:])
	fi

	if test "x$KRB5_CONFIG" = "x"; then
		KRB5_CONFIG=:
	fi

	if test "$KRB5_CONFIG" != ":"; then
		AC_MSG_CHECKING([GSSAPI flags from $KRB5_CONFIG])
		if GSSAPI_CFLAGS=`$KRB5_CONFIG --cflags gssapi 2>/dev/null` &&
		   GSSAPI_LIBS=`$KRB5_CONFIG --libs gssapi 2>/dev/null`; then
			AC_MSG_RESULT([yes])
		else
			AC_MSG_RESULT([no])
			if test "x$krb5_config_explicit" = "xyes"; then
				AC_MSG_ERROR([could not get GSSAPI flags from $KRB5_CONFIG])
			fi
			GSSAPI_CFLAGS=
			GSSAPI_LIBS=
		fi
	fi
fi

if test "x$GSSAPI_LIBS" = "x"; then
	AC_PATH_TOOL([PKG_CONFIG], [pkg-config], [:])

	if test "x$gssdir" != "x"; then
		gssapi_pc_path="$gssdir/lib/pkgconfig:$gssdir/lib64/pkgconfig:$gssdir/share/pkgconfig"
	fi

	for gssapi_pc in $gssapi_pc_modules; do
		AC_MSG_CHECKING([for GSSAPI via pkg-config module $gssapi_pc])
		if test "$PKG_CONFIG" != ":" && {
		    if test "x$gssapi_pc_path" != "x"; then
			PKG_CONFIG_LIBDIR="$gssapi_pc_path" PKG_CONFIG_PATH= $PKG_CONFIG --exists "$gssapi_pc"
		    else
			$PKG_CONFIG --exists "$gssapi_pc"
		    fi
		}; then
			if test "x$gssapi_pc_path" != "x"; then
				GSSAPI_CFLAGS=`PKG_CONFIG_LIBDIR="$gssapi_pc_path" PKG_CONFIG_PATH= $PKG_CONFIG --cflags "$gssapi_pc"`
				GSSAPI_LIBS=`PKG_CONFIG_LIBDIR="$gssapi_pc_path" PKG_CONFIG_PATH= $PKG_CONFIG --libs "$gssapi_pc"`
			else
				GSSAPI_CFLAGS=`$PKG_CONFIG --cflags "$gssapi_pc"`
				GSSAPI_LIBS=`$PKG_CONFIG --libs "$gssapi_pc"`
			fi
			AC_MSG_RESULT([yes])
			break
		fi
		AC_MSG_RESULT([no])
	done
fi

if test "x$GSSAPI_LIBS" = "x" &&
   test "x$gssdir" != "x"; then
	GSSAPI_CFLAGS="$GSSAPI_CFLAGS -I$gssdir/include"
	for gssapi_libdir in "$gssdir/lib" "$gssdir/lib64"; do
		if test ! -d "$gssapi_libdir"; then
			continue
		fi

		GSSAPI_LDFLAGS="-L$gssapi_libdir -Wl,-rpath=$gssapi_libdir"
		save_LDFLAGS=$LDFLAGS
		save_LIBS=$LIBS
		LDFLAGS="$LDFLAGS $GSSAPI_LDFLAGS"

		AS_UNSET([ac_cv_search_gss_init_sec_context])
		AC_SEARCH_LIBS([gss_init_sec_context], [gssapi gssapi_krb5],
		    [case "$ac_cv_search_gss_init_sec_context" in
		     "none required") GSSAPI_LIBS="$GSSAPI_LDFLAGS" ;;
		     *) GSSAPI_LIBS="$GSSAPI_LDFLAGS $ac_cv_search_gss_init_sec_context" ;;
		     esac],, [])

		LDFLAGS=$save_LDFLAGS
		LIBS=$save_LIBS

		if test "x$GSSAPI_LIBS" != "x"; then
			break
		fi
	done
fi

if test "x$GSSAPI_LIBS" = "x"; then
	AC_MSG_ERROR([could not determine GSSAPI compiler and linker flags])
fi

AC_SUBST([GSSAPI_CFLAGS])
AC_SUBST([GSSAPI_LIBS])

save_CPPFLAGS=$CPPFLAGS
save_LIBS=$LIBS
CPPFLAGS="$CPPFLAGS $GSSAPI_CFLAGS"
LIBS="$GSSAPI_LIBS $LIBS"

AC_CHECK_HEADERS([gssapi.h gssapi/gssapi.h gssapi/gssapi_krb5.h])

AC_CHECK_FUNC([gss_init_sec_context],,
	      [AC_MSG_ERROR([could not link GSSAPI])])

AC_CHECK_FUNCS([gss_oid_to_str gss_name_to_oid gss_oid_to_name])

CPPFLAGS=$save_CPPFLAGS
LIBS=$save_LIBS

#
# We only enable warnings if --enable-developer is specified.

AC_ARG_ENABLE(developer,
	AS_HELP_STRING([--enable-developer],
			[enable developer warnings and experimental code]))
AM_CONDITIONAL(DEVELOPER_MODE, test "X$enable_developer" = Xyes)

if test "X$enable_developer" = Xyes; then
	WFLAGS="-Werror"
	WFLAGS="$WFLAGS -Wall"
	WFLAGS="$WFLAGS -Wextra"
	WFLAGS="$WFLAGS -Wstrict-prototypes"
	WFLAGS="$WFLAGS -Wmissing-prototypes"
	WFLAGS="$WFLAGS -Wpointer-arith"
	WFLAGS="$WFLAGS -Wno-traditional"
	WFLAGS="$WFLAGS -Wreturn-type"
	WFLAGS="$WFLAGS -Wswitch"
	WFLAGS="$WFLAGS -Wno-shadow"
	WFLAGS="$WFLAGS -Wcast-qual"
	WFLAGS="$WFLAGS -Wwrite-strings"
	WFLAGS="$WFLAGS -Wno-unused-parameter"
	WFLAGS="$WFLAGS -Wsign-compare"
fi

AC_SUBST(WFLAGS)dnl

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK

AC_CONFIG_FILES([Makefile bin/Makefile lib/Makefile test/Makefile])
AC_OUTPUT
