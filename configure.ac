dnl SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

dnl Process this file with autoconf to produce a configure script.
dnl Configure input file for Libabigail.                     -*-autoconf-*-
dnl
dnl Copyright (C) 2013-2025 Red Hat, Inc.
dnl Author: Dodji Seketeli
dnl
dnl This file is part of Libabigail.
dnl

dnl Libabigail version number is handled here with the major and minor
dnl version numbers.
m4_define([version_major],   [2])
m4_define([version_minor],   [8])

dnl Below are the numbers to handle libabigail.so's versionning
dnl following the libtool's versionning scheme to handle shared
dnl libraries' compatibility.
dnl
dnl Below are the rules to follow to update the three numbers
dnl (LIBABIGAIL_SO_CURRENT, LIBABIGAIL_SO_REVISION and LIBABIGAIL_SO_AGE):
dnl
dnl 1. If the library source code has changed at all since the last
dnl    update, then increment LIBABIGAIL_SO_REVISION ('C:R:A' becomes
dnl    'C:R+1:A').
dnl 
dnl 2. If any interfaces have been added, removed, or changed since
dnl    the last update, increment LIBABIGAIL_SO_CURRENT, and set
dnl    LIBABIGAIL_REVISION to 0.
dnl 
dnl 3. If any interfaces have been added since the last public release,
dnl    then increment LIBABIGAIL_SO_AGE.
dnl 
dnl 4. If any interfaces have been removed or changed since the last
dnl     public release, then set LIBABIGAIL_SO_AGE to 0.
m4_define([libabigail_so_current],  [7])
m4_define([libabigail_so_revision], [0])
m4_define([libabigail_so_age],      [0])

AC_INIT([libabigail],
	[version_major.version_minor],
	[http://sourceware.org/bugzilla],
	[libabigail],
	[http://sourceware.org/libabigail])

AC_PREREQ([2.63])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([README])
AC_CONFIG_MACRO_DIR([m4])

dnl Include some autoconf macros to check for python modules.
dnl
dnl These macros are coming from the autoconf archive at
dnl http://www.gnu.org/software/autoconf-archive

dnl This one is for the AX_CHECK_PYTHON_MODULES() macro.
m4_include([autoconf-archive/ax_check_python_modules.m4])

dnl These two below are for the AX_PROG_PYTHON_VERSION() module.
m4_include([autoconf-archive/ax_compare_version.m4])
m4_include([autoconf-archive/ax_prog_python_version.m4])

dnl This one is to be able to run "make check-valgrind"
dnl and have unit tests run under  der Valgrind.
m4_include([autoconf-archive/ax_valgrind_check.m4])

AM_INIT_AUTOMAKE([1.11.1 foreign subdir-objects dist-xz tar-ustar parallel-tests])
AM_MAINTAINER_MODE([enable])

AM_SILENT_RULES([yes])

dnl By default, the tar command used by 'make dist and make distcheck'
dnl is "tar --format=ustar -chf" where the "-h" option actually
dnl follows symbolic links. So it copies the targets of the symlinks
dnl that are present in the tarball.  Unfortunately, there are
dnl tests that need to keep the symlinks intact in the tarball.
dnl
dnl So let's define a tar command without the -h option.

am__tar='tar --format=ustar -cf - "$$tardir"'

VERSION_MAJOR=version_major
VERSION_MINOR=version_minor
VERSION_REVISION=0
dnl The major version number of the abixml version should be changed
dnl only if a new version of libabigail cannot read an old version of
dnl abixml.  This should be very rare and should be avoided as much as
dnl possible.
ABIXML_VERSION_MAJOR=2
dnl The minor version number of the abixml version should be changed
dnl each time and old version of libabigail can't handle a new version
dnl of abixml.  Note however that when the major version number is
dnl changed, the minor version number should be set to zero.
ABIXML_VERSION_MINOR=4
LIBABIGAIL_SO_CURRENT=libabigail_so_current
LIBABIGAIL_SO_REVISION=libabigail_so_revision
LIBABIGAIL_SO_AGE=libabigail_so_age

AC_SUBST(VERSION_MAJOR)
AC_SUBST(VERSION_MINOR)
AC_SUBST(VERSION_REVISION)
AC_SUBST(ABIXML_VERSION_MAJOR)
AC_SUBST(ABIXML_VERSION_MINOR)
AC_SUBST(LIBABIGAIL_SO_CURRENT)
AC_SUBST(LIBABIGAIL_SO_REVISION)
AC_SUBST(LIBABIGAIL_SO_AGE)

dnl This VERSION_SUFFIX environment variable is to allow appending
dnl arbitrary text to the libabigail version string representation.
dnl That is useful to identify custom versions of the library
dnl (e.g. development versions or versions of a particular origin).
dnl
dnl The feature can be enabled by passing VERSION_SUFFIX to `configure`,
dnl e.g.
dnl
dnl   $ configure VERSION_SUFFIX="-dev"
AC_SUBST(VERSION_SUFFIX)

AC_ARG_ENABLE(rpm,
	      AS_HELP_STRING([--enable-rpm=yes|no|auto],
			     [enable the support of rpm in abipkgdiff (default is auto)]),
	      ENABLE_RPM=$enableval,
	      ENABLE_RPM=auto)

# '--enable-rpm415' option name preserved for backwards compatibility.
AC_ARG_ENABLE(rpm415,
	      AS_HELP_STRING([--enable-rpm415=yes|no|auto],
			     [enable rpm/zstd in abipkgdiff testing (default is auto)]),
	      ENABLE_RPM_ZSTD=$enableval,
	      ENABLE_RPM_ZSTD=auto)

AC_ARG_ENABLE(debug-self-comparison,
	      AS_HELP_STRING([--enable-debug-self-comparison=yes|no],
			     [enable debugging of self comparison with 'abidw --debug-abidiff'(default is no)]),
	      ENABLE_DEBUG_SELF_COMPARISON=$enableval,
	      ENABLE_DEBUG_SELF_COMPARISON=no)

AC_ARG_ENABLE(debug-type-canonicalization,
	      AS_HELP_STRING([--enable-debug-type-canonicalization=yes|no],
			     [enable debugging of type canonicalization 'abidw --debug-tc'(default is no)]),
	      ENABLE_DEBUG_TYPE_CANONICALIZATION=$enableval,
	      ENABLE_DEBUG_TYPE_CANONICALIZATION=no)


AC_ARG_ENABLE(show-type-use-in-abilint,
	      AS_HELP_STRING([--enable-show-type-use-in-abilint=yes|no],
			     ['enable abilint --show-type-use'(default is no)]),
	      ENABLE_SHOW_TYPE_USE_IN_ABILINT=$enableval,
	      ENABLE_SHOW_TYPE_USE_IN_ABILINT=no)

AC_ARG_ENABLE(deb,
	      AS_HELP_STRING([--enable-deb=yes|no|auto],
			     [enable the support of deb in abipkgdiff (default is auto)]),
	      ENABLE_DEB=$enableval,
	      ENABLE_DEB=auto)

AC_ARG_ENABLE(tar,
	      AS_HELP_STRING([--enable-tar=yes|no|auto],
			     [enable the support of GNU tar archives in abipkgdiff (default is auto)]),
	      ENABLE_TAR=$enableval,
	      ENABLE_TAR=auto)

AC_ARG_ENABLE(apidoc,
	      AS_HELP_STRING([--enable-apidoc=yes|no|auto],
			     [enable generation of the apidoc in html]),
	      ENABLE_APIDOC=$enableval,
	      ENABLE_APIDOC=auto)

AC_ARG_ENABLE(manual,
	      AS_HELP_STRING([--enable-manual=yes|no|auto],
			     [enable generation of the manual in html]),
	      ENABLE_MANUAL=$enableval,
	      ENABLE_MANUAL=auto)

AC_ARG_ENABLE([bash-completion],
	      AS_HELP_STRING([--enable-bash-completion=yes|no|auto],
			     [enable using completion files for tools]),
	      ENABLE_BASH_COMPLETION=$enableval,
	      ENABLE_BASH_COMPLETION=auto)

AC_ARG_ENABLE([fedabipkgdiff],
	      AS_HELP_STRING([--enable-fedabipkgdiff=yes|no|auto],
			     [enable the fedabipkgdiff tool]),
	      ENABLE_FEDABIPKGDIFF=$enableval,
	      ENABLE_FEDABIPKGDIFF=auto)

AC_ARG_ENABLE(abidb,
	      AS_HELP_STRING([--enable-abidb=yes|no|auto],
			     [enable the support of the abidb tool (default is auto)]),
	      ENABLE_ABIDB=$enableval,
	      ENABLE_ABIDB=auto)

AC_ARG_ENABLE([python3],
	      AS_HELP_STRING([--enable-python3=yes|no|auto],
			     [enable running abigail tools with python3 (default is auto)]),
	      ENABLE_PYTHON3=$enableval,
	      ENABLE_PYTHON3=auto)

AC_ARG_ENABLE(asan,
	      AS_HELP_STRING([--enable-asan=yes|no],
			     [enable the support of building with -fsanitize=address)]),
	      ENABLE_ASAN=$enableval,
	      ENABLE_ASAN=no)

AC_ARG_ENABLE(msan,
	      AS_HELP_STRING([--enable-msan=yes|no],
			     [enable the support of building with -fsanitize=memory)]),
	      ENABLE_MSAN=$enableval,
	      ENABLE_MSAN=no)

AC_ARG_ENABLE(tsan,
	      AS_HELP_STRING([--enable-tsan=yes|no],
			     [enable the support of building with -fsanitize=thread)]),
	      ENABLE_TSAN=$enableval,
	      ENABLE_TSAN=no)

AC_ARG_ENABLE(ubsan,
	      AS_HELP_STRING([--enable-ubsan=yes|no],
			     [enable the support of building with -fsanitize=undefined)]),
	      ENABLE_UBSAN=$enableval,
	      ENABLE_UBSAN=no)

dnl check if user has enabled CTF code
AC_ARG_ENABLE(ctf,
	      AS_HELP_STRING([--enable-ctf=yes|no],
			     [disable support of ctf files)]),
	      ENABLE_CTF=$enableval,
	      ENABLE_CTF=auto)

dnl check if user has enabled BTF code
AC_ARG_ENABLE(btf,
	      AS_HELP_STRING([--enable-btf=yes|no],
			     [disable support of btf files)]),
	      ENABLE_BTF=$enableval,
	      ENABLE_BTF=auto)

ENABLE_BIG_TESTS=no
AC_ARG_ENABLE(big-tests,
	      AS_HELP_STRING([--enable-big-tests=yes|no],
			     [enable the support of libabigail big tests (in the big-tests subdir)]),
	      ENABLE_BIG_TESTS=$enableval,
	      ENABLE_BIG_TESTS=no)


ENABLE_INLINED_XXHASH=no
AC_ARG_ENABLE(inlined-xxhash,
	      AS_HELP_STRING([--enable-inlined-xxhash=yes|no],
			     [enable the support the inlined-only version of the xxhash library]),
	      ENABLE_INLINED_XXHASH=$enableval,
	      ENABLE_INLINED_XXHASH=no)

WITH_DW_LIBS_PATH=auto
AC_ARG_WITH(libdw,
	    AS_HELP_STRING([--with-libdw=/path/to/libdw-library/prefix],
			   [Set the path to the libdw library prefix]),
	    WITH_DW_LIBS_PATH=$withval,
	    WITH_DW_LIBS_PATH=auto)

WITH_ELF_LIBS_PATH=auto
AC_ARG_WITH(libelf,
	    AS_HELP_STRING([--with-libelf=/path/to/libelf-library/prefix],
			   [Set the path to the libelf library prefix]),
	    WITH_ELF_LIBS_PATH=$withval,
	    WITH_ELF_LIBS_PATH=auto)

WITH_LIBXML2_PATH=auto
AC_ARG_WITH(libxml2,
	    AS_HELP_STRING([--with-libxml2=/path/to/libxml2-library/prefix],
			   [Set the path to the libxml2 library prefix]),
	    WITH_LIBXML2_PATH=$withval,
	    WITH_LIBXML2_PATH=auto)

dnl *************************************************
dnl check for dependencies
dnl *************************************************

AC_PROG_CXX
AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_INSTALL

LT_PREREQ([2.2])
LT_INIT

AC_LANG([C++])
AC_LANG_COMPILER_REQUIRE

dnl
dnl We use C++14.  It has been the default in G++ since GCC 6.  In el8
dnl (that we still support), we do have GCC 8.x with c++14 as the
dnl default, still.
dnl
CXX_STANDARD=c++14

dnl
dnl check if the c++ compiler has support __attribute__((visibility("hidden")))
dnl
AC_MSG_NOTICE([checking for GCC visibility attribute support ...])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
struct __attribute__((visibility("hidden"))) Foo
{
  int m0;

  Foo()
   : m0()
  {}
};
                 ]])],
		 [SUPPORTS_GCC_VISIBILITY_ATTRIBUTE=yes],
		 [SUPPORTS_GCC_VISIBILITY_ATTRIBUTE=no]
)

if test x$SUPPORTS_GCC_VISIBILITY_ATTRIBUTE = xyes; then
   AC_MSG_NOTICE([GCC visibility attribute is supported])
   AC_DEFINE([HAS_GCC_VISIBILITY_ATTRIBUTE], 1,
   	     [Defined if the compiler supports the attribution visibility syntax __attribute__((visibility("hidden")))])
   VISIBILITY_FLAGS="-fvisibility=hidden"
else
   AC_MSG_NOTICE([GCC visibility attribute is not supported])
   VISIBILITY_FLAGS=
fi

AC_SUBST(VISIBILITY_FLAGS)

dnl glibc and BSD include fts into their libc, but musl does not so
dnl check if we need to explicitly link to the standalone musl-fts.
AC_SEARCH_LIBS([fts_open], [fts])

dnl Older glibc had a broken fts that didn't work with Large File Systems.
dnl We want the version that can handler LFS, but include workaround if we
dnl get a bad one. Add define to CFLAGS (not AC_DEFINE it) since we need to
dnl check it before including config.h (which might define _FILE_OFFSET_BITS).
AC_CACHE_CHECK([whether including fts.h with _FILE_OFFSET_BITS set breaks], ac_cv_bad_fts,
  [AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
	#define _FILE_OFFSET_BITS 64
	#include <fts.h>
	]])],
		     ac_cv_bad_fts=no, ac_cv_bad_fts=yes)])
AS_IF([test "x$ac_cv_bad_fts" = "xyes"],
      [CFLAGS="$CFLAGS -DBAD_FTS=1",
       CXXFLAGS="$CXXFLAGS -DBAD_FTS=1"])


dnl Check for dependency: libelf and libdw (elfutils).  Note that we
dnl need to use at least elfutils 0.159 but at that time elfutils
dnl didnt have pkgconfig capabilities to easily query for its version.
dnl Those were added in version 0.165.

dnl look for libelf
ELF_LIBS_VERSION=0.165
SAVED_PKG_CONFIG_PATH=$PKG_CONFIG_PATH
if test $WITH_ELF_LIBS_PATH != xauto; then
  export PKG_CONFIG_PATH="$WITH_ELF_LIBS_PATH/lib/pkgconfig:$PKG_CONFIG_PATH"
fi

AC_MSG_NOTICE([used PKG_CONFIG_PATH=$PKG_CONFIG_PATH to check for libelf]);
PKG_CHECK_MODULES(ELF, libelf >= $ELF_LIBS_VERSION)
if test $WITH_ELF_LIBS_PATH != xauto; then
  PKG_CONFIG_PATH=$SAVED_PKG_CONFIG_PATH
fi

dnl Look for libdw
DW_LIBS_VERSION=0.165
SAVED_PKG_CONFIG_PATH=$PKG_CONFIG_PATH
if test $WITH_DW_LIBS_PATH != xauto; then
  export PKG_CONFIG_PATH="$WITH_DW_LIBS_PATH/lib/pkgconfig:$PKG_CONFIG_PATH"
fi

AC_MSG_NOTICE([used PKG_CONFIG_PATH=$PKG_CONFIG_PATH to check for libdw]);
PKG_CHECK_MODULES(DW, libdw >= $DW_LIBS_VERSION)
if test $WITH_DW_LIBS_PATH != xauto; then
  PKG_CONFIG_PATH=$SAVED_PKG_CONFIG_PATH
fi


dnl Allow users to compile with the NDEBUG macro defined,
dnl meaning they are compiling in a mode where the
dnl assert call does nothing.  With the directive below,
dnl users just need to pass the --disable-assert
dnl option to configure.
AC_HEADER_ASSERT

AC_SUBST(DW_LIBS)
AC_SUBST(DW_CFLAGS)
AC_SUBST([ELF_LIBS])
AC_SUBST([ELF_CFLAGS])

dnl check for libctf presence if CTF code has been enabled by command line
dnl argument, and then define CTF flag (to build CTF file code) if libctf is
dnl found on the system
if test x$ENABLE_CTF != xno; then
  CTF_HEADER=no
  AC_CHECK_HEADER([ctf.h],
		  [CTF_HEADER=yes],
		  [AC_MSG_NOTICE([could not find ctf.h, going to disable CTF support])])
  LIBCTF=
  if test x$CTF_HEADER = xyes; then
       AC_CHECK_LIB(ctf, ctf_open, [LIBCTF=yes], [LIBCTF=no])
  fi

  if test x$LIBCTF = xyes; then
    dnl Test if struct struct ctf_dict_t is present.
    AC_LANG(C++)
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <ctf-api.h>
					ctf_dict_t* c;]])],
		      [HAVE_CTF_DICT_T=yes],
		      [HAVE_CTF_DICT_T=no])

    if test x$HAVE_CTF_DICT_T = xyes; then
      AC_DEFINE([HAVE_CTF_DICT_T], 1, [struct ctf_dict_t is present])
    fi
  fi

  if test x$HAVE_CTF_DICT_T = xno; then
     AC_MSG_NOTICE([Some needed data structures are missing from ctf-api.h. Disabling CTF support.])
     LIBCTF=no
  fi

  if test x$LIBCTF = xyes; then
    AC_MSG_NOTICE([CTF support enabled])
    AC_DEFINE([WITH_CTF], 1,
	     [Defined if user enables and system has the libctf library])
    CTF_LIBS=-lctf
    ENABLE_CTF=yes
  else
    AC_MSG_NOTICE([no suitable libctf found, CTF support was disabled])
    ENABLE_CTF=no
  fi
fi

dnl configure BTF usage
BPF_LIBS=
if test x$ENABLE_BTF != xno; then
  AC_CHECK_HEADER([bpf/btf.h],
		  [HAS_BTF_HEADERS=yes],
		  [AC_MSG_NOTICE([could not find bpf/btf.h])])
  if test x$HAS_BTF_HEADERS = xyes; then
    AC_MSG_NOTICE([found BTF header file so enabling BTF support])
    ENABLE_BTF=yes
    AC_DEFINE([WITH_BTF], 1,
	     [Defined if user enabled BTF usage])
    BPF_LIBS=-lbpf
  else
    AC_MSG_NOTICE([BTF support was disabled])
    ENABLE_BTF=no
  fi

dnl Test if various functions and structs are present.

  if test x$ENABLE_BTF = xyes; then
    dnl Test if struct btf_enum64 is present.
    AC_CHECK_TYPE([struct btf_enum64],
    		  [HAVE_BTF_ENUM64=yes],
		  [HAVE_BTF_ENUM64=no],
		  [#include <bpf/btf.h>])

    if test x$HAVE_BTF_ENUM64 = xyes; then
      AC_DEFINE([WITH_BTF_ENUM64], 1, [struct btf_enum64 is present])
    fi

    dnl Test if btf__get_nr_types is present
    AC_CHECK_DECL([btf__get_nr_types],
		  [HAVE_BTF__GET_NR_TYPES=yes],
		  [HAVE_BTF__GET_NR_TYPES=no],
		  [#include <bpf/btf.h>])

    if test x$HAVE_BTF__GET_NR_TYPES = xyes; then
       AC_DEFINE(WITH_BTF__GET_NR_TYPES, 1, [The function btf__get_nr_types is present])
    fi

    dnl Test if btf__type_cnt is present
    AC_CHECK_DECL([btf__type_cnt],
		  [HAVE_BTF__TYPE_CNT=yes],
		  [HAVE_BTF__TYPE_CNT=no],
		  [#include <bpf/btf.h>])
    if test x$HAVE_BTF__TYPE_CNT = xyes; then
       AC_DEFINE(WITH_BTF__TYPE_CNT, 1, [The function btf__type_cnt is present])
    fi

    dnl Test if BTF_KIND_TYPE_TAG exists
    AC_CHECK_DECL([int kind = BTF_KIND_TYPE_TAG],
    		  [HAVE_BTF_KIND_TYPE_TAG=yes],
		  [HAVE_BTF_KIND_TYPE_TAG=no],
		  [#include <bpf/btf.h>])
    if test x$HAVE_BTF_KIND_TYPE_TAG = xyes; then
       AC_DEFINE([WITH_BTF_KIND_TYPE_TAG], 1,
       [The BTF_KIND_TYPE_TAG enumerator is present])
    fi

    dnl Test if BTF_KIND_DECL_TAG exists
    AC_CHECK_DECL([int kind = BTF_KIND_DECL_TAG],
    		  [HAVE_BTF_KIND_DECL_TAG=yes],
		  [HAVE_BTF_KIND_DECL_TAG=no],
		  [#include <bpf/btf.h>])
    if test x$HAVE_BTF_KIND_DECL_TAG = xyes; then
       AC_DEFINE([WITH_BTF_KIND_DECL_TAG], 1,
       [The BTF_KIND_DECL_TAG enumerator is present])
    fi
  fi
fi

if test x$ENABLE_BIG_TESTS = xyes; then
  AC_MSG_NOTICE([looking for $srcdir/big-tests ...]);
  if test -d $srcdir/big-tests -o -L $srcdir/big-tests; then
     AC_CONFIG_COMMANDS([create-big-tests-build-dir-and-configure],
			[AC_MSG_NOTICE([Found $srcdir/big-tests!])
			 cd $ac_abs_top_srcdir/big-tests
			 autoreconf -i
			 cd $ac_abs_top_builddir
			 test -d big-tests || mkdir big-tests
			 cd big-tests
			 CTF_OPTS=
			 BTF_OPTS=
			 if test x$CTF_ENABLED = xyes; then CTF_OPTS="--enable-ctf"; fi;
			 if test x$BTF_ENABLED = xyes; then BTF_OPTS="--enable-btf"; fi;
			 AC_MSG_NOTICE([configuring $srcdir/big-tests --with-libabigail-tools-dir=$ac_abs_top_builddir/tools --with-libabigail-headers-dir=$ac_abs_top_srcdir/include $CTF_OPTS $BTF_OPTS])
			 $ac_abs_top_srcdir/big-tests/configure --with-libabigail-tools-dir=$ac_abs_top_builddir/tools --with-libabigail-headers-dir=$ac_abs_top_srcdir/include $CTF_OPTS $BTF_OPTS],
			 [CTF_ENABLED=$ENABLE_CTF
			 BTF_ENABLED=$ENABLE_BTF])
  else
     AC_MSG_ERROR([No sub-directory big-tests found. Please checkout libabigail-big-tests under a sub-directory named 'big-tests'])
  fi
fi

dnl Check for dependency: libxml
LIBXML2_VERSION=2.6.22
SAVED_PKG_CONFIG_PATH=$PKG_CONFIG_PATH
if test $WITH_LIBXML2_PATH != xauto; then
  export PKG_CONFIG_PATH="$WITH_LIBXML2_PATH/lib/pkgconfig:$PKG_CONFIG_PATH"
fi

AC_MSG_NOTICE([used PKG_CONFIG_PATH=$PKG_CONFIG_PATH to check for libxml2]);
PKG_CHECK_MODULES(XML, libxml-2.0 >= $LIBXML2_VERSION)
if test $WITH_LIBXML2_PATH != xauto; then
  PKG_CONFIG_PATH=$SAVED_PKG_CONFIG_PATH
fi

AC_SUBST(LIBXML2_VERSION)
AC_SUBST(XML_LIBS)
AC_SUBST(XML_CFLAGS)

dnl Check for dependency: xxhash
XXHASH_VERSION=0.8.0
PKG_CHECK_MODULES(XXHASH, libxxhash >= $XXHASH_VERSION)
AC_SUBST(XXHASH_CFLAGS)
AC_SUBST(XXHASH_LIBS)

dnl Check for dependency: liblzma
LIBLZMA_VERSION=5.2.0
PKG_CHECK_MODULES(LZMA, liblzma >= $LIBLZMA_VERSION)
AC_SUBST(LZMA_CFLAGS)
AC_SUBST(LZMA_LIBS)

dnl Check for some programs like rm, mkdir, etc ...
AC_CHECK_PROG(HAS_RM, rm, yes, no)
if test x$HAS_RM = xno; then
   AC_MSG_ERROR([could not find the program 'rm' installed])
fi

AC_CHECK_PROG(HAS_MKDIR, mkdir, yes, no)
if test x$HAS_MKDIR = xno; then
   AC_MSG_ERROR([could not find the program 'mkdir' installed])
fi

dnl Check for the rpm2cpio and cpio programs
if test x$ENABLE_RPM = xyes -o x$ENABLE_RPM = xauto; then
  AC_CHECK_PROG(HAS_RPM2CPIO, rpm2cpio, yes, no)
  AC_CHECK_PROG(HAS_CPIO, cpio, yes, no)
  AC_CHECK_PROG(HAS_RPM, rpm, yes, no)

  if test x$HAS_RPM2CPIO = xyes -a x$HAS_CPIO = xyes -a x$HAS_RPM = xyes; then
     ENABLE_RPM=yes
  else
    if test x$ENABLE_RPM = xyes; then
      AC_MSG_ERROR([rpm support in abipkgdiff needs 'rpm2cpio', 'cpio' and 'rpm' programs to be installed])
    fi
    ENABLE_RPM=no
  fi
fi

dnl Point to a rpm/zstd file, that is:
dnl     $ rpm -qp --qf '%{PAYLOADCOMPRESSOR}\n' [rpm_zstd_file]
dnl     zstd
m4_define([rpm_zstd_file], [tests/data/test-diff-pkg/mesa-libGLU-9.0.1-3.fc33.x86_64.rpm])
AC_CONFIG_SRCDIR([rpm_zstd_file])
if test x$ENABLE_RPM_ZSTD = xyes -o x$ENABLE_RPM_ZSTD = xauto; then
  if test x$ENABLE_RPM = xno; then
    if test x$ENABLE_RPM_ZSTD = xyes; then
      AC_MSG_ERROR([rpm/zstd support needs rpm support])
    fi
    ENABLE_RPM_ZSTD=n/a
  else
    AC_MSG_CHECKING([for rpm/zstd support])
    rpm2cpio > /dev/null 2>&AS_MESSAGE_LOG_FD "$srcdir"/rpm_zstd_file
    if test $? -eq 0; then
      enable_rpm_zstd=yes
    else
      enable_rpm_zstd=no
    fi
    AC_MSG_RESULT([$enable_rpm_zstd])
    if test x$ENABLE_RPM_ZSTD:$enable_rpm_zstd = xyes:no; then
      AC_MSG_ERROR([rpm/zstd support not available])
    fi
    ENABLE_RPM_ZSTD=$enable_rpm_zstd
  fi
fi

if test x$ENABLE_RPM = xyes; then
   AC_DEFINE([WITH_RPM], 1, [compile the rpm package support in abipkgdiff])
   AC_MSG_NOTICE([rpm support in abipkgdiff is enabled]);

   if test x$ENABLE_RPM_ZSTD = xyes; then
      AC_DEFINE([WITH_RPM_ZSTD], 1, [has rpm/zstd support])
      AC_MSG_NOTICE([rpm/zstd in abipkgdiff testing is enabled])
   fi
else
   AC_MSG_NOTICE([rpm support in abipkgdiff is disabled]);
fi

AM_CONDITIONAL(ENABLE_RPM, test x$ENABLE_RPM = xyes)

dnl There is a test that needs symlinks support in the distribution tarball.  If symlinks are
dnl removed from the tarball, then the test should be disabled.
m4_define([symlink_file], [tests/data/test-diff-pkg/symlink-dir-test1/dir1/symlinks/foo.o])
if test -L "$srcdir"/symlink_file; then
   AC_DEFINE([WITH_SYMLINKS_KEPT_IN_DIST], 1, [symbolic links are kept in the distribution tarball])
fi

dnl enable the debugging of self comparison when doing abidw --debug-abidiff <binary>
if test x$ENABLE_DEBUG_SELF_COMPARISON = xyes; then
  AC_DEFINE([WITH_DEBUG_SELF_COMPARISON], 1, [compile support of debugging abidw --abidiff])
  AC_MSG_NOTICE([support of debugging self comparison is enabled])
else
  AC_MSG_NOTICE([support of debugging self comparison is disabled])
fi

AM_CONDITIONAL(ENABLE_DEBUG_SELF_COMPARISON, test x$ENABLE_DEBUG_SELF_COMPARISON = xyes)

dnl enable support of abilint --show-type-use <type-id>
if test x$ENABLE_SHOW_TYPE_USE_IN_ABILINT = xyes; then
  AC_DEFINE([WITH_SHOW_TYPE_USE_IN_ABILINT], 1, [compile support of abilint --show-type-use])
  AC_MSG_NOTICE([support of abilint --show-type-use <type-id> is enabled])
else
  AC_MSG_NOTICE([support of abilint --show-type-use <type-id> is disabled])
fi

AM_CONDITIONAL(ENABLE_SHOW_TYPE_USE_IN_ABILINT, test x$ENABLE_SHOW_TYPE_USE_IN_ABILINT = xyes)

dnl enable the debugging of type canonicalization when doing abidw --debug-tc <binary>
if test x$ENABLE_DEBUG_TYPE_CANONICALIZATION = xyes; then
   AC_DEFINE([WITH_DEBUG_TYPE_CANONICALIZATION],
	     1,
	     [compile support of debugging type canonicalization while using abidw --debug-tc])
   AC_MSG_NOTICE([support of debugging type canonicalization is enabled])
else
   AC_MSG_NOTICE([support of debugging type canonicalization is disabled])
fi

AM_CONDITIONAL(ENABLE_DEBUG_TYPE_CANONICALIZATION, test x$ENABLE_DEBUG_TYPE_CANONICALIZATION = xyes)

dnl Check for the dpkg program
if test x$ENABLE_DEB = xauto -o x$ENABLE_DEB = xyes; then
   AC_CHECK_PROG(HAS_DPKG, dpkg, yes, no)

   if test x$ENABLE_DEB = xauto; then
     if test x$HAS_DPKG = xyes; then
       ENABLE_DEB=yes
     else
       ENABLE_DEB=no
    fi
   fi
fi

if test x$ENABLE_DEB = xyes; then
   AC_DEFINE([WITH_DEB], 1, [compile the deb package support in abipkgdiff])
   AC_MSG_NOTICE(deb support in abipkgdiff is enabled);
else
   AC_MSG_NOTICE(deb support in abipkgdiff is disabled);
fi

AM_CONDITIONAL(ENABLE_DEB, test x$ENABLE_DEB = xyes)

dnl Check for the tar program
if test x$ENABLE_TAR = xauto -o x$ENABLE_TAR = xyes; then
   AC_CHECK_PROG(HAS_TAR, tar, yes, no)

   if test x$ENABLE_TAR = xauto; then
     if test x$HAS_TAR = xyes; then
       ENABLE_TAR=yes
    fi
   fi
fi

if test x$ENABLE_TAR = xyes; then
   AC_DEFINE([WITH_TAR], 1, [compile the GNU tar archive support in abipkgdiff])
   AC_MSG_NOTICE(GNU tar support in abipkgdiff is enabled);
else
   AC_MSG_NOTICE(GNU tar support in abipkgdiff is disabled);
fi

AM_CONDITIONAL(ENABLE_TAR, test x$ENABLE_TAR = xyes)

dnl Check for the bash-completion package
if test x$ENABLE_BASH_COMPLETION = xauto -o x$ENABLE_BASH_COMPLETION = xyes; then
   AC_CHECK_PROG(HAS_BASH_COMPLETION, bash-completion, yes, no)

   if test x$ENABLE_BASH_COMPLETION = xauto; then
     if test x$HAS_BASH_COMPLETION = xyes; then
       ENABLE_BASH_COMPLETION=yes
     else
       ENABLE_BASH_COMPLETION=no
    fi
   fi
fi

if test x$ENABLE_BASH_COMPLETION = xyes; then
   AC_MSG_NOTICE(bash-completion support in libabigail is enabled);
else
   AC_MSG_NOTICE(bash-completion support in libabigail is disabled);
fi

AM_CONDITIONAL(ENABLE_BASH_COMPLETION, test x$ENABLE_BASH_COMPLETION = xyes)

# The minimal python 2 version we want to support is 2.6.6 because EL6
# distributions have that version installed.
MINIMAL_PYTHON2_VERSION="2.6.6"

AC_PATH_PROG(PYTHON, python, no)
AX_PROG_PYTHON_VERSION($MINIMAL_PYTHON2_VERSION,
			 [MINIMAL_PYTHON_VERSION_FOUND=yes],
			 [MINIMAL_PYTHON_VERSION_FOUND=no])

# The minimal python 3 version we want to support is 3.5, which is
# available in Fedora releases and in EL7.
if test x$ENABLE_PYTHON3 != xno; then
  AC_CHECK_PROGS(PYTHON3_INTERPRETER, [python3 python3.5 python3.6 python3.7], no)
else
  PYTHON3_INTERPRETER=no
fi

if test x$ENABLE_PYTHON3 = xauto; then
    if test x$PYTHON3_INTERPRETER != xno; then
      ENABLE_PYTHON3=yes
    else
      # When enabling python3 is auto, tests only run if the
      # python3 interpreter was found on the system. Otherwise,
      # just ignore it.
	ENABLE_PYTHON3=no
      AC_MSG_NOTICE([Python 3 was not found. Skip running tests with Python 3.])
    fi
fi

if test x$ENABLE_PYTHON3 = xyes; then
    if  test x$PYTHON3_INTERPRETER != xno; then
      # We were asked to enable python3 implicitely (auto and
      # python3 was found) or explicitly.  So enable running tests
      # using python3 then.
      RUN_TESTS_WITH_PY3=yes
    else
       AC_MSG_ERROR([Python 3 was not found])
    fi
fi

if test x$PYTHON3_INTERPRETER = xyes; then
   MINIMAL_PYTHON_VERSION_FOUND=yes
fi

if test x$MINIMAL_PYTHON_VERSION_FOUND = xno; then
  AC_MSG_NOTICE([no minimal version of python found])
  if test x$PYTHON = xno; then
     AC_MSG_NOTICE([python binary wasn't found])
     if test x$PYTHON3_INTERPRETER != xno; then
     	  AC_MSG_NOTICE([using $PYTHON3_INTERPRETER instead])
	  PYTHON=$PYTHON3_INTERPRETER
	  MINIMAL_PYTHON_VERSION_FOUND=yes
	  MISSING_FEDABIPKGDIFF_DEP=no
     fi
  fi
else
  AC_MSG_NOTICE([a minimal version of python was found ...])
  if test x$PYTHON3_INTERPRETER != xno; then
   # We were instructed to use python3 and it's present on the
   # system.  Let's update the PYTHON variable that points to the
   # actual python interpreter we are going to be using
   AC_MSG_NOTICE([... and it was $PYTHON3_INTERPRETER])
   PYTHON=$PYTHON3_INTERPRETER
  fi
fi

dnl if --enable-fedabipkgdiff has the 'auto' value, then check for the required
dnl python modules.  If they are present, then enable the fedabipkgdiff program.
dnl If they are not then disable the program.
dnl
dnl If --enable-fedabipkgdiff has the 'yes' value, then check for the required
dnl python modules and whatever dependency fedabipkgdiff needs.  If they are
dnl not present then the configure script will error out.

if test x$ENABLE_FEDABIPKGDIFF = xauto -o x$ENABLE_FEDABIPKGDIFF = xyes; then
   CHECK_DEPS_FOR_FEDABIPKGDIFF=yes
else
   CHECK_DEPS_FOR_FEDABIPKGDIFF=no
fi

if test x$CHECK_DEPS_FOR_FEDABIPKGDIFF = xyes; then
  MISSING_FEDABIPKGDIFF_DEP=no

  if test x$ENABLE_FEDABIPKGDIFF = xyes; then
     MISSING_FEDABIPKGDIFF_DEP_FATAL=yes
  else
     MISSING_FEDABIPKGDIFF_DEP_FATAL=no
  fi

  AC_PATH_PROG(WGET, wget, no)

  if test x$WGET = xno; then
    MISSING_FEDABIPKGDIFF_DEP=yes
    if test x$MISSING_FEDABIPKGDIFF_DEP_FATAL = xyes; then
      AC_MSG_ERROR(could not find the wget program)
    else
      AC_MSG_NOTICE([could not find the wget program])
      AC_MSG_NOTICE([disabling fedabipkgdiff as a result])
    fi
  fi

  if test x$MINIMAL_PYTHON_VERSION_FOUND = xno; then
    MISSING_FEDABIPKGDIFF_DEP=yes
    if test x$MISSING_FEDABIPKGDIFF_DEP_FATAL = xyes; then
      AC_MSG_ERROR([could not find a python program of version at least $MINIMAL_PYTHON2_VERSION])
    fi
  fi

  ###################################################################
  # Now we are going to check the presence of the required python
  # modules using either python2 or python3 as required until now.
  ###################################################################

  # Grrr, the urlparse python2 module got renamed in python3 as
  # urllib.parse.  Oh well.
  if test x$PYTHON = xpython3; then
     URLPARSE_MODULE=urllib.parse
     IMPORT_MODULE=importlib.machinery
  else
     URLPARSE_MODULE=urlparse
     IMPORT_MODULE=imp
  fi

  REQUIRED_PYTHON_MODULES_FOR_FEDABIPKGDIFF="\
   argparse logging os re subprocess sys $URLPARSE_MODULE \
   xdg koji rpm $IMPORT_MODULE tempfile mimetypes shutil six"

  AX_CHECK_PYTHON_MODULES([$REQUIRED_PYTHON_MODULES_FOR_FEDABIPKGDIFF],
			  [$PYTHON],
			  [FOUND_ALL_PYTHON_MODULES=yes],
			  [FOUND_ALL_PYTHON_MODULES=no])

  if test x$FOUND_ALL_PYTHON_MODULES = xno; then
    MISSING_FEDABIPKGDIFF_DEP=yes
    if test x$MISSING_FEDABIPKGDIFF_DEP_FATAL = xyes; then
      AC_MSG_ERROR([missing python modules: $MISSING_PYTHON_MODULES]);
    else
      AC_MSG_NOTICE([missing python modules: $MISSING_PYTHON_MODULES])
      AC_MSG_NOTICE([disabling fedabipkgdiff as a result])
    fi
  else
    # On some old platforms, the koji client object doesn't have
    # the required .read_config method.  Alas, that module doesn't
    # have any __version__ string either.  So we do as well as we
    # can to try and detect that case and disable fedabipkgdiff if
    # necessary.
    AC_MSG_CHECKING([if koji client is recent enough])
    $PYTHON 2>&AS_MESSAGE_LOG_FD -c "
import koji
try:
    koji.read_config('koji')
except koji.ConfigurationError:
    # See 'tools/fedabipkgdiff'.
    pass"
    if test $? -eq 0; then
      koji_version_check_ok=yes
    else
      koji_version_check_ok=no
    fi
    AC_MSG_RESULT([$koji_version_check_ok])
    if test x$koji_version_check_ok = xno; then
      MISSING_FEDABIPKGDIFF_DEP=yes
      if test x$MISSING_FEDABIPKGDIFF_DEP_FATAL = xyes; then
        AC_MSG_ERROR([unsuitable koji client])
      else
	AC_MSG_WARN([disabling fedabipkgdiff])
      fi
    fi
  fi

  if test x$MISSING_FEDABIPKGDIFF_DEP = xno; then
    ENABLE_FEDABIPKGDIFF=yes
  else
    ENABLE_FEDABIPKGDIFF=no
  fi
fi

dnl abidb checks
if test x$PYTHON3_INTERPRETER != xno -a x$ENABLE_ABIDB != xno; then
  AX_CHECK_PYTHON_MODULES([git],
			  [$PYTHON],
			  [FOUND_ALL_PYTHON_MODULES=yes],
			  [FOUND_ALL_PYTHON_MODULES=no])

  $PYTHON3_INTERPRETER -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"
  if test $? -ne 0; then
    AC_MSG_NOTICE([Python 3 version 3.9 or higher is required for abidb])
    AC_MSG_WARN([disabling abidb as a result])
    ENABLE_ABIDB=no
  else
    AC_MSG_NOTICE([Found Python 3 version at 3.9 or higher.  Great for abidb!])
  fi

  if test x$ENABLE_ABIDB = xno; then
    pass
  elif test x$ENABLE_ABIDB != xno -a x$FOUND_ALL_PYTHON_MODULES = xno; then
    AC_MSG_NOTICE([missing python modules: $MISSING_PYTHON_MODULES])
    AC_MSG_WARN([disabling abidb as a result])
    ENABLE_ABIDB=no
  else
    ENABLE_ABIDB=yes
    dnl search for optional modules, just for autoconf reporting purposes
    AX_CHECK_PYTHON_MODULES([libarchive],
			    [$PYTHON],
			    [FOUND_ALL_OPTIONAL_PYTHON_MODULES=yes],
			    [FOUND_ALL_OPTIONAL_PYTHON_MODULES=no])
      if test x$FOUND_ALL_OPTIONAL_PYTHON_MODULES = xno; then
        AC_MSG_WARN([missing optional python modules for abidb: $MISSING_PYTHON_MODULES])
    else
	AC_MSG_NOTICE([found all optional python modules for abidb])
    fi
  fi
else
    AC_MSG_NOTICE([disabling abidb])
fi
AM_CONDITIONAL(ENABLE_ABIDB, test x$ENABLE_ABIDB = xyes)

AM_CONDITIONAL(ENABLE_FEDABIPKGDIFF, test x$ENABLE_FEDABIPKGDIFF = xyes)
AM_CONDITIONAL(ENABLE_RUNNING_TESTS_WITH_PY3, test x$RUN_TESTS_WITH_PY3 = xyes)
AM_CONDITIONAL(ENABLE_PYTHON3_INTERPRETER, test x$PYTHON3_INTERPRETER != xno)
AC_SUBST(PYTHON)

DEPS_CPPFLAGS="$XML_CFLAGS $XXHASH_CFLAGS $ELF_CFLAGS $DW_CFLAGS $LZMA_CFLAGS"
AC_SUBST(DEPS_CPPFLAGS)

dnl Check for the presence of doxygen program

if test x$ENABLE_APIDOC != xno; then
  AC_CHECK_PROG(FOUND_DOXYGEN, doxygen, yes, no)
  if test x$ENABLE_APIDOC = xauto; then
    if test x$FOUND_DOXYGEN = xyes; then
      ENABLE_APIDOC=yes
    else
      ENABLE_APIDOC=no
    fi
  fi
fi
AM_CONDITIONAL(ENABLE_APIDOC, test x$ENABLE_APIDOC = xyes)

dnl Check for the presence of the sphinx-build program

if test x$ENABLE_MANUAL != xno; then
  AC_CHECK_PROG(FOUND_SPHINX_BUILD, sphinx-build, yes, no)
  if test x$ENABLE_MANUAL = xauto; then
    if test x$FOUND_SPHINX_BUILD = xyes; then
      ENABLE_MANUAL=yes
    else
      ENABLE_MANUAL=no
    fi
  fi
fi
AM_CONDITIONAL(ENABLE_MANUAL, test x$ENABLE_MANUAL = xyes)

dnl Check for the presence of Valgrind and do the plumbing to allow
dnl the running of "make check-valgrind".
AX_VALGRIND_DFLT(memcheck, on)
AX_VALGRIND_DFLT(helgrind, on)
AX_VALGRIND_DFLT(drd, off)
AX_VALGRIND_DFLT(sgcheck, off)

AX_VALGRIND_CHECK

dnl Set the list of libraries libabigail depends on
DEPS_LIBS="$XML_LIBS $ELF_LIBS $DW_LIBS $CTF_LIBS $BPF_LIBS $LZMA_LIBS"
if test x$ENABLE_INLINED_XXHASH = xno; then
  DEPS_LIBS="$DEPS_LIBS $XXHASH_LIBS"
fi
AC_SUBST(DEPS_LIBS)

if test x$ABIGAIL_DEVEL != x; then
   CFLAGS="-g -Og -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2"
   CXXFLAGS="-g -Og -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -D_GLIBCXX_DEBUG"
fi

if test x$ABIGAIL_DEBUG != x; then
    CFLAGS="$CFLAGS -Og -g3 -ggdb"
    CXXFLAGS="$CXXFLAGS -Og -g3 -ggdb"
fi

if test x$ABIGAIL_NO_OPTIMIZATION_DEBUG != x; then
   CFLAGS="-g -O0 -Wall -Wextra -Werror"
   CXXFLAGS="-g -O0 -Wall -Wextra -Werror"
fi

if test x$ENABLE_ASAN = xyes; then
    CFLAGS="$CFLAGS -fsanitize=address"
    CXXFLAGS="$CXXFLAGS -fsanitize=address"
fi

if test x$ENABLE_MSAN = xyes; then
    CFLAGS="$CFLAGS -fsanitize=memory -fsanitize-memory-track-origins"
    CXXFLAGS="$CXXFLAGS -fsanitize=memory -fsanitize-memory-track-origins"
fi

if test x$ENABLE_TSAN = xyes; then
    CFLAGS="$CFLAGS -fsanitize=thread"
    CXXFLAGS="$CXXFLAGS -fsanitize=thread"
fi

if test x$ENABLE_UBSAN = xyes; then
    CFLAGS="$CFLAGS -fsanitize=undefined"
    CXXFLAGS="$CXXFLAGS -fsanitize=undefined"
fi

dnl If the user asked then let's use inlined xxhash functions.
if test x$ENABLE_INLINED_XXHASH = xyes; then
   CFLAGS="$CFLAGS -DXXH_INLINE_ALL=1"
   CXXFLAGS="$CXXFLAGS -DXXH_INLINE_ALL=1"
fi

dnl Set a few Automake conditionals

AM_CONDITIONAL([CTF_READER],[test "x$ENABLE_CTF" = "xyes"])
AM_CONDITIONAL([BTF_READER],[test "x$ENABLE_BTF" = "xyes"])

dnl Set the level of C++ standard we use.
CXXFLAGS="$CXXFLAGS -std=$CXX_STANDARD"

dnl Check if several decls and constant are defined in dependant
dnl libraries
HAS_EM_AARCH64=no
AC_CHECK_DECL([EM_AARCH64],
              [HAS_EM_AARCH64=yes],
              [HAS_EM_AARCH64=no],
              [[#include <elf.h>]])

if test x$HAS_EM_AARCH64 = xyes; then
  AC_DEFINE([HAVE_EM_AARCH64_MACRO],
                 1,
            [Defined to 1 if elf.h has EM_AARCH64 macro defined])
fi

HAS_EM_TILEPRO=no
AC_CHECK_DECL([EM_TILEPRO],
              [HAS_EM_TILEPRO=yes],
              [HAS_EM_TILEPRO=no],
              [[#include <elf.h>]])

if test x$HAS_EM_TILEPRO = xyes; then
  AC_DEFINE([HAVE_EM_TILEPRO_MACRO],
                 1,
            [Defined to 1 if elf.h has EM_TILEPR0 macro defined])
fi

HAS_EM_TILEGX=no
AC_CHECK_DECL([EM_TILEGX],
              [HAS_EM_TILEGX=yes],
              [HAS_EM_TILEGX=no],
              [[#include <elf.h>]])

if test x$HAS_EM_TILEGX = xyes; then
  AC_DEFINE([HAVE_EM_TILEGX_MACRO],
                 1,
            [Defined to 1 if elf.h has EM_TILEGX macro defined])
fi

HAS_EM_RISCV=no
AC_CHECK_DECL([EM_RISCV],
              [HAS_EM_RISCV=yes],
              [HAS_EM_RISCV=no],
              [[#include <elf.h>]])

if test x$HAS_EM_RISCV = xyes; then
  AC_DEFINE([HAVE_EM_RISCV_MACRO],
                 1,
            [Defined to 1 if elf.h has EM_RISCV macro defined])
fi

HAS_R_AARCH64_ABS64=no
AC_CHECK_DECL([R_AARCH64_ABS64],
	      [HAS_R_AARCH64_ABS64=yes],
	      [HAS_R_AARCH64_ABS64=no],
	      [[#include <elf.h>]])

if test x$HAS_R_AARCH64_ABS64 = xyes; then
   AC_DEFINE([HAVE_R_AARCH64_ABS64_MACRO],
	     1,
	     [Defined to 1 if elf.h has R_AARCH64_ABS64 macro defined])
fi

HAS_R_AARCH64_PREL32=no
AC_CHECK_DECL([R_AARCH64_PREL32],
	      [HAS_R_AARCH64_PREL32=yes],
	      [HAS_R_AARCH64_PREL32=no],
	      [[#include <elf.h>]])

if test x$HAS_R_AARCH64_PREL32 = xyes; then
   AC_DEFINE([HAVE_R_AARCH64_PREL32_MACRO],
	     1,
	     [Defined to 1 if elf.h has R_AARCH64_PREL32 macro defined])
fi

HAS_DW_LANG_UPC=no
AC_CHECK_DECL([DW_LANG_UPC],
	      [HAS_DW_LANG_UPC=yes],
	      [HAS_DW_LANG_UPC=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_UPC = xyes; then
   AC_DEFINE([HAVE_DW_LANG_UPC_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_UPC enumerator])
fi

HAS_DW_LANG_D=no
AC_CHECK_DECL([DW_LANG_D],
	      [HAS_DW_LANG_D=yes],
	      [HAS_DW_LANG_D=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_D = xyes; then
   AC_DEFINE([HAVE_DW_LANG_D_enumerator],
             1,
	     [Define to 1 if dwarf.h has the DW_LANG_D enumerator])
fi

HAS_DW_LANG_Python=no
AC_CHECK_DECL([DW_LANG_Python],
	      [HAS_DW_LANG_Python=yes],
	      [HAS_DW_LANG_Python=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Python = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Python_enumerator],
             1,
	     [Define to 1 if dwarf.h has the DW_LANG_Python enumerator])
fi

HAS_DW_LANG_Go=no
AC_CHECK_DECL([DW_LANG_Go],
	      [HAS_DW_LANG_Go=yes],
	      [HAS_DW_LANG_Go=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Go = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Go_enumerator],
             1,
	     [Define to 1 if dwarf.h has the DW_LANG_Go enumerator])
fi

HAS_DW_LANG_C11=no
AC_CHECK_DECL([DW_LANG_C11],
	      [HAS_DW_LANG_C11=yes],
	      [HAS_DW_LANG_C11=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_C11 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_C11_enumerator],
             1,
	     [Define to 1 if dwarf.h has the DW_LANG_C11 enumerator])
fi

HAS_DW_LANG_C_plus_plus_03=no
AC_CHECK_DECL([DW_LANG_C_plus_plus_03],
	      [HAS_DW_LANG_C_plus_plus_03=yes],
	      [HAS_DW_LANG_C_plus_plus_03=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_C_plus_plus_03 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_C_plus_plus_03_enumerator],
             1,
	     [Define to 1 if dwarf.h has the DW_LANG_C_plus_plus_03 enumerator])
fi

HAS_DW_LANG_C_plus_plus_11=no
AC_CHECK_DECL([DW_LANG_C_plus_plus_11],
	      [HAS_DW_LANG_C_plus_plus_11=yes],
	      [HAS_DW_LANG_C_plus_plus_11=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_C_plus_plus_11 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_C_plus_plus_11_enumerator],
             1,
	     [Define to 1 if dwarf.h has the DW_LANG_C_plus_plus_11 enumerator])
fi

HAS_DW_LANG_C_plus_plus_14=no
AC_CHECK_DECL([DW_LANG_C_plus_plus_14],
	      [HAS_DW_LANG_C_plus_plus_14=yes],
	      [HAS_DW_LANG_C_plus_plus_14=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_C_plus_plus_14 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_C_plus_plus_14_enumerator],
             1,
	     [Define to 1 if dwarf.h has the DW_LANG_C_plus_plus_14 enumerator])
fi

HAS_DW_LANG_Mips_Assembler=no
AC_CHECK_DECL([DW_LANG_Mips_Assembler],
	      [HAS_DW_LANG_Mips_Assembler=yes],
	      [HAS_DW_LANG_Mips_Assembler=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Mips_Assembler = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Mips_Assembler_enumerator],
             1,
	     [Define to 1 if dwarf.h has the DW_LANG_Mips_Assembler enumerator])
fi

HAS_DW_LANG_Rust=no
AC_CHECK_DECL([DW_LANG_Rust],
	      [HAS_DW_LANG_Rust=yes],
	      [HAS_DW_LANG_Rust=no],
	      [[#include <dwarf.h>]])

if test x$HAS_DW_LANG_Rust = xyes; then
  AC_DEFINE([HAVE_DW_LANG_Rust_enumerator], 
  	    1,
	    [Define to 1 if dwarf.h has the DW_LANG_Rust enumerator])
fi

HAS_DW_LANG_OCaml=no
AC_CHECK_DECL([DW_LANG_OCaml],
	      [HAS_DW_LANG_OCaml=yes],
	      [HAS_DW_LANG_OCaml=no],
	      [[#include <dwarf.h>]])

if test x$HAS_DW_LANG_OCaml = xyes; then
  AC_DEFINE([HAVE_DW_LANG_OCaml_enumerator], 
  	    1,
	    [Define to 1 if dwarf.h has the DW_LANG_OCaml enumerator])
fi

HAS_DW_LANG_Kotlin=no
AC_CHECK_DECL([DW_LANG_Kotlin],
	      [HAS_DW_LANG_Kotlin=yes],
	      [HAS_DW_LANG_Kotlin=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Kotlin = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Kotlin_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Kotlin enumerator])
fi

HAS_DW_LANG_Zig=no
AC_CHECK_DECL([DW_LANG_Zig],
	      [HAS_DW_LANG_Zig=yes],
	      [HAS_DW_LANG_Zig=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Zig = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Zig_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Zig enumerator])
fi

HAS_DW_LANG_Crystal=no
AC_CHECK_DECL([DW_LANG_Crystal],
	      [HAS_DW_LANG_Crystal=yes],
	      [HAS_DW_LANG_Crystal=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Crystal = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Crystal_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Crystal enumerator])
fi

HAS_DW_LANG_C_plus_plus_17=no
AC_CHECK_DECL([DW_LANG_C_plus_plus_17],
	      [HAS_DW_LANG_C_plus_plus_17=yes],
	      [HAS_DW_LANG_C_plus_plus_17=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_C_plus_plus_17 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_C_plus_plus_17_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_C_plus_plus_17 enumerator])
fi

HAS_DW_LANG_C_plus_plus_20=no
AC_CHECK_DECL([DW_LANG_C_plus_plus_20],
	      [HAS_DW_LANG_C_plus_plus_20=yes],
	      [HAS_DW_LANG_C_plus_plus_20=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_C_plus_plus_20 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_C_plus_plus_20_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_C_plus_plus_20 enumerator])
fi

HAS_DW_LANG_C17=no
AC_CHECK_DECL([DW_LANG_C17],
	      [HAS_DW_LANG_C17=yes],
	      [HAS_DW_LANG_C17=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_C17 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_C17_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_C17 enumerator])
fi

HAS_DW_LANG_Fortran18=no
AC_CHECK_DECL([DW_LANG_Fortran18],
	      [HAS_DW_LANG_Fortran18=yes],
	      [HAS_DW_LANG_Fortran18=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Fortran18 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Fortran18_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Fortran18 enumerator])
fi

HAS_DW_LANG_Ada2005=no
AC_CHECK_DECL([DW_LANG_Ada2005],
	      [HAS_DW_LANG_Ada2005=yes],
	      [HAS_DW_LANG_Ada2005=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Ada2005 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Ada2005_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Ada2005 enumerator])
fi

HAS_DW_LANG_Ada2012=no
AC_CHECK_DECL([DW_LANG_Ada2012],
	      [HAS_DW_LANG_Ada2012=yes],
	      [HAS_DW_LANG_Ada2012=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Ada2012 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Ada2012_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Ada2012 enumerator])
fi

HAS_DW_LANG_HIP=no
AC_CHECK_DECL([DW_LANG_HIP],
	      [HAS_DW_LANG_HIP=yes],
	      [HAS_DW_LANG_HIP=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_HIP = xyes; then
   AC_DEFINE([HAVE_DW_LANG_HIP_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_HIP enumerator])
fi

HAS_DW_LANG_Assembly=no
AC_CHECK_DECL([DW_LANG_Assembly],
	      [HAS_DW_LANG_Assembly=yes],
	      [HAS_DW_LANG_Assembly=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Assembly = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Assembly_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Assembly enumerator])
fi

HAS_DW_LANG_C_sharp=no
AC_CHECK_DECL([DW_LANG_C_sharp],
	      [HAS_DW_LANG_C_sharp=yes],
	      [HAS_DW_LANG_C_sharp=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_C_sharp = xyes; then
   AC_DEFINE([HAVE_DW_LANG_C_sharp_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_C_sharp enumerator])
fi

HAS_DW_LANG_Mojo=no
AC_CHECK_DECL([DW_LANG_Mojo],
	      [HAS_DW_LANG_Mojo=yes],
	      [HAS_DW_LANG_Mojo=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Mojo = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Mojo_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Mojo enumerator])
fi

HAS_DW_LANG_GLSL=no
AC_CHECK_DECL([DW_LANG_GLSL],
	      [HAS_DW_LANG_GLSL=yes],
	      [HAS_DW_LANG_GLSL=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_GLSL = xyes; then
   AC_DEFINE([HAVE_DW_LANG_GLSL_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_GLSL enumerator])
fi

HAS_DW_LANG_GLSL_ES=no
AC_CHECK_DECL([DW_LANG_GLSL_ES],
	      [HAS_DW_LANG_GLSL_ES=yes],
	      [HAS_DW_LANG_GLSL_ES=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_GLSL_ES = xyes; then
   AC_DEFINE([HAVE_DW_LANG_GLSL_ES_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_GLSL_ES enumerator])
fi

HAS_DW_LANG_HLSL=no
AC_CHECK_DECL([DW_LANG_HLSL],
	      [HAS_DW_LANG_HLSL=yes],
	      [HAS_DW_LANG_HLSL=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_HLSL = xyes; then
   AC_DEFINE([HAVE_DW_LANG_HLSL_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_HLSL enumerator])
fi

HAS_DW_LANG_OpenCL_CPP=no
AC_CHECK_DECL([DW_LANG_OpenCL_CPP],
	      [HAS_DW_LANG_OpenCL_CPP=yes],
	      [HAS_DW_LANG_OpenCL_CPP=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_OpenCL_CPP = xyes; then
   AC_DEFINE([HAVE_DW_LANG_OpenCL_CPP_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_OpenCL_CPP enumerator])
fi

HAS_DW_LANG_CPP_for_OpenCL=no
AC_CHECK_DECL([DW_LANG_CPP_for_OpenCL],
	      [HAS_DW_LANG_CPP_for_OpenCL=yes],
	      [HAS_DW_LANG_CPP_for_OpenCL=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_CPP_for_OpenCL = xyes; then
   AC_DEFINE([HAVE_DW_LANG_CPP_for_OpenCL_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_CPP_for_OpenCL enumerator])
fi

HAS_DW_LANG_SYCL=no
AC_CHECK_DECL([DW_LANG_SYCL],
	      [HAS_DW_LANG_SYCL=yes],
	      [HAS_DW_LANG_SYCL=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_SYCL = xyes; then
   AC_DEFINE([HAVE_DW_LANG_SYCL_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_SYCL enumerator])
fi

HAS_DW_LANG_C_plus_plus_23=no
AC_CHECK_DECL([DW_LANG_C_plus_plus_23],
	      [HAS_DW_LANG_C_plus_plus_23=yes],
	      [HAS_DW_LANG_C_plus_plus_23=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_C_plus_plus_23 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_C_plus_plus_23_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_C_plus_plus_23 enumerator])
fi

HAS_DW_LANG_Odin=no
AC_CHECK_DECL([DW_LANG_Odin],
	      [HAS_DW_LANG_Odin=yes],
	      [HAS_DW_LANG_Odin=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Odin = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Odin_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Odin enumerator])
fi

HAS_DW_LANG_P4=no
AC_CHECK_DECL([DW_LANG_P4],
	      [HAS_DW_LANG_P4=yes],
	      [HAS_DW_LANG_P4=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_P4 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_P4_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_P4 enumerator])
fi

HAS_DW_LANG_Metal=no
AC_CHECK_DECL([DW_LANG_Metal],
	      [HAS_DW_LANG_Metal=yes],
	      [HAS_DW_LANG_Metal=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Metal = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Metal_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Metal enumerator])
fi

HAS_DW_LANG_C23=no
AC_CHECK_DECL([DW_LANG_C23],
	      [HAS_DW_LANG_C23=yes],
	      [HAS_DW_LANG_C23=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_C23 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_C23_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_C23 enumerator])
fi

HAS_DW_LANG_Fortran23=no
AC_CHECK_DECL([DW_LANG_Fortran23],
	      [HAS_DW_LANG_Fortran23=yes],
	      [HAS_DW_LANG_Fortran23=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Fortran23 = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Fortran23_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Fortran23 enumerator])
fi

HAS_DW_LANG_Ruby=no
AC_CHECK_DECL([DW_LANG_Ruby],
	      [HAS_DW_LANG_Ruby=yes],
	      [HAS_DW_LANG_Ruby=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Ruby = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Ruby_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Ruby enumerator])
fi

HAS_DW_LANG_Move=no
AC_CHECK_DECL([DW_LANG_Move],
	      [HAS_DW_LANG_Move=yes],
	      [HAS_DW_LANG_Move=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Move = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Move_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Move enumerator])
fi

HAS_DW_LANG_Hylo=no
AC_CHECK_DECL([DW_LANG_Hylo],
	      [HAS_DW_LANG_Hylo=yes],
	      [HAS_DW_LANG_Hylo=no],
	      [[#include <dwarf.h>]])
if test x$HAS_DW_LANG_Hylo = xyes; then
   AC_DEFINE([HAVE_DW_LANG_Hylo_enumerator],
	     1,
	     [Define to 1 if dwarf.h has the DW_LANG_Hylo enumerator])

fi

HAS_DW_FORM_strx1=no
HAS_DW_FORM_strx2=no
HAS_DW_FORM_strx3=no
HAS_DW_FORM_strx4=no
HAS_DW_FORM_line_strp=no

AC_CHECK_DECL([DW_FORM_strx1],
	      [HAS_DW_FORM_strx1=yes],
	      [HAS_DW_FORM_strx1=no],
	      [[#include <dwarf.h>]])

if test x$HAS_DW_FORM_strx1 = xyes; then
   AC_DEFINE([HAVE_DW_FORM_strx1],
   	     1,
	     [Define to 1 if dwarf.h has the DW_FORM_strx1 enumerator])
fi

AC_CHECK_DECL([DW_FORM_strx2],
	      [HAS_DW_FORM_strx2=yes],
	      [HAS_DW_FORM_strx2=no],
	      [[#include <dwarf.h>]])

if test x$HAS_DW_FORM_strx2 = xyes; then
   AC_DEFINE([HAVE_DW_FORM_strx2],
   	     1,
	     [Define to 1 if dwarf.h has the DW_FORM_strx2 enumerator])
fi

AC_CHECK_DECL([DW_FORM_strx3],
	      [HAS_DW_FORM_strx3=yes],
	      [HAS_DW_FORM_strx3=no],
	      [[#include <dwarf.h>]])

if test x$HAS_DW_FORM_strx3 = xyes; then
   AC_DEFINE([HAVE_DW_FORM_strx3],
   	     1,
	     [Define to 1 if dwarf.h has the DW_FORM_strx3 enumerator])
fi

AC_CHECK_DECL([DW_FORM_strx4],
	      [HAS_DW_FORM_strx4=yes],
	      [HAS_DW_FORM_strx4=no],
	      [[#include <dwarf.h>]])

if test x$HAS_DW_FORM_strx4 = xyes; then
   AC_DEFINE([HAVE_DW_FORM_strx4],
   	     1,
	     [Define to 1 if dwarf.h has the DW_FORM_strx4 enumerator])
fi

AC_CHECK_DECL([DW_FORM_line_strp],
	      [HAS_DW_FORM_line_strp=yes],
	      [HAS_DW_FORM_line_strp=no],
	      [[#include <dwarf.h>]])

if test x$HAS_DW_FORM_line_strp = xyes; then
   AC_DEFINE([HAVE_DW_FORM_line_strp],
   	     1,
	     [Define to 1 if dwarf.h has the DW_FORM_line_strp enumerator])
fi

if test x$HAS_DW_FORM_strx1 = xyes -a \
	x$HAS_DW_FORM_strx2 = xyes -a \
	x$HAS_DW_FORM_strx3 = xyes -a \
	x$HAS_DW_FORM_strx4 = xyes ; then
   AC_DEFINE([HAVE_DW_FORM_strx],
   	     1,
	     [Define to 1 if dwarf.h has the DW_FORM_strx enumerators])
fi

dnl Set large files support
AC_SYS_LARGEFILE

AC_CONFIG_FILES([Makefile
libabigail.pc
  include/Makefile
  include/abg-version.h
  doc/Makefile
    doc/manuals/Makefile
  src/Makefile
  tools/Makefile
  tests/Makefile
    tests/data/Makefile
    bash-completion/Makefile])

dnl Some test scripts are generated by autofoo.
AC_CONFIG_FILES([tests/runtestcanonicalizetypes.sh],
		[chmod +x tests/runtestcanonicalizetypes.sh])
		AC_CONFIG_FILES([tests/runtestslowselfcompare.sh],
		[chmod +x tests/runtestslowselfcompare.sh])
AC_CONFIG_FILES([tests/mockfedabipkgdiff],
		[chmod +x tests/mockfedabipkgdiff])
AC_CONFIG_FILES([tests/runtestfedabipkgdiff.py],
		[chmod +x tests/runtestfedabipkgdiff.py])
AC_CONFIG_FILES([tests/runtestfedabipkgdiffpy3.sh],
		[chmod +x tests/runtestfedabipkgdiffpy3.sh])
AC_CONFIG_FILES([tests/runtestdefaultsupprs.py],
		[chmod +x tests/runtestdefaultsupprs.py])
AC_CONFIG_FILES([tests/runtestdefaultsupprspy3.sh],
		[chmod +x tests/runtestdefaultsupprspy3.sh])
AC_CONFIG_FILES([tests/runtestabidb1.sh],
		[chmod +x tests/runtestabidb1.sh])
AC_CONFIG_FILES([tests/runtestabidb2.sh],
		[chmod +x tests/runtestabidb2.sh])

AC_OUTPUT

AC_MSG_NOTICE([
=====================================================================
	Libabigail: $VERSION_MAJOR.$VERSION_MINOR.$VERSION_REVISION$VERSION_SUFFIX
=====================================================================

		Here is the configuration of the package:

    Prefix                                         : ${prefix}
    Source code location                           : ${srcdir}
    C Compiler                                     : ${CC}
    C++ Compiler		                   : ${CXX}
    GCC visibility attribute supported             : ${SUPPORTS_GCC_VISIBILITY_ATTRIBUTE}
    CXXFLAGS	   	     			   : ${CXXFLAGS}
    ELF_LIBS					   : ${ELF_LIBS}
    ELF_CFLAGS					   : ${ELF_CFLAGS}
    DW_LIBS					   : ${DW_LIBS}
    DW_CFLAGS					   : ${DW_CFLAGS}
    XML_LIBS					   $ ${XML_LIBS}
    XML_CFLAGS					   $ ${XML_CFLAGS}
    DEPS_LIBS					   $ ${DEPS_LIBS}
    Python					   : ${PYTHON}

 OPTIONAL FEATURES:
    C++ standard level                             : ${CXX_STANDARD}
    Enable inlined-only xxhash library		   : ${ENABLE_INLINED_XXHASH}
    Enable rpm support in abipkgdiff               : ${ENABLE_RPM}
    Enable rpm/zstd in abipkgdiff testing          : ${ENABLE_RPM_ZSTD}
    Enable abilint --show-type-use <type-id>       : ${ENABLE_SHOW_TYPE_USE_IN_ABILINT}
    Enable self comparison debugging               : ${ENABLE_DEBUG_SELF_COMPARISON}
    Enable type canonicalization debugging         : ${ENABLE_DEBUG_TYPE_CANONICALIZATION}
    Enable deb support in abipkgdiff               : ${ENABLE_DEB}
    Enable GNU tar archive support in abipkgdiff   : ${ENABLE_TAR}
    Enable bash completion	                   : ${ENABLE_BASH_COMPLETION}
    Enable fedabipkgdiff                           : ${ENABLE_FEDABIPKGDIFF}
    Enable abidb                                   : ${ENABLE_ABIDB}    
    Enable python 3				   : ${ENABLE_PYTHON3}
    Enable CTF front-end                           : ${ENABLE_CTF}
    Enable BTF front-end                           : ${ENABLE_BTF}
    Enable Big Libabigail tests                    : ${ENABLE_BIG_TESTS}
    Enable running tests under Valgrind            : ${enable_valgrind}
    Enable build with -fsanitize=address    	   : ${ENABLE_ASAN}
    Enable build with -fsanitize=memory    	   : ${ENABLE_MSAN}
    Enable build with -fsanitize=thread    	   : ${ENABLE_TSAN}
    Enable build with -fsanitize=undefined  	   : ${ENABLE_UBSAN}
    Generate html apidoc	                   : ${ENABLE_APIDOC}
    Generate html manual	                   : ${ENABLE_MANUAL}
])
