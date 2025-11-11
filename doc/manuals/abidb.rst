
======
abidb
======

``abidb`` manages a git repository of abixml files describing shared
libraries, and checks binaries against them.  ``elfutils`` and
``libabigail`` programs are used to query and process the binaries.
``abidb`` works well with ``debuginfod`` to fetch needed DWARF content
automatically.


.. _abidb_invocation_label:

Invocation
==========

::

  abidb [OPTIONS] [--submit PATH1 PATH2 ...] [--check PATH1 PATH2 ...]

Common Options
==============

  * ``--abicompat PATH``

    Specify the path to the ``abicompat`` program to use.  By default,
    in the absence of this option, the ``abicompat`` program found in
    directories listed in the $PATH environment is used.

  * ``--abidw PATH``

    Specify the path to the ``abidw`` program to use.  By default,
    in the absence of this option, the ``abidw`` program found in
    directories listed in the $PATH environment is used.

  * ``--distrobranch BRANCH``

    Specify the git branch for the abixml files in the git repo.  The
    default is a string like DISTRO/VERSION/ARCHITECTURE, computed
    from the running environment.

  * ``--git REPO``

    Specify the preexisting git working tree for abidb to submit to or
    check against.  The default is the current working directory.  It
    may be used concurrently by multiple "check" operations, but only
    one "submit" operation.

  * ``--help | -h``

    Display a short help about the command and exit.

  * ``--loglevel LOGLEVEL``

    Specify the diagnostic level for messages to stderr.  One of
    ``debug``, ``info``, ``warning``, ``error``, or ``critical``;
    case-insensitive.  The default is ``info``.

  * ``--timeout SECONDS``

    Specify a maximum limit to the execution time (in seconds) allowed
    for the ``abidw`` and ``abicompat`` programs that are executed.
    By default, no limit is set for the execution time of these
    programs.

Submit Options
==============

  * ``--archive | -Z .EXT[=CMD]``

    Designate PATH names with a ``.EXT`` suffix to be treated as
    archives.  If ``CMD`` is present, pipe the PATH through the given
    shell command, otherwise pass as if through ``cat``.  The
    resulting stream is then opened by ``libarchive``, to enumerate
    the contents of a wide variety of possible archive file format.
    Process each file in the archive individually into abixml.

    For example, ``-Z .zip`` will process each file in a zip file, and
    ``-Z .deb='dpkg-deb --fsys-tarfile'`` will process each payload file
    in a Debian archive.


  * ``--filter REGEX``

    Limit files selected for abixml extraction to those that match the
    given regular expression.  The default is ``/lib.*\.so``, as a
    heuristic to identify shared libraries.


  * ``--submit PATH1 PATH2 ...``

    Using ``abidw``, extract abixml for each of the listed files,
    generally shared libraries, subject to the filename filter and the
    archive decoding options.  Save the output of each ``abidw`` run
    into the selected distrobranch of the selected git repo.  If
    ``--submit`` and ``--check`` are both given, do submit operations
    first.


  * ``--sysroot PREFIX``
    Specify the a prefix path that is to be removed from submitted
    file names.


Check Options
=============

  * ``--check PATH1 PATH2 ...``

    Using ``abidiff``, compare each of the listed file, generally
    executables, against abixml documents for selected versions for
    all shared libraries needed by the executable.  These are listed
    by enumerating the dynamic segment tags ``DT_NEEDED`` of the
    executable.

  * ``--ld-library-path DIR1:DIR2:DIR3...``

    Select the search paths for abixml documents used to locate any
    particular ``SONAME`` .  The first given directory wins.  However,
    all versions of the same ``SONAME`` in that directory are selected
    for comparison.  The default is unspecified, which means to search
    for all matching ``SONAME`` entries in the distrobranch,
    regardless of specific directory.

Exit Code
=========

In case of successful submission and/or checking of all paths, the
exit code is 0.

In case of error, the exit code of ``abidb`` is nonzero, and a brief
listing of the binaries unable to be submitted and/or checked is
printed.


Git Repository Schema
=====================

``abidb`` stores abixml documents in a git repo with the following
naming schema within the distrobranch:

1. The directory path leading to the shared library file

2. The SONAME of the shared library file, as a subdirectory name

3. A file named BUILDID.xml, where ``BUILDID`` is the hexadecimal ELF
   build-id note of the shared library.

For example:

+---------------------------+-------------------------------------------------------------------+
|shared library file name   |abixml path in git                                                 |
+---------------------------+-------------------------------------------------------------------+
| /usr/lib64/libc.so.6.2.32 | /usr/lib64/libc.so.6/788cdd41a15985bf8e0a48d213a46e07d58822df.xml |
| /usr/lib64/libc.so.6.2.33 | /usr/lib64/libc.so.6/e2ca832f1c2112aea9d7b9bc639e97e873a6b516.xml |
| /lib/ld-linux.so.2        | /lib/ld-linux.so.2/b65f3c15b129f33f44f504da1719926aec03c07d.xml   |
+---------------------------+-------------------------------------------------------------------+

The intent of including the buildid in the name is so that as a distro
is updated with multiple versions of a given shared library, they can
be represented nearby but non-conflicting.  The ``SONAME`` is used in
the second-last name component, inspired the behavior of ``ld.so`` and
``ldconfig``, which rely on symbolic links to map references from
the ``SONAME`` to an actual file.

See Also
=======

 * ELF: http://en.wikipedia.org/wiki/Executable_and_Linkable_Format
 * DWARF: https://www.dwarfstd.org
 * Debuginfod: https://sourceware.org/elfutils/Debuginfod.html
 * Git: https://git-scm.com/
 * Libarchive: https://www.libarchive.org/
