.. _abidiff_label:

=======
abidiff
=======

abidiff compares the Application Binary Interfaces (ABI) of two shared
libraries in `ELF`_ format.  It emits a meaningful report describing the
differences between the two ABIs.

This tool can also compare the textual representations of the ABI of
two ELF binaries (as emitted by ``abidw``) or an ELF binary against a
textual representation of another ELF binary.

For a comprehensive ABI change report between two input shared
libraries that includes changes about function and variable sub-types,
``abidiff`` uses by default, debug information in `DWARF`_ format, if
present, otherwise it compares interfaces using debug information in
`CTF`_ or `BTF`_ formats, if present. Finally, if no debug info in
these formats is found, it only considers `ELF`_ symbols and report
about their addition or removal.

.. include:: tools-use-libabigail.txt

.. _abidiff_invocation_label:

Invocation
==========

::

  abidiff [options] <first-shared-library> <second-shared-library>


Environment
===========

.. _abidiff_default_supprs_label:

abidiff loads two default :ref:`suppression specifications files
<suppr_spec_label>`, merges their content and use it to filter out ABI
change reports that might be considered as false positives to users.

* Default system-wide suppression specification file

  It's located by the optional environment variable
  LIBABIGAIL_DEFAULT_SYSTEM_SUPPRESSION_FILE.  If that environment
  variable is not set, then abidiff tries to load the suppression file
  $libdir/libabigail/libabigail-default.abignore.  If that file is not
  present, then no default system-wide suppression specification file
  is loaded.

* Default user suppression specification file.

  It's located by the optional environment
  LIBABIGAIL_DEFAULT_USER_SUPPRESSION_FILE.  If that environment
  variable is not set, then abidiff tries to load the suppression file
  $HOME/.abignore.  If that file is not present, then no default user
  suppression specification is loaded.

.. _abidiff_options_label:

Options
=======

  * ``--help | -h``

    Display a short help about the command and exit.

  * ``--debug-self-comparison``

    In this mode, error messages are emitted for types which fail type
    canonicalization, in some circumstances, when comparing a binary
    against itself.

    When comparing a binary against itself, canonical types of the
    second binary should be equal (as much as possible) to canonical
    types of the first binary.  When some discrepancies are detected
    in this mode, an abort signal is emitted and execution is halted.
    This option should be used while executing the tool in a debugger,
    for troubleshooting purposes.

    This is an optional debugging and sanity check option.  To enable
    it the libabigail package needs to be configured with
    the --enable-debug-self-comparison configure option.

  * ``--debug-tc``

    In this mode, the process of type canonicalization is put under
    heavy scrutiny.  Basically, during type canonicalization, each
    type comparison is performed twice: once in a structural mode
    (comparing every sub-type member-wise), and once using canonical
    comparison.  The two comparisons should yield the same result.
    Otherwise, an abort signal is emitted and the process can be
    debugged to understand why the two kinds of comparison yield
    different results.

    This is an optional debugging and sanity check option.  To enable
    it the libabigail package needs to be configured with
    the --enable-debug-type-canonicalization configure option.

  * ``--version | -v``

    Display the version of the program and exit.

  * ``--debug-info-dir1 | --d1`` <*di-path1*>

    For cases where the debug information for *first-shared-library*
    is split out into a separate file, tells ``abidiff`` where to find
    that separate debug information file.

    Note that *di-path* must point to the root directory under which
    the debug information is arranged in a tree-like manner.  Under
    Red Hat based systems, that directory is usually
    ``<root>/usr/lib/debug``.

    This option can be provided several times with different root
    directories.  In that case, ``abidiff`` will potentially look into
    all those root directories to find the split debug info for
    *first-shared-library*.

    Note also that this option is not mandatory for split debug
    information installed by your system's package manager because
    then ``abidiff`` knows where to find it.

  * ``--debug-info-dir2 | --d2`` <*di-path2*>

    Like ``--debug-info-dir1``, this options tells ``abidiff`` where
    to find the split debug information for the
    *second-shared-library* file.

    This option can be provided several times with different root
    directories.  In that case, ``abidiff`` will potentially look into
    all those root directories to find the split debug info for
    *second-shared-library*.

  * ``--headers-dir1 | --hd1`` <headers-directory-path-1>

    Specifies where to find the public headers of the first shared
    library (or binary in general) that the tool has to consider.  The
    tool will thus filter out ABI changes on types that are not
    defined in public headers.

    Note that several public header directories can be specified for
    the first shared library.  In that case the ``--headers-dir1``
    option should be present several times on the command line, like
    in the following example: ::

      $ abidiff --headers-dir1 /some/path       \
                --headers-dir1 /some/other/path \
		binary-version-1 binary-version-2

  * ``--header-file1 | --hf1`` <header-file-path-1>

    Specifies where to find one public header of the first shared
    library that the tool has to consider.  The tool will thus filter
    out ABI changes on types that are not defined in public headers.

  * ``--headers-dir2 | --hd2`` <headers-directory-path-2>

    Specifies where to find the public headers of the second shared
    library that the tool has to consider.  The tool will thus filter
    out ABI changes on types that are not defined in public headers.

    Note that several public header directories can be specified for
    the second shared library.  In that case the ``--headers-dir2``
    option should be present several times like in the following
    example: ::

      $ abidiff --headers-dir2 /some/path       \
                --headers-dir2 /some/other/path \
		binary-version-1 binary-version-2

  * ``--header-file2 | --hf2`` <header-file-path-2>

    Specifies where to find one public header of the second shared
    library that the tool has to consider.  The tool will thus filter
    out ABI changes on types that are not defined in public headers.

  * ``--add-binaries1`` <*bin1,bin2,bin3,..*>

    For each of the comma-separated binaries given in argument to this
    option, if the binary is found in the directory specified by the
    ``--added-binaries-dir1`` option, then ``abidiff`` loads the ABI
    corpus of the binary and adds it to a set of corpora (called an
    ABI Corpus Group) that includes the first argument of ``abidiff``.

    That ABI corpus group is then compared against the second corpus
    group given in argument to ``abidiff``.

  * ``--add-binaries2`` <*bin1,bin2,bin3,..*>

    For each of the comma-separated binaries given in argument to this
    option, if the binary is found in the directory specified by the
    ``--added-binaries-dir2`` option, then ``abidiff`` loads the ABI
    corpus of the binary and adds it to a set of corpora(called an ABI
    Corpus Group) that includes the second argument of ``abidiff``.

    That ABI corpus group is then compared against the first corpus
    group given in argument to ``abidiff``.

  * ``--follow-dependencies | --fdeps``

    For each dependency of the first argument of ``abidiff``, if it's
    found in the directory specified by the ``--added-binaries-dir1``
    option, then construct an ABI corpus out of the dependency, add it
    to a set of corpora (called an ABI Corpus Group) that includes the
    first argument of ``abidiff``.

    Similarly, for each dependency of the second argument of
    ``abidiff``, if it's found in the directory specified by the
    ``--added-binaries-dir2`` option, then construct an ABI corpus out
    of the dependency, add it to an ABI corpus group that includes the
    second argument of ``abidiff``.

    These two ABI corpus groups are then compared against each other.

    Said otherwise, this makes ``abidiff`` compare the set of its
    first input and its dependencies against the set of its second
    input and its dependencies.

  * ``list-dependencies | --ldeps``

    This option lists all the dependencies of the input arguments of
    ``abidiff`` that are found in the directories specified by the
    options ``--added-binaries-dir1`` and ``--added-binaries-dir2``

  * ``--added-binaries-dir1 | --abd1`` <added-binaries-directory-1>

    This option is to be used in conjunction with the
    ``--add-binaries1``, ``--follow-dependencies`` and
    ``--list-dependencies`` options.  Binaries referred to by these
    options, if found in the directory `added-binaries-directory-1`,
    are loaded as ABI corpus and are added to the first ABI corpus group
    that is to be used in the comparison.

  * ``--added-binaries-dir2 | --abd2`` <added-binaries-directory-2>

    This option is to be used in conjunction with the
    ``--add-binaries2``, ``--follow-dependencies`` and
    ``--list-dependencies`` options.  Binaries referred to by these
    options, if found in the directory `added-binaries-directory-2`,
    are loaded as ABI corpus and are added to the second ABI corpus
    group to be used in the comparison.

  * ``--no-linux-kernel-mode``

    Without this option, if abidiff detects that the binaries it is
    looking at are Linux Kernel binaries (either vmlinux or modules)
    then it only considers functions and variables which ELF symbols
    are listed in the __ksymtab and __ksymtab_gpl sections.

    With this option, abidiff considers the binary as a non-special
    ELF binary.  It thus considers functions and variables which are
    defined and exported in the ELF sense.

  * ``--kmi-whitelist | -kaw`` <*path-to-whitelist*>

    When analyzing a Linux kernel binary, this option points to the
    white list of names of ELF symbols of functions and variables
    which ABI must be considered.  That white list is called a "Kernel
    Module Interface white list".  This is because for the Kernel, we
    don't talk about ``ABI``; we rather talk about the interface
    between the Kernel and its module. Hence the term ``KMI`` rather
    than ``ABI``.

    Any other function or variable which ELF symbol are not present in
    that white list will not be considered by this tool.

    If this option is not provided -- thus if no white list is
    provided -- then the entire KMI, that is, the set of all publicly
    defined and exported functions and global variables by the Linux
    Kernel binaries, is considered.

  * ``--drop-private-types``

    This option is to be used with the ``--headers-dir1``,
    ``header-file1``, ``header-file2`` and ``--headers-dir2`` options.
    With this option, types that are *NOT* defined in the headers are
    entirely dropped from the internal representation build by
    Libabigail to represent the ABI.  They thus don't have to be
    filtered out from the final ABI change report because they are not
    even present in Libabigail's representation.

    Without this option however, those private types are kept in the
    internal representation and later filtered out from the report.

    This options thus potentially makes Libabigail consume less
    memory.  It's meant to be mainly used to optimize the memory
    consumption of the tool on binaries with a lot of publicly defined
    and exported types.

  * ``--exported-interfaces-only``

    By default, when looking at the debug information accompanying a
    binary, this tool analyzes the descriptions of the types reachable
    by the interfaces (functions and variables) that are visible
    outside of their translation unit.  Once that analysis is done, an
    ABI corpus is constructed by only considering the subset of types
    reachable from interfaces associated to `ELF`_ symbols that are
    defined and exported by the binary.  It's those final ABI Corpora
    that are compared by this tool.

    The problem with that approach however is that analyzing all the
    interfaces that are visible from outside their translation unit
    can amount to a lot of data, especially when those binaries are
    applications, as opposed to shared libraries.  One example of such
    applications is the `Linux Kernel`_.  Analyzing massive ABI
    corpora like these can be extremely slow.

    To mitigate that performance issue, this option allows libabigail
    to only analyze types that are reachable from interfaces
    associated with defined and exported `ELF`_ symbols.

    Note that this option is turned on by default when analyzing the
    `Linux Kernel`_.  Otherwise, it's turned off by default.

  * ``--allow-non-exported-interfaces``

    When looking at the debug information accompanying a binary, this
    tool analyzes the descriptions of the types reachable by the
    interfaces (functions and variables) that are visible outside of
    their translation unit.  Once that analysis is done, an ABI corpus
    is constructed by only considering the subset of types reachable
    from interfaces associated to `ELF`_ symbols that are defined and
    exported by the binary.  It's those final ABI Corpora that are
    compared by this tool.

    The problem with that approach however is that analyzing all the
    interfaces that are visible from outside their translation unit
    can amount to a lot of data, especially when those binaries are
    applications, as opposed to shared libraries.  One example of such
    applications is the `Linux Kernel`_.  Analyzing massive ABI
    Corpora like these can be extremely slow.

    In the presence of an "average sized" binary however one can
    afford having libabigail analyze all interfaces that are visible
    outside of their translation unit, using this option.

    Note that this option is turned on by default, unless we are in
    the presence of the `Linux Kernel`_.

  * ``--stat``

    Rather than displaying the detailed ABI differences between
    *first-shared-library* and *second-shared-library*, just display
    some summary statistics about these differences.

  * ``--symtabs``

    Only display the symbol tables of the *first-shared-library* and
    *second-shared-library*.

  * ``--deleted-fns``

    In the resulting report about the differences between
    *first-shared-library* and *second-shared-library*, only display
    the globally defined functions that got deleted from
    *first-shared-library*.

  * ``--changed-fns``

    In the resulting report about the differences between
    *first-shared-library* and *second-shared-library*, only display
    the changes in sub-types of the global functions defined in
    *first-shared-library*.

  * ``--added-fns``

    In the resulting report about the differences between
    *first-shared-library* and *second-shared-library*, only display
    the globally defined functions that were added to
    *second-shared-library*.

  * ``--deleted-vars``

    In the resulting report about the differences between
    *first-shared-library* and *second-shared-library*, only display
    the globally defined variables that were deleted from
    *first-shared-library*.

  * ``--changed-vars``

    In the resulting report about the differences between
    *first-shared-library* and *second-shared-library*, only display
    the changes in the sub-types of the global variables defined in
    *first-shared-library*

  * ``--added-vars``

    In the resulting report about the differences between
    *first-shared-library* and *second-shared-library*, only display
    the global variables that were added (defined) to
    *second-shared-library*.

  * ``--non-reachable-types|-t``

    Analyze and emit change reports for all the types of the binary,
    including those that are not reachable from global functions and
    variables.

    This option might incur some serious performance degradation as
    the number of types analyzed can be huge.  However, if paired with
    the ``--headers-dir{1,2}`` and/or ``header-file{1,2}`` options,
    the additional non-reachable types analyzed are restricted to
    those defined in public headers files, thus hopefully making the
    performance hit acceptable.

    Also, using this option alongside suppression specifications (by
    also using the ``--suppressions`` option) might help keep the number of
    analyzed types (and the potential performance degradation) in
    control.

    Note that without this option, only types that are reachable from
    global functions and variables are analyzed, so the tool detects
    and reports changes on these reachable types only.

  * ``--no-added-syms``

    In the resulting report about the differences between
    *first-shared-library* and *second-shared-library*, do not display
    added functions or variables.  Do not display added functions or
    variables ELF symbols either.  All other kinds of changes are
    displayed unless they are explicitely forbidden by other options
    on the command line.

  * ``--no-linkage-name``

    In the resulting report, do not display the linkage names of
    the added, removed, or changed functions or variables.

  * ``--no-show-locs``

   Do not show information about where in the *second shared library*
   the respective type was changed.

  * ``--show-bytes``

    Show sizes and offsets in bytes, not bits.  By default, sizes and
    offsets are shown in bits.

  * ``--show-bits``

    Show sizes and offsets in bits, not bytes.  This option is
    activated by default.

  * ``--show-hex``

    Show sizes and offsets in hexadecimal base.

  * ``--show-dec``

    Show sizes and offsets in decimal base.  This option is activated
    by default.

  * ``--ignore-soname``

    Ignore differences in the SONAME when doing a comparison

  *  ``--no-show-relative-offset-changes``

     Without this option, when the offset of a data member changes,
     the change report not only mentions the older and newer offset,
     but it also mentions by how many bits the data member changes.
     With this option, the latter is not shown.

  * ``--no-unreferenced-symbols``

    In the resulting report, do not display change information about
    function and variable symbols that are not referenced by any debug
    information.  Note that for these symbols not referenced by any
    debug information, the change information displayed is either
    added or removed symbols.

  * ``--no-default-suppression``

    Do not load the :ref:`default suppression specification files
    <abidiff_default_supprs_label>`.

  * ``--suppressions | --suppr`` <*path-to-suppressions*>

    Use a :ref:`suppression specification <suppr_spec_label>` file
    located at *path-to-suppressions*.  Note that this option can
    appear multiple times on the command line.  In that case, all of
    the provided suppression specification files are taken into
    account.

    Please note that, by default, if this option is not provided, then
    the :ref:`default suppression specification files
    <abidiff_default_supprs_label>` are loaded .

  * ``--drop`` <*regex*>

    When reading the *first-shared-library* and
    *second-shared-library* ELF input files, drop the globally defined
    functions and variables which name match the regular expression
    *regex*.  As a result, no change involving these functions or
    variables will be emitted in the diff report.

  * ``--drop-fn`` <*regex*>

    When reading the *first-shared-library* and
    *second-shared-library* ELF input files, drop the globally defined
    functions which name match the regular expression *regex*.  As a
    result, no change involving these functions will be emitted in the
    diff report.

  * ``--drop-var`` <*regex*>

    When reading the *first-shared-library* and
    *second-shared-library* ELF input files, drop the globally defined
    variables matching a the regular expression *regex*.

  * ``--keep`` <*regex*>

    When reading the *first-shared-library* and
    *second-shared-library* ELF input files, keep the globally defined
    functions and variables which names match the regular expression
    *regex*.  All other functions and variables are dropped on the
    floor and will thus not appear in the resulting diff report.

  * ``--keep-fn`` <*regex*>

    When reading the *first-shared-library* and
    *second-shared-library* ELF input files, keep the globally defined
    functions which name match the regular expression *regex*.  All
    other functions are dropped on the floor and will thus not appear
    in the resulting diff report.

  * ``--keep-var`` <*regex*>

    When reading the *first-shared-library* and
    *second-shared-library* ELF input files, keep the globally defined
    which names match the regular expression *regex*.  All other
    variables are dropped on the floor and will thus not appear in the
    resulting diff report.

  * ``--harmless``

    In the diff report, display only the :ref:`harmless
    <harmlesschangeconcept_label>` changes.  By default, the harmless
    changes are filtered out of the diff report keep the clutter to a
    minimum and have a greater chance to spot real ABI issues.

  * ``--no-harmful``

    In the diff report, do not display the :ref:`harmful
    <harmfulchangeconcept_label>` changes.  By default, only the
    harmful changes are displayed in diff report.

  * ``--redundant``

    In the diff report, do display redundant changes.  A redundant
    change is a change that has been displayed elsewhere in the
    report.

  * ``--no-redundant``

    In the diff report, do *NOT* display redundant changes.  A
    redundant change is a change that has been displayed elsewhere in
    the report.  This option is switched on by default.

  * ``--no-architecture``

    Do not take architecture in account when comparing ABIs.

  * ``--no-corpus-path``

    Do not emit the path attribute for the ABI corpus.

  * ``--fail-no-debug-info``

    If no debug info was found, then this option makes the program to
    fail.  Otherwise, without this option, the program will attempt to
    compare properties of the binaries that are not related to debug
    info, like pure ELF properties.

  * ``--leaf-changes-only|-l`` only show leaf changes, so don't show
    impact analysis report.  This option implies ``--redundant``.

    The typical output of abidiff when comparing two binaries looks
    like this ::

	$ abidiff libtest-v0.so libtest-v1.so
	Functions changes summary: 0 Removed, 1 Changed, 0 Added function
	Variables changes summary: 0 Removed, 0 Changed, 0 Added variable

	1 function with some indirect sub-type change:

	  [C]'function void fn(C&)' at test-v1.cc:13:1 has some indirect sub-type changes:
	    parameter 1 of type 'C&' has sub-type changes:
	      in referenced type 'struct C' at test-v1.cc:7:1:
		type size hasn't changed
		1 data member change:
		 type of 'leaf* C::m0' changed:
		   in pointed to type 'struct leaf' at test-v1.cc:1:1:
		     type size changed from 32 to 64 bits
		     1 data member insertion:
		       'char leaf::m1', at offset 32 (in bits) at test-v1.cc:4:1

	$

    So in that example the report emits information about how the data
    member insertion change of "struct leaf" is reachable from
    function "void fn(C&)".  In other words, the report not only shows
    the data member change on "struct leaf", but it also shows the
    impact of that change on the function "void fn(C&)".

    In abidiff parlance, the change on "struct leaf" is called a leaf
    change.  So the ``--leaf-changes-only --impacted-interfaces``
    options show, well, only the leaf change.  And it goes like this:
    ::

	$ abidiff -l libtest-v0.so libtest-v1.so
	'struct leaf' changed:
	  type size changed from 32 to 64 bits
	  1 data member insertion:
	    'char leaf::m1', at offset 32 (in bits) at test-v1.cc:4:1

	  one impacted interface:
	    function void fn(C&)
	$

    Note how the report ends by showing the list of interfaces
    impacted by the leaf change.

    Now if you don't want to see that list of impacted interfaces,
    then you can just avoid using the ``--impacted-interface`` option.
    You can learn about that option below, in any case.


  * ``--impacted-interfaces``

    When showing leaf changes, this option instructs abidiff to show
    the list of impacted interfaces.  This option is thus to be used
    in addition the ``--leaf-changes-only`` option, otherwise, it's
    ignored.


  *  ``--dump-diff-tree``

    After the diff report, emit a textual representation of the diff
    nodes tree used by the comparison engine to represent the changed
    functions and variables.  That representation is emitted to the
    error output for debugging purposes.  Note that this diff tree is
    relevant only to functions and variables that have some sub-type
    changes.  Added or removed functions and variables do not have any
    diff nodes tree associated to them.

  * ``--no-assume-odr-for-cplusplus``

    When analysing a binary originating from C++ code using `DWARF`_
    debug information, libabigail assumes the `One Definition Rule`_
    to speed-up the analysis.  In that case, when several types have
    the same name in the binary, they are assumed to all be equal.

    This option disables that assumption and instructs libabigail to
    actually actually compare the types to determine if they are
    equal.

  * ``--no-leverage-dwarf-factorization``

    When analysing a binary which `DWARF`_ debug information was
    processed with the `DWZ`_ tool, the type information is supposed
    to be already factorized.  That context is used by libabigail to
    perform some speed optimizations.

    This option disables those optimizations.

  * ``--no-change-categorization | -x``

    This option disables the categorization of changes into harmless
    and harmful changes.  Note that this categorization is a
    pre-requisite for the filtering of changes so this option disables
    that filtering.  The goal of this option is to speed-up the
    execution of the program for cases where the graph of changes is
    huge and where the user is just interested in looking at, for
    instance, leaf node changes without caring about their possible
    impact on interfaces.  In that case, this option would be used
    along with the ``--leaf-changes-only`` one.

  * ``--ctf``

    When comparing binaries, extract ABI information from `CTF`_ debug
    information, if present.

  * ``--btf``

    When comparing binaries, extract ABI information from `BTF`_ debug
    information, if present.

  * ``--stats``

    Emit statistics about various internal things.

  * ``--verbose``

    Emit verbose logs about the progress of miscellaneous internal
    things.

.. _abidiff_return_value_label:

Return values
=============

The exit code of the ``abidiff`` command is either 0 if the ABI of the
binaries being compared are equal, or non-zero if they differ or if
the tool encountered an error.

In the later case, the exit code is a 8-bits-wide bit field in which
each bit has a specific meaning.

The first bit, of value 1, named ``ABIDIFF_ERROR`` means there was an
error.

The second bit, of value 2, named ``ABIDIFF_USAGE_ERROR`` means there
was an error in the way the user invoked the tool.  It might be set,
for instance, if the user invoked the tool with an unknown command
line switch, with a wrong number or argument, etc.  If this bit is
set, then the ``ABIDIFF_ERROR`` bit must be set as well.

The third bit, of value 4, named ``ABIDIFF_ABI_CHANGE`` means the ABI
of the binaries being compared are different.  

The fourth bit, of value 8, named ``ABIDIFF_ABI_INCOMPATIBLE_CHANGE``
means the ABI of the binaries compared are different in an
incompatible way.  If this bit is set, then the ``ABIDIFF_ABI_CHANGE``
bit must be set as well.  If the ``ABIDIFF_ABI_CHANGE`` is set and the
``ABIDIFF_INCOMPATIBLE_CHANGE`` is *NOT* set, then it means that the
ABIs being compared might or might not be compatible.  In that case, a
human being needs to review the ABI changes to decide if they are
compatible or not.

Note that, at the moment, there are only a few kinds of ABI changes
that would result in setting the flag ``ABIDIFF_ABI_INCOMPATIBLE_CHANGE``.
Those ABI changes are either:

  - the removal of the symbol of a function or variable that has been
    defined and exported.
  - the modification of the index of a member of a virtual function
    table (for C++ programs and libraries).

With time, when more ABI change patterns are found to *always*
constitute incompatible ABI changes, we will adapt the code to
recognize those cases and set the ``ABIDIFF_ABI_INCOMPATIBLE_CHANGE``
accordingly.  So, if you find such patterns, please let us know.

The remaining bits are not used for the moment.

.. _abidiff_usage_example_label:

Usage examples
==============

  1. Detecting a change in a sub-type of a function: ::

	$ cat -n test-v0.cc
		 1	// Compile this with:
		 2	//   g++ -g -Wall -shared -o libtest-v0.so test-v0.cc
		 3	
		 4	struct S0
		 5	{
		 6	  int m0;
		 7	};
		 8	
		 9	void
		10	foo(S0* /*parameter_name*/)
		11	{
		12	  // do something with parameter_name.
		13	}
	$ 
	$ cat -n test-v1.cc
		 1	// Compile this with:
		 2	//   g++ -g -Wall -shared -o libtest-v1.so test-v1.cc
		 3	
		 4	struct type_base
		 5	{
		 6	  int inserted;
		 7	};
		 8	
		 9	struct S0 : public type_base
		10	{
		11	  int m0;
		12	};
		13	
		14	void
		15	foo(S0* /*parameter_name*/)
		16	{
		17	  // do something with parameter_name.
		18	}
	$ 
	$ g++ -g -Wall -shared -o libtest-v0.so test-v0.cc
	$ g++ -g -Wall -shared -o libtest-v1.so test-v1.cc
	$ 
	$ ../build/tools/abidiff libtest-v0.so libtest-v1.so
	Functions changes summary: 0 Removed, 1 Changed, 0 Added function
	Variables changes summary: 0 Removed, 0 Changed, 0 Added variable

	1 function with some indirect sub-type change:

	  [C]'function void foo(S0*)' has some indirect sub-type changes:
		parameter 0 of type 'S0*' has sub-type changes:
		  in pointed to type 'struct S0':
		    size changed from 32 to 64 bits
		    1 base class insertion:
		      struct type_base
		    1 data member change:
		     'int S0::m0' offset changed from 0 to 32
	$


  2. Detecting another change in a sub-type of a function: ::

	$ cat -n test-v0.cc
		 1	// Compile this with:
		 2	//   g++ -g -Wall -shared -o libtest-v0.so test-v0.cc
		 3	
		 4	struct S0
		 5	{
		 6	  int m0;
		 7	};
		 8	
		 9	void
		10	foo(S0& /*parameter_name*/)
		11	{
		12	  // do something with parameter_name.
		13	}
	$ 
	$ cat -n test-v1.cc
		 1	// Compile this with:
		 2	//   g++ -g -Wall -shared -o libtest-v1.so test-v1.cc
		 3	
		 4	struct S0
		 5	{
		 6	  char inserted_member;
		 7	  int m0;
		 8	};
		 9	
		10	void
		11	foo(S0& /*parameter_name*/)
		12	{
		13	  // do something with parameter_name.
		14	}
	$ 
	$ g++ -g -Wall -shared -o libtest-v0.so test-v0.cc
	$ g++ -g -Wall -shared -o libtest-v1.so test-v1.cc
	$ 
	$ ../build/tools/abidiff libtest-v0.so libtest-v1.so
	Functions changes summary: 0 Removed, 1 Changed, 0 Added function
	Variables changes summary: 0 Removed, 0 Changed, 0 Added variable

	1 function with some indirect sub-type change:

	  [C]'function void foo(S0&)' has some indirect sub-type changes:
		parameter 0 of type 'S0&' has sub-type changes:
		  in referenced type 'struct S0':
		    size changed from 32 to 64 bits
		    1 data member insertion:
		      'char S0::inserted_member', at offset 0 (in bits)
		    1 data member change:
		     'int S0::m0' offset changed from 0 to 32


	$

  3. Detecting that functions got removed or added to a library: ::

	$ cat -n test-v0.cc
		 1	// Compile this with:
		 2	//   g++ -g -Wall -shared -o libtest-v0.so test-v0.cc
		 3	
		 4	struct S0
		 5	{
		 6	  int m0;
		 7	};
		 8	
		 9	void
		10	foo(S0& /*parameter_name*/)
		11	{
		12	  // do something with parameter_name.
		13	}
	$ 
	$ cat -n test-v1.cc
		 1	// Compile this with:
		 2	//   g++ -g -Wall -shared -o libtest-v1.so test-v1.cc
		 3	
		 4	struct S0
		 5	{
		 6	  char inserted_member;
		 7	  int m0;
		 8	};
		 9	
		10	void
		11	bar(S0& /*parameter_name*/)
		12	{
		13	  // do something with parameter_name.
		14	}
	$ 
	$ g++ -g -Wall -shared -o libtest-v0.so test-v0.cc
	$ g++ -g -Wall -shared -o libtest-v1.so test-v1.cc
	$ 
	$ ../build/tools/abidiff libtest-v0.so libtest-v1.so
	Functions changes summary: 1 Removed, 0 Changed, 1 Added functions
	Variables changes summary: 0 Removed, 0 Changed, 0 Added variable

	1 Removed function:
	  'function void foo(S0&)'    {_Z3fooR2S0}

	1 Added function:
	  'function void bar(S0&)'    {_Z3barR2S0}

	$

  4. Comparing two sets of binaries that are passed on the command line: ::

           $ abidiff --add-binaries1=file2-v1              \
                     --add-binaries2=file2-v2,file2-v1     \
	             --added-binaries-dir1 dir1 	   \
	             --added-binaries-dir2 dir2	           \
	             file1-v1 file1-v2

     Note that the files ``file2-v1``, and ``file2-v2`` are to be
     found in ``dir1`` and ``dir2`` or in the current directory.


  5. Compare two libraries and their dependencies: ::

           $ abidiff --follow-dependencies			\
	             --added-binaries-dir1 /some/where		\
	             --added-binaries-dir2 /some/where/else	\
	             foo bar

     This compares the set of binaries comprised by ``foo`` and its
     dependencies against the set of binaries comprised by ``bar`` and
     its dependencies.


.. _ELF: http://en.wikipedia.org/wiki/Executable_and_Linkable_Format
.. _DWARF: http://www.dwarfstd.org
.. _CTF: https://raw.githubusercontent.com/wiki/oracle/binutils-gdb/files/ctf-spec.pdf
.. _BTF: https://docs.kernel.org/bpf/btf.html
.. _ODR: https://en.wikipedia.org/wiki/One_Definition_Rule
.. _One Definition Rule: https://en.wikipedia.org/wiki/One_Definition_Rule
.. _DWZ: https://sourceware.org/dwz
.. _Linux Kernel: https://kernel.org/
