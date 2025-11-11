.. _abi_change_label:

ABI changes
===========

Libabigail represents and analyzes changes of types, functions,
variables and ELF symbols.  

Those different kinds of ABI artifact changes are categorized
depending on the impact they have on ABI compatibility.

ABI artifact changes are reported by tools like :ref:`abidiff
<abidiff_label>` and :ref:`abipkgdiff <abipkgdiff_label>` in textual
diff reports organized around the different kinds of changes listed
below.

Please note that users can instruct the tools to avoid emitting
reports about certain changes.  This is done via :ref:`suppression
specifications <suppr_spec_label>`.


.. _harmlesschangeconcept_label:

Harmless changes
^^^^^^^^^^^^^^^^

A change in the diff report is considered harmless if it *does not*
cause any ABI compatibility issue.  That is, it does not prevent an
application dynamically linked against a given version of a library to
keep working with the changed subsequent versions of the same library.

By default, :ref:`abidiff_label` and :ref:`abipkgdiff_label` filters
harmless changes from the diff report.


.. _harmfulchangeconcept_label:

Harmful changes
^^^^^^^^^^^^^^^^

An ABI change is considered harmful if it *might* cause ABI
compatibility issues.  That is, it might prevent an application
dynamically linked against a given version of a library to keep
working with the changed subsequent versions of the same library.

Said otherwise, a harmful change is a change that is not harmless.

A harmful change absolutely needs to be reviewed by a human being to
know if it actually causes an ABI compatibility issue.

By default, :ref:`abidiff_label` shows harmful changes for functions
and global variables.

If the tool emits at least one harmful change then the bit
:ref:`ABIDIFF_ABI_CHANGE <abidiff_return_value_label>` of the
bit-field returned in the exit code is set to 1.


.. _incompatiblechangeconcept_label:

Incompatible changes
^^^^^^^^^^^^^^^^^^^^

An incompatible change is a harmful change that causes ABI
incompatibilities issues.  In the colloquial language of programmers,
such a change is said to *break ABI*.

If the :ref:`abidiff_label` or :ref:`abipkgdiff_label` tool emits at
least one incompatible change then the bits
:ref:`ABIDIFF_ABI_INCOMPATIBLE_CHANGE <abidiff_return_value_label>`
and :ref:`ABIDIFF_ABI_CHANGE <abidiff_return_value_label>` of the
bit-field returned in the exit code are set to 1.


Changes recognized as ABI incompatible are the following:

* SONAME change of shared library
* change of the architecture of a binary
* remove of exported function or global variable ELF symbols (not
  necessarily described by debug information)
* removal of exported functions or global variables that are described
  by debug information.
* any incompatible change to the layout of the type which is used as a
  type of a global variable or a return or parameter type of a
  function.  That incompatible layout type change might be:

      * a modification to the size of the type
      * or the removal of a data member
      * or a modification of a data member offset
      * or an incompatible change to a sub-type of the type

  Please note that if a type is used neither as a type of a global
  variable nor as a return or parameter type of a function, then
  :ref:`abidiff_label` (or :ref:`abipkgdiff_label`) will not consider
  an incompatible change of this type as an incompatible ABI change.
  That change will just be considered as harmful.  The
  :ref:`ABIDIFF_ABI_CHANGE <abidiff_return_value_label>` bit of the
  bit-field returned in the exit code is set to 1, meaning that the
  change requires a human review.  This is a current limitation of the
  libabigail analysis framework that might be addressed in future
  refinements.
