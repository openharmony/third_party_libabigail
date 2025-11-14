.. _abi_artifacts_label:

ABI artifacts
=============

An ABI artifact is a relevant part of the ABI of a shared library or
program.  Examples of ABI artifacts are exported types, variables,
functions, or `ELF`_ symbols exported by a shared library.

The set of ABI artifacts for a binary is called an ABI Corpus.

Scalar types have a name, a size and other scalar properties.

An aggregate type is generally constituted of sub-types.

For instance, class or union types are a kind of aggregate type.  They
have a name, a size and members.  Each member can be either
  - a data member with a type representing a sub-type of the aggregate
    type, an offset and a name

  - or a function with a type representing another sub-type of the
    aggregate type and a name.  Some (virtual) member functions might
    have an offset as well.

Another example of aggregate type is a function type, which is the
union of the return type and parameter types of the function.

Functions and variables are declarations that have a name and a type.
They are both associated with an `ELF`_ symbol.

.. _ELF: http://en.wikipedia.org/wiki/Executable_and_Linkable_Format
