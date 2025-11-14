// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- mode: C++ -*-
//
// Copyright (C) 2013-2025 Red Hat, Inc.

/// @file

#ifndef __ABG_HASH_H__
#define __ABG_HASH_H__

#include <cstdint>
#include <cstddef>
#include <string>
#include "abg-ir.h"

namespace abigail
{
/// Namespace for hashing.
namespace hashing
{

/// Enumeration of the different hashing states of an IR node being
/// hashed.
enum hashing_state
{
  /// No hashing has been done/started.
  HASHING_NOT_DONE_STATE = 0,

  /// Hashing started but is not yet finished.
  ///
  /// Note that when a type_or_decl_base::priv::set_hash_value is
  /// invoked on an artifact which has this state, then the hash value
  /// is set/saved onto the artifact.
  HASHING_STARTED_STATE,

  /// A cycle has been detected in the graph on the current node node.
  ///
  /// This means the hashing has started on the current IR node and
  /// while hashing its children nodes, this very same IR node is
  /// visited again to be hashed.  This is a cycle and it needs to be
  /// broken otherwise the hashing continues forever.
  ///
  /// Note that when a type_or_decl_base::priv::set_hash_value is
  /// invoked on an artifact which has this state, then the hash value
  /// is set/saved onto the artifact.
  HASHING_CYCLED_TYPE_STATE,

  /// Hashing a sub-type while hashing another type.
  ///
  /// When a type_or_decl_base::hash_value() is invoked on an artifact
  /// which has this state, it means the hash value that is computed
  /// must NOT be set/saved onto the
  /// artifact. type_or_decl_base::priv::set_hash_value is where this
  /// is enforced.
  HASHING_SUBTYPE_STATE,

  /// Hashing of given IR node started and is now done.  If an ABI
  /// artifact is in this state, then it must have an hash value
  /// available and should be get by peek_hash_value or
  /// type_or_decl_base::hash_value().
  HASHING_FINISHED_STATE,
};

bool
deserialize_hash(const string& input, uint64_t& hash);

bool
serialize_hash(uint64_t hash, string& output);

hash_t
combine_hashes(hash_t, hash_t);

uint32_t
fnv_hash(const std::string& str);

hash_t
hash(std::uint64_t v, std::uint64_t seed = 0);

hash_t
hash(const std::string& str);

hashing::hashing_state
get_hashing_state(const ir::type_or_decl_base& tod);

void
set_hashing_state(const ir::type_or_decl_base& tod,
		  hashing::hashing_state s);

bool
is_recursive_artefact(const type_or_decl_base& t);

void
is_recursive_artefact(const type_or_decl_base& t, bool f);
}//end namespace hashing

namespace ir
{

struct decl_base::hash
{
  hash_t
  operator()(const decl_base& d) const;

  hash_t
  operator()(const decl_base* d) const;
}; // end struct decl_base::hash


/// Hash functor for instances of @ref type_base.
struct type_base::hash
{
  hash_t
  operator()(const type_base& t) const;

  hash_t
  operator()(const type_base* t) const;

  hash_t
  operator()(const type_base_sptr t) const;
}; // end struct type_base::hash

/// Hash functor for instances of @ref type_decl.
struct type_decl::hash
{
  hash_t
  operator()(const type_decl& t) const;

  hash_t
  operator()(const type_decl* t) const;
}; // end struct type_decl::hash

/// Hash functor for instances of @ref qualified_type_def.
struct qualified_type_def::hash
{
  hash_t
  operator()(const qualified_type_def& t) const;

  hash_t
  operator()(const qualified_type_def* t) const;
}; // end struct qualified_type_def::hash

/// Hash functor for instances of @ref pointer_type_def.
struct pointer_type_def::hash
{
  hash_t
  operator()(const pointer_type_def& t) const;

  hash_t
  operator()(const pointer_type_def* t) const;
}; // end struct pointer_type_def::hash

/// Hash functor for instances of @ref reference_type_def.
struct reference_type_def::hash
{
  hash_t
  operator()(const reference_type_def& t) const;

  hash_t
  operator()(const reference_type_def* t) const;
}; // end struct reference_type_def::hash

/// Hash functor for instances of @ref ptr_to_mbr_type.
struct ptr_to_mbr_type::hash
{
  hash_t
  operator() (const ptr_to_mbr_type& t) const;

  hash_t
  operator() (const ptr_to_mbr_type* t) const;

  hash_t
  operator() (const ptr_to_mbr_type_sptr& t) const;
}; // end reference_type_def::hash

/// Hash functor for instances of @ref array_type_def::subrange_type
struct array_type_def::subrange_type::hash
{
  hash_t
  operator()(const array_type_def::subrange_type& s) const;

  hash_t
  operator()(const array_type_def::subrange_type* s) const;
};// end struct array_type_def::subrange_type::hash

/// Hash functor for instances of @ref array_type_def::hash
struct array_type_def::hash
{
  hash_t
  operator()(const array_type_def& t) const;

  hash_t
  operator()(const array_type_def* t) const;
}; //end struct array_type_def::hash

/// Hash functor for instances of @ref  enum_type_decl
struct enum_type_decl::hash
{
  hash_t
  operator()(const enum_type_decl& t) const;

  hash_t
  operator()(const enum_type_decl* t) const;
};// end struct enum_type_decl::hash

/// Hash functor for instances of @ref typedef_decl
struct typedef_decl::hash
{
  hash_t
  operator()(const typedef_decl& t) const;

  hash_t
  operator()(const typedef_decl* t) const;
};// end struct typedef_decl::hash

/// The hashing functor for @ref function_type.
struct function_type::hash
{
  hash_t
  operator()(const function_type& t) const;

  hash_t
  operator()(const function_type* t) const;

  hash_t
  operator()(const function_type_sptr t) const;
};// end struct function_type::hash

/// Hashing functor for the @ref method_type type.
struct method_type::hash
{
  hash_t
  operator()(const method_type& t) const;

  hash_t
  operator()(const method_type* t) const;

  hash_t
  operator()(const method_type_sptr t) const;
}; // end struct method_type::hash

/// The hashing functor for member_base.
struct member_base::hash
{
  hash_t
  operator()(const member_base& m) const;
};

/// Hasher for the @ref class_or_union type
struct class_or_union::hash
{
  hash_t
  operator()(const class_or_union& t) const;

  hash_t
  operator()(const class_or_union* t) const;
}; // end struct class_decl::hash

/// The hashing functor for class_decl::base_spec.
struct class_decl::base_spec::hash
{
  hash_t
  operator()(const base_spec& t) const;

  hash_t
  operator()(const base_spec* t) const;
};

/// Hasher for the @ref class_decl type
struct class_decl::hash
{
  hash_t
  operator()(const class_decl& t) const;

  hash_t
  operator()(const class_decl* t) const;
}; // end struct class_decl::hash

/// Hash functor for instances of @ref union_decl type.
struct union_decl::hash
{
  hash_t
  operator()(const union_decl&) const;

  hash_t
  operator()(const union_decl*) const;
};//end struct union_decl::hash

}// end namespace ir
}//end namespace abigail

#endif //__ABG_HASH_H__
