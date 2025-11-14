// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- Mode: C++ -*-
//
// Copyright (C) 2016-2025 Red Hat, Inc.
//
// Author: Dodji Seketeli

/// @file
///
/// This contains the private implementation of the suppression engine
/// of libabigail.

#ifndef __ABG_IR_PRIV_H__
#define __ABG_IR_PRIV_H__

#include <algorithm>
#include <iostream>
#include <string>

#include "abg-hash.h"
#include "abg-corpus.h"
#include "abg-tools-utils.h"

namespace abigail
{

namespace ir
{

using std::string;
using std::unordered_set;
using abg_compat::optional;

/// The result of structural comparison of type ABI artifacts.
enum comparison_result
{
  COMPARISON_RESULT_DIFFERENT = 0,
  COMPARISON_RESULT_EQUAL = 1,
  COMPARISON_RESULT_CYCLE_DETECTED = 2,
  COMPARISON_RESULT_UNKNOWN = 3,
}; //end enum comparison_result

/// The internal representation of an integral type.
///
/// This is a "utility type" used internally to canonicalize the name
/// of fundamental integral types, so that "unsignd long" and "long
/// unsined int" end-up having the same name.
class real_type
{
public:
  /// The possible base types of integral types.  We might have
  /// forgotten many of these, so do not hesitate to add new ones.
  ///
  /// If you do add new ones, please also consider updating functions
  /// parse_base_real_type and real_type::to_string.
  enum base_type
  {
    /// The "int" base type.
    INT_BASE_TYPE,
    /// The "char" base type.
    CHAR_BASE_TYPE,
    /// The "bool" base type in C++ or "_Bool" in C11.
    BOOL_BASE_TYPE,
    /// The "double" base type.
    DOUBLE_BASE_TYPE,
    /// The "float" base type.
    FLOAT_BASE_TYPE,
    /// The "char16_t base type.
    CHAR16_T_BASE_TYPE,
    /// The "char32_t" base type.
    CHAR32_T_BASE_TYPE,
    /// The "wchar_t" base type.
    WCHAR_T_BASE_TYPE,
    SIZE_BASE_TYPE,
    SSIZE_BASE_TYPE,
    BIT_SIZE_BASE_TYPE,
    SBIT_SIZE_BASE_TYPE,
    /// The aray size type used by Clang.
    ARRAY_SIZE_BASE_TYPE
  };

  /// The modifiers of the base types above.  Several modifiers can be
  /// combined for a given base type.  The presence of modifiers is
  /// usually modelled by a bitmap of modifiers.
  ///
  /// If you add a new modifier, please consider updating functions
  /// parse_real_type_modifier and real_type::to_string.
  enum modifiers_type
  {
    NO_MODIFIER = 0,
    /// The "signed" modifier.
    SIGNED_MODIFIER = 1,
    /// The "unsigned" modier.
    UNSIGNED_MODIFIER = 1 << 1,
    /// The "short" modifier.
    SHORT_MODIFIER = 1 << 2,
    /// The "long" modifier.
    LONG_MODIFIER = 1 << 3,
    /// The "long long" modifier.
    LONG_LONG_MODIFIER = 1 << 4
  };

private:
  base_type	base_;
  modifiers_type modifiers_;

public:

  real_type();
  real_type(const string& name);
  real_type(base_type, modifiers_type);

  base_type
  get_base_type() const;

  modifiers_type
  get_modifiers() const;

  void
  set_modifiers(modifiers_type);

  bool
  operator==(const real_type&) const;

  string
  to_string(bool internal=false) const;

  operator string() const;
}; // end class real_type

real_type::modifiers_type
operator|(real_type::modifiers_type l, real_type::modifiers_type r);

real_type::modifiers_type
operator&(real_type::modifiers_type l, real_type::modifiers_type r);

real_type::modifiers_type
operator~(real_type::modifiers_type l);

real_type::modifiers_type&
operator|=(real_type::modifiers_type& l, real_type::modifiers_type r);

real_type::modifiers_type&
operator &=(real_type::modifiers_type& l, real_type::modifiers_type r);

bool
parse_real_type(const string& type_name,
		    real_type& type);

/// Private type to hold private members of @ref translation_unit
struct translation_unit::priv
{
  const environment&				env_;
  corpus*					corp;
  bool						is_constructed_;
  char						address_size_;
  language					language_;
  std::string					path_;
  std::string					comp_dir_path_;
  std::string					abs_path_;
  location_manager				loc_mgr_;
  mutable global_scope_sptr			global_scope_;
  mutable vector<type_base_sptr>		synthesized_types_;
  vector<function_type_sptr>			live_fn_types_;
  type_maps					types_;


  priv(const environment& env)
    : env_(env),
      corp(),
      is_constructed_(),
      address_size_(),
      language_(LANG_UNKNOWN)
  {}

  ~priv()
  {}

  type_maps&
  get_types()
  {return types_;}
}; // end translation_unit::priv

// <type_or_decl_base stuff>

/// The private data of @ref type_or_decl_base.
struct type_or_decl_base::priv
{
  // This holds the kind of dynamic type of particular instance.
  // Yes, this is part of the implementation of a "poor man" runtime
  // type identification.  We are doing this because profiling shows
  // that using dynamic_cast in some places is really to slow and is
  // constituting a hotspot.  This poor man's implementation made
  // things be much faster.
  enum type_or_decl_kind	kind_;
  // This holds the runtime type instance pointer of particular
  // instance.  In other words, this is the "this pointer" of the
  // dynamic type of a particular instance.
  void*			rtti_;
  // This holds a pointer to either the type_base sub-object (if the
  // current instance is a type) or the decl_base sub-object (if the
  // current instance is a decl).  This is used by the is_decl() and
  // is_type() functions, which also show up during profiling as
  // hotspots, due to their use of dynamic_cast.
  void*			type_or_decl_ptr_;
  mutable hashing::hashing_state hashing_state_;
  bool				is_recursive_artefact_;
  hash_t			hash_value_;
  const environment&		env_;
  translation_unit*		translation_unit_;
  // The location of an artifact as seen from its input by the
  // artifact reader.  This might be different from the source
  // location advertised by the original emitter of the artifact
  // emitter.
  location			artificial_location_;
  // Flags if the current ABI artifact is artificial (i.e, *NOT*
  // generated from the initial source code, but rather either
  // artificially by the compiler or by libabigail itself).
  bool				is_artificial_;

  /// Constructor of the type_or_decl_base::priv private type.
  ///
  /// @param e the environment in which the ABI artifact was created.
  ///
  /// @param k the identifier of the runtime type of the current
  /// instance of ABI artifact.
  priv(const environment& e,
       enum type_or_decl_kind k = ABSTRACT_TYPE_OR_DECL)
    : kind_(k),
      rtti_(),
      type_or_decl_ptr_(),
      hashing_state_(hashing::HASHING_NOT_DONE_STATE),
      is_recursive_artefact_(),
      env_(e),
      translation_unit_(),
      is_artificial_()
  {}

  /// Getter of the kind of the IR node.
  ///
  /// @return the kind of the IR node.
  enum type_or_decl_kind
  kind() const
  {return kind_;}

  /// Setter of the kind of the IR node.
  ///
  /// @param k the new IR node kind.
  void
  kind (enum type_or_decl_kind k)
  {kind_ |= k;}

  /// Getter the hashing state of the current IR node.
  ///
  /// @return the hashing state of the current IR node.
  hashing::hashing_state
  get_hashing_state() const
  {return hashing_state_;}

  /// Getter of the property which flags the current artefact as being
  /// recursive or not.
  ///
  /// @return true iff the current artefact it recursive.
  bool
  is_recursive_artefact() const
  {return is_recursive_artefact_;}

  /// Setter of the property which flags the current artefact as being
  /// recursive or not.
  ///
  /// @param f the new value of the property.
  void
  is_recursive_artefact(bool f)
  {is_recursive_artefact_ = f;}

  /// Setter of the hashing state of the current IR node.
  ///
  /// @param s the hashing state of the current IR node.
  void
  set_hashing_state(hashing::hashing_state s) const
  {hashing_state_ = s;}

  /// Setter of the hashing value of the current IR node.
  ///
  /// An empty value is just ignored.  Also, if the IR node is NEITHER
  /// in the hashing::HASHING_NOT_DONE_STATE nor in the
  /// hashing::HASHING_CYCLED_TYPE_STATE, then the function does
  /// nothing.
  ///
  /// @param h the new hash value.
  void
  set_hash_value(hash_t h)
  {
    hashing::hashing_state s = get_hashing_state();

    ABG_ASSERT(s == hashing::HASHING_NOT_DONE_STATE
	       || s == hashing::HASHING_CYCLED_TYPE_STATE
	       || s == hashing::HASHING_FINISHED_STATE
	       || s == hashing::HASHING_SUBTYPE_STATE);
    if (h.has_value()
	&& (s == hashing::HASHING_NOT_DONE_STATE
	    || s == hashing::HASHING_CYCLED_TYPE_STATE))
      {
	hash_value_ = h;
	set_hashing_state(hashing::HASHING_FINISHED_STATE);
      }
  }

  /// Setter of the hashing value of the current IR node.
  ///
  /// Unlike set_hash_value above, this function always sets a new
  /// hash value regardless of the hash value or of the hashing state
  /// of the IR node.
  ///
  /// @param h the new hash value.
  void
  force_set_hash_value(hash_t h)
  {
    if (h.has_value())
    {
      hash_value_ = h;
      set_hashing_state(hashing::HASHING_FINISHED_STATE);
    }
  }
}; // end struct type_or_decl_base::priv

/// Compute the hash value of an IR node and return it.
/// 
/// Note that if the IR node is a non-canonicalizeable type, no hash
/// value is computed and an empty hash is returned.  Also, if the IR
/// node already has a hash value, then this function just returns it.
///
/// This is a sub-routine of the internal hashing functions defined in
/// abg-hash.cc
///
/// @param tod the IR node to compute the value for.
///
/// @return the computed hash value computed.
template<typename T>
hash_t
do_hash_value(const T& tod)
{
  if (type_base* type = is_type(&tod))
    if (is_non_canonicalized_type(type))
      // Non canonicalized types are not hashed.  They must always be
      // compared structurally.
      return hash_t();

  typename T::hash do_hash;
  hash_t h = do_hash(tod);
  return h;
}

/// Compute the hash value of an IR node and return it.
/// 
/// Note that if the IR node is a non-canonicalizeable type, no hash
/// value is computed and an empty hash is returned.  Also, if the IR
/// node already has a hash value, then this function just returns it.
///
/// This is a sub-routine of the internal hashing functions defined in
/// abg-hash.cc
///
/// @param tod the IR node to compute the value for.
///
/// @return the computed hash value computed.
template<typename T>
hash_t
do_hash_value(const T* tod)
{
  if (!tod)
    return hash_t();
  return hash_value(*tod);
}

/// Compute the hash value of an IR node and return it.
/// 
/// Note that if the IR node is a non-canonicalizeable type, no hash
/// value is computed and an empty hash is returned.  Also, if the IR
/// node already has a hash value, then this function just returns it.
///
/// This is a sub-routine of the internal hashing functions defined in
/// abg-hash.cc
///
/// @param tod the IR node to compute the value for.
///
/// @return the computed hash value computed.
template<typename T>
hash_t
do_hash_value(const shared_ptr<T>& tod)
{
  if (!tod)
    return hash_t();
  return do_hash_value(*tod);
}


/// Set the hash value of an IR node and return it.
///
/// If the IR node already has a hash value set, this function just
/// returns it.  Otherwise, the function computes a new hash value and
/// sets it to the IR node.
///
/// Note that if the IR node is a non-canonicalizeable type, no hash
/// value is computed and an empty hash is returned.
///
/// This is a sub-routine of the type_or_decl_base::hash_value()
/// virtual member functions.
///
/// @param type_or_decl the IR node to compute the value for.
///
/// @return the hash value computed and set to the IR node, or the
/// hash value the IR node already had.
template<typename T>
hash_t
set_or_get_cached_hash_value(const T& tod)
{
  hash_t h = do_hash_value(tod);
  const_cast<T&>(tod).set_hash_value(h);
  return h;
}

/// Set the hash value of an IR node and return it.
///
/// If the IR node already has a hash value set, this function just
/// returns it.  Otherwise, the function computes a new hash value and
/// sets it to the IR node.
///
/// Note that if the IR node is a non-canonicalizeable type, no hash
/// value is computed and an empty hash is returned.
///
/// This is a sub-routine of the type_or_decl_base::hash_value()
/// virtual member functions.
///
/// @param type_or_decl the IR node to compute the value for.
///
/// @return the hash value computed and set to the IR node, or the
/// hash value the IR node already had.
template<typename T>
hash_t
set_or_get_cached_hash_value(const T* artifact)
{
  if (!artifact)
    return hash_t();
  return set_or_get_cached_hash_value(*artifact);
}

// </type_or_decl_base stuff>


// <type_base definitions>

size_t
get_canonical_type_index(const type_base& t);

size_t
get_canonical_type_index(const type_base* t);

size_t
get_canonical_type_index(const type_base_sptr& t);

/// Definition of the private data of @ref type_base.
struct type_base::priv
{
  size_t		size_in_bits;
  size_t		alignment_in_bits;
  size_t		canonical_type_index;
  type_base_wptr	canonical_type;
  // The data member below holds the canonical type that is managed by
  // the smart pointer referenced by the canonical_type data member
  // above.  We are storing this underlying (naked) pointer here, so
  // that users can access it *fast*.  Otherwise, accessing
  // canonical_type above implies creating a shared_ptr, and that has
  // been measured to be slow for some performance hot spots.
  type_base*		naked_canonical_type;
  // Computing the representation of a type again and again can be
  // costly.  So we cache the internal and non-internal type
  // representation strings here.
  interned_string	internal_cached_repr_;
  interned_string	cached_repr_;

  priv()
    : size_in_bits(),
      alignment_in_bits(),
      canonical_type_index(),
      naked_canonical_type()
  {}

  priv(size_t s,
       size_t a,
       type_base_sptr c = type_base_sptr())
    : size_in_bits(s),
      alignment_in_bits(a),
      canonical_type_index(),
      canonical_type(c),
      naked_canonical_type(c.get())
  {}
}; // end struct type_base::priv

bool
type_is_suitable_for_hash_computing(const type_base&);

// <environment definitions>

/// The hashing functor for a pair of uint64_t.
struct uint64_t_pair_hash
{
  /// Hashing function for a pair of uint64_t.
  ///
  /// @param p the pair to hash.
  uint64_t
  operator()(const std::pair<uint64_t, uint64_t>& p) const
  {
    return *abigail::hashing::combine_hashes(hash_t(p.first),
					     hash_t(p.second));
  }
};

/// A convenience typedef for a pair of uint64_t which is initially
/// intended to store a pair of pointer values.
typedef std::pair<uint64_t, uint64_t> uint64_t_pair_type;

/// A convenience typedef for a set of @ref uint64_t_pair
typedef unordered_set<uint64_t_pair_type,
		      uint64_t_pair_hash> uint64_t_pairs_set_type;

/// A convenience typedef for a set of pointer to @ref class_or_union
typedef unordered_set<const class_or_union*> class_set_type;

/// A convenience typedef for a set of pointer to @ref function_type.
typedef unordered_set<const function_type*> fn_set_type;

/// A convenience typedef for a map which key is a pair of uint64_t
/// and which value is a boolean.  This is initially intended to cache
/// the result of comparing two (sub-)types.
typedef unordered_map<uint64_t_pair_type, bool,
		      uint64_t_pair_hash> type_comparison_result_type;

/// The private data of the @ref environment type.
struct environment::priv
{
  config				config_;
  canonical_types_map_type		canonical_types_;
  mutable vector<type_base_sptr>	sorted_canonical_types_;
  type_base_sptr			void_type_;
  type_base_sptr			void_pointer_type_;
  type_base_sptr			variadic_marker_type_;
  // The set of pairs of class types being currently compared.  It's
  // used to avoid endless loops while recursively comparing types.
  // This should be empty when none of the 'equal' overloads are
  // currently being invoked.
  class_set_type			left_classes_being_compared_;
  class_set_type			right_classes_being_compared_;
  // The set of pairs of function types being currently compared.  It's used
  // to avoid endless loops while recursively comparing types.  This
  // should be empty when none of the 'equal' overloads are currently
  // being invoked.
  fn_set_type				left_fn_types_being_compared_;
  fn_set_type				right_fn_types_being_compared_;
  // This is a cache for the result of comparing two sub-types (of
  // either class or function types) that are designated by their
  // memory address in the IR.
  type_comparison_result_type		type_comparison_results_cache_;
  vector<type_base_sptr>		extra_live_types_;
  interned_string_pool			string_pool_;
  // The two vectors below represent the stack of left and right
  // operands of the current type comparison operation that is
  // happening during type canonicalization.
  //
  // Basically, that stack of operand looks like below.
  //
  // First, suppose we have a type T_L that has two sub-types as this:
  //
  //  T_L
  //   |
  //   +-- L_OP0
  //   |
  //   +-- L_OP1
  //
  // Now suppose that we have another type T_R that has two sub-types
  // as this:
  //
  //  T_R
  //   |
  //   +-- R_OP0
  //   |
  //   +-- R_OP1
  //
  //   Now suppose that we compare T_L against T_R.  We are going to
  //   have a stack of pair of types. Each pair of types represents
  //   two (sub) types being compared against each other.
  //
  //   On the stack, we will thus first have the pair (T_L, T_R)
  //   being compared.  Then, we will have the pair (L_OP0, R_OP0)
  //   being compared, and then the pair (L_OP1, R_OP1) being
  //   compared.  Like this:
  //
  // | T_L | L_OP0 | L_OP1 | <-- this goes into left_type_comp_operands_;
  //  -------- -------------
  // | T_R | R_OP0 | R_OP1 | <-- this goes into right_type_comp_operands_;
  //
  vector<const type_base*>		left_type_comp_operands_;
  vector<const type_base*>		right_type_comp_operands_;

#ifdef WITH_DEBUG_SELF_COMPARISON
  // This is used for debugging purposes.
  // When abidw is used with the option --debug-abidiff, some
  // libabigail internals need to get a hold on the initial binary
  // input of abidw, as well as as the abixml file that represents the
  // ABI of that binary.
  //
  // So this one is the corpus for the input binary.
  corpus_wptr				first_self_comparison_corpus_;
  // This one is the corpus for the ABIXML file representing the
  // serialization of the input binary.
  corpus_wptr				second_self_comparison_corpus_;
  // This is also used for debugging purposes, when using
  //   'abidw --debug-abidiff <binary>'.  It holds the set of mapping of
  // an abixml (canonical) type and its type-id.
  unordered_map<string, uintptr_t>	type_id_canonical_type_map_;
  // Likewise.  It holds a map that associates the pointer to a type
  // read from abixml and the type-id string it corresponds to.
  unordered_map<uintptr_t, string>	pointer_type_id_map_;
#endif
  bool					canonicalization_started_;
  bool					canonicalization_is_done_;
  bool					decl_only_class_equals_definition_;
  bool					use_enum_binary_only_equality_;
  bool					allow_type_comparison_results_caching_;
  bool					do_log_;
  optional<bool>			analyze_exported_interfaces_only_;
#ifdef WITH_DEBUG_SELF_COMPARISON
  bool					self_comparison_debug_on_;
#endif
#ifdef WITH_DEBUG_TYPE_CANONICALIZATION
  // This controls whether to use canonical type comparison during
  // type comparison or not.  This is only used for debugging, when we
  // want to ensure that comparing types using canonical or structural
  // comparison yields the same result.
  bool					use_canonical_type_comparison_;
  // Whether we are debugging type canonicalization or not.  When
  // debugging type canonicalization, a type is compared to its
  // potential canonical type twice: The first time with canonical
  // comparison activated, and the second time with structural
  // comparison activated.  The two comparison should yield the same
  // result, otherwise, canonicalization is "broken" for that
  // particular type.
  bool					debug_type_canonicalization_;
  bool					debug_die_canonicalization_;
#endif

  priv()
    : canonicalization_started_(),
      canonicalization_is_done_(),
      decl_only_class_equals_definition_(false),
      use_enum_binary_only_equality_(true),
      allow_type_comparison_results_caching_(false),
      do_log_(false)
#ifdef WITH_DEBUG_SELF_COMPARISON
    ,
      self_comparison_debug_on_(false)
#endif
#ifdef WITH_DEBUG_TYPE_CANONICALIZATION
    ,
      use_canonical_type_comparison_(true),
      debug_type_canonicalization_(false),
      debug_die_canonicalization_(false)
#endif
  {}

  /// Allow caching of the sub-types comparison results during the
  /// invocation of the @ref equal overloads for class and function
  /// types.
  ///
  /// @param f if true, allow type comparison result caching.
  void
  allow_type_comparison_results_caching(bool f)
  {allow_type_comparison_results_caching_ = f;}

  /// Check whether if caching of the sub-types comparison results during the
  /// invocation of the @ref equal overloads for class and function
  /// types is in effect.
  ///
  /// @return true iff caching of the sub-types comparison results
  /// during the invocation of the @ref equal overloads for class and
  /// function types is in effect.
  bool
  allow_type_comparison_results_caching() const
  {return allow_type_comparison_results_caching_;}

  void
  do_log(bool f)
  {do_log_ = f;}

  bool
  do_log() const
  {return do_log_;}

  /// Cache the result of comparing two sub-types.
  ///
  /// @param first the first sub-type that has been compared. Its
  /// address is going to be stored in the cache.
  ///
  /// @param second the second sub-type that has been compared. Its
  /// address is going to be stored in the cache.
  ///
  /// @param r the result of comparing @p first and @p second.  This
  /// is going to be stored in the cache, as well as the addresses of
  /// @p first and @p second.
  template<typename T>
  void
  cache_type_comparison_result(T& first, T& second, bool r)
  {
    if (allow_type_comparison_results_caching())
      {
	type_comparison_results_cache_.emplace
	  (std::make_pair(reinterpret_cast<uint64_t>(&first),
			  reinterpret_cast<uint64_t>(&second)),
	   r);
      }
  }

  /// Retrieve the result of comparing two sub-types from the cache,
  /// if it was previously stored.
  ///
  /// @param first the first sub-type to consider.
  ///
  /// @param second the second sub-type to consider.  The pair of
  /// addresses of {@p first, @p second} is going to be looked up in
  /// the cache.  If it's present, then the associated result of the
  /// comparison of @p first against @p second is present as well, and
  /// is returned.
  ///
  /// @param r this is an out parameter which is set to the result of
  /// the comparison of @p first against @p second if the pair of
  /// addresses of {@p first, @p second} is present in the cache.
  ///
  /// @return true iff the pair of addresses of {@p first, @p second}
  /// is present in the cache.  In that case, the associated result of
  /// the comparison of @p first against @p second is returned in the
  /// argument of @p r.
  template<typename T>
  bool
  is_type_comparison_cached(T& first, T& second, bool& r)
  {
    if (!allow_type_comparison_results_caching())
      return false;

    type_comparison_result_type::const_iterator it =
      type_comparison_results_cache_.find
      (std::make_pair(reinterpret_cast<uint64_t>(&first),
		      reinterpret_cast<uint64_t>(&second)));
    if (it == type_comparison_results_cache_.end())
      return false;

    r = it->second;
    return true;
  }

  /// Clear the cache type comparison results.
  void
  clear_type_comparison_results_cache()
  {type_comparison_results_cache_.clear();}

  /// Push a pair of operands on the stack of operands of the current
  /// type comparison, during type canonicalization.
  ///
  /// For more information on this, please look at the description of
  /// the right_type_comp_operands_ data member.
  ///
  /// @param left the left-hand-side comparison operand to push.
  ///
  /// @param right the right-hand-side comparison operand to push.
  void
  push_composite_type_comparison_operands(const type_base* left,
					  const type_base* right)
  {
    ABG_ASSERT(left && right);

    left_type_comp_operands_.push_back(left);
    right_type_comp_operands_.push_back(right);
  }

  /// Pop a pair of operands from the stack of operands to the current
  /// type comparison.
  ///
  /// For more information on this, please look at the description of
  /// the right_type_comp_operands_ data member.
  ///
  /// @param left the left-hand-side comparison operand we expect to
  /// pop from the top of the stack.  If this doesn't match the
  /// operand found on the top of the stack, the function aborts.
  ///
  /// @param right the right-hand-side comparison operand we expect to
  /// pop from the bottom of the stack. If this doesn't match the
  /// operand found on the top of the stack, the function aborts.
  void
  pop_composite_type_comparison_operands(const type_base* left,
					 const type_base* right)
  {
    const type_base *t = left_type_comp_operands_.back();
    ABG_ASSERT(t == left);
    t = right_type_comp_operands_.back();
    ABG_ASSERT(t == right);

    left_type_comp_operands_.pop_back();
    right_type_comp_operands_.pop_back();
  }

#ifdef WITH_DEBUG_SELF_COMPARISON

  const unordered_map<string, uintptr_t>&
  get_type_id_canonical_type_map() const
  {return type_id_canonical_type_map_;}

  unordered_map<string, uintptr_t>&
  get_type_id_canonical_type_map()
  {return type_id_canonical_type_map_;}

  const unordered_map<uintptr_t, string>&
  get_pointer_type_id_map() const
  {return pointer_type_id_map_;}

  unordered_map<uintptr_t, string>&
  get_pointer_type_id_map()
  {return pointer_type_id_map_;}

  string
  get_type_id_from_pointer(uintptr_t ptr) const
  {
    auto it = get_pointer_type_id_map().find(ptr);
    if (it != get_pointer_type_id_map().end())
      return it->second;
    return "";
  }

  string
  get_type_id_from_type(const type_base *t) const
  {return get_type_id_from_pointer(reinterpret_cast<uintptr_t>(t));}

  uintptr_t
  get_canonical_type_from_type_id(const char* type_id) const
  {
    if (!type_id)
      return 0;
    auto it = get_type_id_canonical_type_map().find(type_id);
    if (it != get_type_id_canonical_type_map().end())
      return it->second;
    return 0;
  }

  /// When debugging self comparison, verify that a type T
  /// de-serialized from abixml has the same canonical type as the
  /// initial type built from DWARF that was serialized into T in the
  /// first place.
  ///
  /// @param t deserialized type (from abixml) to consider.
  ///
  /// @param c the canonical type that @p t has, as computed freshly
  /// from the abixml file.
  ///
  /// @return true iff @p c has the same value as the canonical type
  /// that @p t had before being serialized into abixml.
  bool
  check_canonical_type_from_abixml_during_self_comp(const type_base* t,
						    const type_base* c)
  {
    if (!t || !t->get_corpus() || !c)
      return false;

    if (!(t->get_corpus()->get_origin() == ir::corpus::NATIVE_XML_ORIGIN))
      return false;

    // Get the abixml type-id that this type was constructed from.
    string type_id;
    {
      unordered_map<uintptr_t, string>::const_iterator it =
	pointer_type_id_map_.find(reinterpret_cast<uintptr_t>(t));
      if (it == pointer_type_id_map_.end())
	// This type didn't have a type-id in the abixml file.  Maybe
	// it's a function or method type.  So let's just keep going.
	return true;
      type_id = it->second;
    }

    // Get the canonical type the original in-memory type (constructed
    // from DWARF) had when it was serialized into abixml in the first place.
    type_base *original_canonical_type = nullptr;
    if (!type_id.empty())
      {
	unordered_map<string, uintptr_t>::const_iterator it =
	  type_id_canonical_type_map_.find(type_id);
	if (it == type_id_canonical_type_map_.end())
	  return false;
	original_canonical_type = reinterpret_cast<type_base*>(it->second);
      }

    // Now perform the real check.
    //
    // We want to ensure that the canonical type 'c' of 't' is the
    // same as the canonical type of initial in-memory type (built
    // from DWARF) that was serialized into 't' (in abixml) in the
    // first place.
    if (original_canonical_type == c)
      return true;

    return false;
  }

  /// When debugging self comparison, verify that a type T
  /// de-serialized from abixml has the same canonical type as the
  /// initial type built from DWARF that was serialized into T in the
  /// first place.
  ///
  /// @param t deserialized type (from abixml) to consider.
  ///
  /// @return true iff @p c is the canonical type that @p t should
  /// have.
  bool
  check_abixml_canonical_type_propagation_during_self_comp(const type_base* t)
  {
    if (t->get_corpus()
	&& t->get_corpus()->get_origin() == ir::corpus::NATIVE_XML_ORIGIN)
      {
	type_base* c = t->get_naked_canonical_type();
	if (c && !check_canonical_type_from_abixml_during_self_comp(t, c))
	  {
	    string repr = t->get_pretty_representation(true, true);
	    string type_id = get_type_id_from_type(t);
	    std::cerr << "error: canonical type propagation error for '"
		      << repr
		      << "' of type-id: '"
		      << type_id
		      << "' / type: @"
		      << std::hex
		      << t
		      << "/ canon: @"
		      << c
		      << ", should have had canonical type: "
		      << std::hex
		      << get_canonical_type_from_type_id(type_id.c_str())
		      << "\n";
	    return false;
	  }
      }
    return true;
  }

  /// When debugging self comparison, verify that a type T
  /// de-serialized from abixml has the same canonical type as the
  /// initial type built from DWARF that was serialized into T in the
  /// first place.
  ///
  /// @param t deserialized type (from abixml) to consider.
  ///
  /// @param c the canonical type @p t should have.
  ///
  /// @return true iff @p c is the canonical type that @p t should
  /// have.
  bool
  check_canonical_type_from_abixml_during_self_comp(const type_base_sptr& t,
						    const type_base_sptr& c)
  {
    return check_canonical_type_from_abixml_during_self_comp(t.get(), c.get());
  }
#endif
};// end struct environment::priv

bool
compare_using_locations(const decl_base *f,
			const decl_base *s);

/// A functor to sort decls somewhat topologically.  That is, types
/// are sorted in a way that makes the ones that are defined "first"
/// to come first.
///
/// The topological criteria is a lexicographic sort of the definition
/// location of the type.  For types that have no location (or the
/// same location), it's their qualified name that is used for the
/// lexicographic sort.
struct decl_topo_comp
{
  /// Test if a decl has an artificial or natural location.
  ///
  /// @param d the decl to consider
  ///
  /// @return true iff @p d has a location.
  bool
  has_artificial_or_natural_location(const decl_base* d)
  {return get_artificial_or_natural_location(d).get_value();}

  /// Test if a type has an artificial or natural location.
  ///
  /// @param t the type to consider
  ///
  /// @return true iff @p t has a location.
  bool
  has_artificial_or_natural_location(const type_base* t)
  {
    if (decl_base *d = is_decl(t))
      return has_artificial_or_natural_location(d);
    return false;
  }

  /// The "Less Than" comparison operator of this functor.
  ///
  /// @param f the first decl to be considered for the comparison.
  ///
  /// @param s the second decl to be considered for the comparison.
  ///
  /// @return true iff @p f is less than @p s.
  bool
  operator()(const decl_base *f,
	     const decl_base *s)
  {
    if (!!f != !!s)
      return f && !s;

    if (!f)
      return false;

    // Unique types that are artificially created in the environment
    // don't have locations.  They ought to be compared on the basis
    // of their pretty representation before we start looking at IR
    // nodes' locations down the road.
    if (is_unique_type(is_type(f)) || is_unique_type(is_type(s)))
      return (f->get_cached_pretty_representation(/*internal=*/false)
	      < s->get_cached_pretty_representation(/*internal=*/false));

    // If both decls come from an abixml file, keep the order they
    // have from that abixml file.
    if (has_artificial_or_natural_location(f)
	&& has_artificial_or_natural_location(s)
	&& (((!f->get_corpus() && !s->get_corpus())
	     || (f->get_corpus() && f->get_corpus()->get_origin() == corpus::NATIVE_XML_ORIGIN
		 && s->get_corpus() && s->get_corpus()->get_origin() == corpus::NATIVE_XML_ORIGIN))))
      return compare_using_locations(f, s);

    // If a decl has artificial location, then use that one over the
    // natural one.
    location fl = get_artificial_or_natural_location(f);
    location sl = get_artificial_or_natural_location(s);

    if (fl.get_value() && sl.get_value())
      return compare_using_locations(f, s);
    else if (!!fl != !!sl)
      // So one of the decls doesn't have location data.
      // The first decl is less than the second if it's the one not
      // having location data.
      return !fl && sl;

    // We reach this point if location data is useless.
    if (f->get_is_anonymous()
	&& s->get_is_anonymous()
	&& (f->get_cached_pretty_representation(/*internal=*/false)
	    == s->get_cached_pretty_representation(/*internal=*/false)))
      return f->get_name() < s->get_name();

    return (f->get_cached_pretty_representation(/*internal=*/false)
	    < s->get_cached_pretty_representation(/*internal=*/false));
  }

  /// The "Less Than" comparison operator of this functor.
  ///
  /// @param f the first decl to be considered for the comparison.
  ///
  /// @param s the second decl to be considered for the comparison.
  ///
  /// @return true iff @p f is less than @p s.
  bool
  operator()(const decl_base_sptr &f,
	     const decl_base_sptr &s)
  {return operator()(f.get(), s.get());}

}; // end struct decl_topo_comp

bool
is_ptr_ref_or_qual_type(const type_base *t);

/// A functor to sort types somewhat topologically.  That is, types
/// are sorted in a way that makes the ones that are defined "first"
/// to come first.
///
/// The topological criteria is a lexicographic sort of the definition
/// location of the type.  For types that have no location, it's their
/// qualified name that is used for the lexicographic sort.
struct type_topo_comp
{
  /// Test if a decl has an artificial or natural location.
  ///
  /// @param d the decl to consider
  ///
  /// @return true iff @p d has a location.
  bool
  has_artificial_or_natural_location(const decl_base* d)
  {return get_artificial_or_natural_location(d).get_value();}

  /// Test if a type has an artificial or natural location.
  ///
  /// @param t the type to consider
  ///
  /// @return true iff @p t has a location.
  bool
  has_artificial_or_natural_location(const type_base* t)
  {
    if (decl_base *d = is_decl(t))
      return has_artificial_or_natural_location(d);
    return false;
  }

  /// The "Less Than" comparison operator of this functor.
  ///
  /// @param f the first type to be considered for the comparison.
  ///
  /// @param s the second type to be considered for the comparison.
  ///
  /// @return true iff @p f is less than @p s.
  bool
  operator()(const type_base_sptr &f,
	     const type_base_sptr &s)
  {return operator()(f.get(), s.get());}

  /// The "Less Than" comparison operator of this functor.
  ///
  /// @param f the first type to be considered for the comparison.
  ///
  /// @param s the second type to be considered for the comparison.
  ///
  /// @return true iff @p f is less than @p s.
  bool
  operator()(const type_base *f,
	     const type_base *s)
  {
    if (f == s || !f || !s)
      return false;

    // If both decls come from an abixml file, keep the order they
    // have from that abixml file.
    if (is_decl(f) && is_decl(s)
	&& has_artificial_or_natural_location(f)
	&& has_artificial_or_natural_location(s)
	&& ((!f->get_corpus() && !s->get_corpus())
	    || (f->get_corpus()
		&& f->get_corpus()->get_origin() == corpus::NATIVE_XML_ORIGIN
		&& s->get_corpus()
		&& (s->get_corpus()->get_origin()
		    == corpus::NATIVE_XML_ORIGIN))))
      return compare_using_locations(is_decl(f), is_decl(s));

    bool f_is_ptr_ref_or_qual = is_ptr_ref_or_qual_type(f);
    bool s_is_ptr_ref_or_qual = is_ptr_ref_or_qual_type(s);

    if (f_is_ptr_ref_or_qual != s_is_ptr_ref_or_qual)
      return !f_is_ptr_ref_or_qual && s_is_ptr_ref_or_qual;

    if (f_is_ptr_ref_or_qual && s_is_ptr_ref_or_qual
	&& !has_artificial_or_natural_location(f)
	&& !has_artificial_or_natural_location(s))
      {
	interned_string s1 = f->get_cached_pretty_representation(/*internal=*/false);
	interned_string s2 = s->get_cached_pretty_representation(/*internal=*/false);
	if (s1 == s2)
	  {
	    if (qualified_type_def * q = is_qualified_type(f))
	      {
		if (q->get_cv_quals() == qualified_type_def::CV_NONE)
		  if (!is_qualified_type(s))
		    // We are looking at two types that are the result of
		    // an optimization that happens during the IR
		    // construction.  Namely, type f is a cv-qualified
		    // type with no qualifier (no const, no volatile, no
		    // nothing, we call it an empty-qualified type).
		    // These are the result of an optimization which
		    // removes "redundant qualifiers" from some types.
		    // For instance, consider a "const reference".  The
		    // const there is redundant because a reference is
		    // always const.  So as a result of the optimizaton
		    // that type is going to be transformed into an
		    // empty-qualified reference. If we don't make that
		    // optimization, then we risk having spurious change
		    // reports down the road.  But then, as a consequence
		    // of that optimization, we need to sort the
		    // empty-qualified type and its non-qualified variant
		    // e.g, to ensure stability in the abixml output; both
		    // types are logically equal, but here, we decide that
		    // the empty-qualified one is topologically "less
		    // than" the non-qualified counterpart.
		    //
		    // So here, type f is an empty-qualified type and type
		    // s is its non-qualified variant.  We decide that f
		    // is topologically less than s.
		    return true;
	      }
	    // Now let's peel off the pointer (or reference types) and
	    // see if the ultimate underlying types have the same
	    // textual representation; if not, use that as sorting
	    // criterion.
	    type_base *peeled_f =
	      peel_pointer_or_reference_type(f, true);
	    type_base *peeled_s =
	      peel_pointer_or_reference_type(s, true);

	    s1 = peeled_f->get_cached_pretty_representation(/*internal=*/false);
	    s2 = peeled_s->get_cached_pretty_representation(/*internal=*/false);
	    if (s1 != s2)
	      return s1 < s2;

	    // The underlying type of pointer/reference have the same
	    // textual representation; let's try to peel of typedefs
	    // as well and we'll consider sorting the result as decls.
	    peeled_f = peel_typedef_pointer_or_reference_type(peeled_f, true);
	    peeled_s = peel_typedef_pointer_or_reference_type(peeled_s, true);

	    s1 = peeled_f->get_cached_pretty_representation(false);
	    s2 = peeled_s->get_cached_pretty_representation(false);
	    if (s1 != s2)
	      return s1 < s2;
	  }
      }

    interned_string s1 = f->get_cached_pretty_representation(false);
    interned_string s2 = s->get_cached_pretty_representation(false);

    if (s1 != s2)
      return s1 < s2;

    if (is_typedef(f) && is_typedef(s))
      {
	s1 = is_typedef(f)->get_underlying_type()->get_cached_pretty_representation(false);
	s2 = is_typedef(s)->get_underlying_type()->get_cached_pretty_representation(false);
	if (s1 != s2)
	  return s1 < s2;
      }

    type_base *peeled_f = peel_typedef_pointer_or_reference_type(f, true);
    type_base *peeled_s = peel_typedef_pointer_or_reference_type(s, true);

    s1 = peeled_f->get_cached_pretty_representation(false);
    s2 = peeled_s->get_cached_pretty_representation(false);

    if (s1 != s2)
      return s1 < s2;

    if (method_type* m_f = is_method_type(peeled_f))
      if (method_type* m_s = is_method_type(peeled_s))
      {
	// If two method types differ from their const-ness, make the
	// const one come first.
	if (m_f->get_is_const() != m_s->get_is_const())
	  return m_f->get_is_const();

	// If two method types have the same name (textual
	// representation), make the non-static one come first.
	if (m_f->get_is_for_static_method() != m_s->get_is_for_static_method())
	  return m_f->get_is_for_static_method() < m_s->get_is_for_static_method();
      }

    decl_base *fd = is_decl(f);
    decl_base *sd = is_decl(s);

    if (!!fd != !!sd)
      return fd && !sd;

    if (!fd
	&& f->get_translation_unit()
	&& s->get_translation_unit())
      {
	string s1 = f->get_translation_unit()->get_absolute_path();
	string s2 = s->get_translation_unit()->get_absolute_path();
	return s1 < s2;
      }

    // If all pretty representions are equal, sort by
    // hash value and canonical type index.
    hash_t h_f = peek_hash_value(*f);
    hash_t h_s = peek_hash_value(*s);
    if (h_f && h_s && *h_f != *h_s)
      return *h_f < *h_s;

    size_t cti_f = get_canonical_type_index(*f);
    size_t cti_s = get_canonical_type_index(*s);
    if (cti_f != cti_s)
      return cti_f < cti_s;

    // If the two types have no decls, how come we could not sort them
    // until now? Let's investigate.
    ABG_ASSERT(fd);

    // From this point, fd and sd should be non-nil
    decl_topo_comp decl_comp;
    return decl_comp(fd, sd);
  }
}; //end struct type_topo_comp

/// Functor used to sort types before hashing them.
struct sort_for_hash_functor
{
  /// Return the rank of a given kind of IR node.
  ///
  /// The rank is used to sort a kind of IR node relative to another
  /// one of a different kind.  For instance, a an IR node of
  /// BASIC_TYPE kind has a lower rank than an IR node of ENUM_TYPE
  /// kind.
  ///
  /// @param k the kind of a given IR node.
  ///
  /// @return the rank of the IR node.
  size_t
  rank(enum type_or_decl_base::type_or_decl_kind k)
  {
    size_t result = 0;

    if (k & type_or_decl_base::BASIC_TYPE)
      result = 1;
    if (k & type_or_decl_base::SUBRANGE_TYPE)
      result = 2;
    else if (k & type_or_decl_base::ENUM_TYPE)
      result = 3;
    else if (k & type_or_decl_base::CLASS_TYPE)
      result = 4;
    else if (k & type_or_decl_base::UNION_TYPE)
      result = 5;
    else if (k & type_or_decl_base::FUNCTION_TYPE)
      result = 6;
    else if (k & type_or_decl_base::METHOD_TYPE)
      result = 7;
    else if (k & type_or_decl_base::TYPEDEF_TYPE)
      result = 8;
    else if (k & type_or_decl_base::QUALIFIED_TYPE)
      result = 9;
    else if (k & type_or_decl_base::POINTER_TYPE)
      result = 10;
    else if (k & type_or_decl_base::REFERENCE_TYPE)
      result = 11;
    else if (k & type_or_decl_base::POINTER_TO_MEMBER_TYPE)
      result = 12;
    else if (k & type_or_decl_base::ARRAY_TYPE)
      result = 13;

    return result;
  }

  /// "Less Than" operator for type IR nodes.
  ///
  /// This returns true iff the first operand is less than the second
  /// one.
  ///
  /// IR nodes are first sorted using their rank.  Two IR node of the
  /// same rank are then sorted using their qualified name.
  ///
  /// @param f the first operand to consider.
  ///
  /// @param s the second operand to consider.
  bool
  operator()(const type_base& f, const type_base& s)
  {
    size_t rank_f = rank(f.kind()),
      rank_s = rank(s.kind());

    // If rank_f or rank_s is zero, it probably means there is a new
    // type IR kind that needs proper ranking.
    ABG_ASSERT(rank_f != 0 && rank_s != 0);

    bool result = false;
    if (rank_f < rank_s)
      result = true;
    else if (rank_f == rank_s)
      {
	type_topo_comp comp;
	result = comp(&f,&s);
      }
    return result;
  }

  /// "Less Than" operator for type IR nodes.
  ///
  /// This returns true iff the first operand is less than the second
  /// one.
  ///
  /// IR nodes are first sorted using their rank.  Two IR node of the
  /// same rank are then sorted using their qualified name.
  ///
  /// @param f the first operand to consider.
  ///
  /// @param s the second operand to consider.
  bool
  operator()(const type_base* f, const type_base* s)
  {
    return operator()(*f, *s);
  }

  /// "Less Than" operator for type IR nodes.
  ///
  /// This returns true iff the first operand is less than the second
  /// one.
  ///
  /// IR nodes are first sorted using their rank.  Two IR node of the
  /// same rank are then sorted using their qualified name.
  ///
  /// @param f the first operand to consider.
  ///
  /// @param s the second operand to consider.  
  bool
  operator()(const type_base_sptr& f, const type_base_sptr& s)
  {
    return operator()(f.get(), s.get());
  }
};//end struct sort_for_hash_functor

/// Sort types before hashing (and then canonicalizing) them.
///
/// @param begin an iterator pointing to the beginning of the sequence
/// of types to sort.
///
/// @param end an iterator pointing to the end of the sequence of
/// types to sort.
template <typename IteratorType>
void
sort_types_for_hash_computing_and_c14n(IteratorType begin,
				       IteratorType end)
{
  sort_for_hash_functor comp;
  return std::stable_sort(begin, end, comp);
}

void
sort_types_for_hash_computing_and_c14n(vector<type_base_sptr>& types);

/// Compute the canonical type for all the IR types of the system.
///
/// After invoking this function, the time it takes to compare two
/// types of the IR is equivalent to the time it takes to compare
/// their pointer value.  That is faster than performing a structural
/// (A.K.A. member-wise) comparison.
///
/// Note that this function performs some sanity checks after* the
/// canonicalization process.  It ensures that at the end of the
/// canonicalization process, all types have been canonicalized.  This
/// is important because the canonicalization algorithm sometimes
/// clears some canonical types after having speculatively set them
/// for performance purposes.  At the end of the process however, all
/// types must be canonicalized, and this function detects violations
/// of that assertion.
///
/// @tparam input_iterator the type of the input iterator of the @p
/// beging and @p end.
///
/// @tparam deref_lambda a lambda function which takes in parameter
/// the input iterator of type @p input_iterator and dereferences it
/// to return the type to canonicalize.
///
/// @param begin an iterator pointing to the first type of the set of types
/// to canonicalize.
///
/// @param end an iterator pointing past-the-end (after the last type) of
/// the set of types to canonicalize.
///
/// @param deref a lambda function that knows how to dereference the
/// iterator @p begin to return the type to canonicalize.
template<typename input_iterator,
	 typename deref_lambda>
void
canonicalize_types(const input_iterator& begin,
		   const input_iterator& end,
		   deref_lambda deref,
		   bool do_log = false,
		   bool show_stats = false)
{
  if (begin == end)
    return;

  auto first_iter = begin;
  auto first = deref(first_iter);
  environment& env = const_cast<environment&>(first->get_environment());

  env.canonicalization_started(true);

  int i;
  input_iterator t;
  // First, let's compute the canonical type of this type.
  tools_utils::timer tmr;
  if (do_log)
    {
      std::cerr << "Canonicalizing types ...\n";
      tmr.start();
    }

  for (t = begin,i = 0; t != end; ++t, ++i)
    {
      if (do_log && show_stats)
	std::cerr << "#" << std::dec << i << " ";

      canonicalize(deref(t));
    }

  env.canonicalization_is_done(true);

  if (do_log)
    {
      tmr.stop();
      std::cerr << "Canonicalizing of types DONE in: " << tmr << "\n\n";
      tmr.start();
    }
}

/// Hash and canonicalize a sequence of types.
///
/// Note that this function first sorts the types, then hashes them
/// and then canonicalizes them.
///
/// Operations must be done in that order to get predictable results.
///
/// @param begin an iterator pointing to the first element of the
/// sequence of types to hash and canonicalize.
///
/// @param begin an iterator pointing past-the-end of the sequence of
/// types to hash and canonicalize.
///
/// @param deref this is a lambda that is used to dereference the
/// types contained in the sequence referenced by iterators @p begin
/// and @p end.
template <typename IteratorType,
	  typename deref_lambda>
void
hash_and_canonicalize_types(IteratorType	begin,
			    IteratorType	end,
			    deref_lambda	deref,
			    bool do_log = false,
			    bool show_stats = false)
{
  tools_utils::timer tmr;
  if (do_log)
    {
      std::cerr << "sorting types before canonicalization ... \n";
      tmr.start();
    }

  sort_types_for_hash_computing_and_c14n(begin, end);

  if (do_log)
    {
      tmr.stop();
      std::cerr << "sorted types for c14n in: " << tmr << "\n\n";

      std::cerr << "hashing types before c14n ...\n";
      tmr.start();
    }

  for (IteratorType t = begin; t != end; ++t)
    if (!peek_hash_value(*deref(t)))
      (*t)->hash_value();

  if (do_log)
    {
      tmr.stop();
      std::cerr << "hashed types in: " << tmr << "\n\n";
    }

  canonicalize_types(begin, end, deref, do_log, show_stats);
}

/// Sort and canonicalize a sequence of types.
///
/// Note that this function does NOT hash the types.  It thus assumes
/// that the types are allready hashed.
///
/// Operations must be done in that order (sorting and then
/// canonicalizing) to get predictable results.
///
/// @param begin an iterator pointing to the first element of the
/// sequence of types to hash and canonicalize.
///
/// @param begin an iterator pointing past-the-end of the sequence of
/// types to hash and canonicalize.
///
/// @param deref this is a lambda that is used to dereference the
/// types contained in the sequence referenced by iterators @p begin
/// and @p end.
template <typename IteratorType,
	  typename deref_lambda>
void
sort_and_canonicalize_types(IteratorType	begin,
			    IteratorType	end,
			    deref_lambda	deref)
{
  sort_types_for_hash_computing_and_c14n(begin, end);
  canonicalize_types(begin, end, deref);
}

// <class_or_union::priv definitions>
struct class_or_union::priv
{
  typedef_decl_wptr		naming_typedef_;
  data_members			data_members_;
  data_members			static_data_members_;
  data_members			non_static_data_members_;
  member_functions		member_functions_;
  // A map that associates a linkage name to a member function.
  string_mem_fn_sptr_map_type	mem_fns_map_;
  // A map that associates function signature strings to member
  // function.
  string_mem_fn_ptr_map_type	signature_2_mem_fn_map_;
  member_function_templates	member_function_templates_;
  member_class_templates	member_class_templates_;
  bool				is_printing_flat_representation_ = false;
  // The set of classes which layouts are currently being compared
  // against this one.  This is to avoid endless loops.
  unordered_set<type_base*>	comparing_class_layouts_;
  priv()
  {}

  priv(class_or_union::data_members& data_mbrs,
       class_or_union::member_functions& mbr_fns)
    : data_members_(data_mbrs),
      member_functions_(mbr_fns)
  {
    for (const auto& data_member: data_members_)
      if (get_member_is_static(data_member))
	static_data_members_.push_back(data_member);
      else
	non_static_data_members_.push_back(data_member);
  }

  /// Mark a pair of classes or unions as being currently compared
  /// using the class_or_union== operator.
  ///
  /// Note that this marking business is to avoid infinite loop when
  /// comparing a pair of classes or unions. If via the comparison of
  /// a data member or a member function a recursive re-comparison of
  /// the class or union is attempted, the marking process helps to
  /// detect that infinite loop possibility and avoid it.
  ///
  /// @param first the class or union (of the pair) to mark as being
  /// currently compared.
  ///
  /// @param second the second class or union (of the pair) to mark as
  /// being currently compared.
  void
  mark_as_being_compared(const class_or_union& first,
			 const class_or_union& second) const
  {
    const environment& env = first.get_environment();

    env.priv_->left_classes_being_compared_.insert(&first);
    env.priv_->right_classes_being_compared_.insert(&second);
  }

  /// Mark a pair of classes or unions as being currently compared
  /// using the class_or_union== operator.
  ///
  /// Note that this marking business is to avoid infinite loop when
  /// comparing a pair of classes or unions. If via the comparison of
  /// a data member or a member function a recursive re-comparison of
  /// the class or union is attempted, the marking process helps to
  /// detect that infinite loop possibility and avoid it.
  ///
  /// @param first the class or union (of the pair) to mark as being
  /// currently compared.
  ///
  /// @param second the second class or union (of the pair) to mark as
  /// being currently compared.
  void
  mark_as_being_compared(const class_or_union* first,
			 const class_or_union* second) const
  {mark_as_being_compared(*first, *second);}

  /// Mark a pair of classes or unions as being currently compared
  /// using the class_or_union== operator.
  ///
  /// Note that this marking business is to avoid infinite loop when
  /// comparing a pair of classes or unions. If via the comparison of
  /// a data member or a member function a recursive re-comparison of
  /// the class or union is attempted, the marking process helps to
  /// detect that infinite loop possibility and avoid it.
  ///
  /// @param first the class or union (of the pair) to mark as being
  /// currently compared.
  ///
  /// @param second the second class or union (of the pair) to mark as
  /// being currently compared.
  void
  mark_as_being_compared(const class_or_union_sptr& first,
			 const class_or_union_sptr& second) const
  {mark_as_being_compared(*first, *second);}

  /// If a pair of class_or_union has been previously marked as
  /// being compared -- via an invocation of mark_as_being_compared()
  /// this method unmarks it.  Otherwise is has no effect.
  ///
  /// This method is not thread safe because it uses the static data
  /// member classes_being_compared_.  If you wish to use it in a
  /// multi-threaded environment you should probably protect the
  /// access to that static data member with a mutex or somesuch.
  ///
  /// @param first the first instance of class_or_union (of the pair)
  /// to unmark.
  ///
  /// @param second the second instance of class_or_union (of the
  /// pair) to unmark.
  void
  unmark_as_being_compared(const class_or_union& first,
			   const class_or_union& second) const
  {
    const environment& env = first.get_environment();

    env.priv_->left_classes_being_compared_.erase(&first);
    env.priv_->right_classes_being_compared_.erase(&second);
  }

  /// If a pair of class_or_union has been previously marked as
  /// being compared -- via an invocation of mark_as_being_compared()
  /// this method unmarks it.  Otherwise is has no effect.
  ///
  /// This method is not thread safe because it uses the static data
  /// member classes_being_compared_.  If you wish to use it in a
  /// multi-threaded environment you should probably protect the
  /// access to that static data member with a mutex or somesuch.
  ///
  /// @param first the first instance of class_or_union (of the pair)
  /// to unmark.
  ///
  /// @param second the second instance of class_or_union (of the
  /// pair) to unmark.
  void
  unmark_as_being_compared(const class_or_union* first,
			   const class_or_union* second) const
  {
    if (!first || !second)
      return;
    unmark_as_being_compared(*first, *second);
  }

  /// Test if a pair of class_or_union is being currently compared.
  ///
  ///@param first the first class or union (of the pair) to test for.
  ///
  ///@param second the second class or union (of the pair) to test for.
  ///
  /// @return true if the pair {@p first, @p second} is being
  /// compared, false otherwise.
  bool
  comparison_started(const class_or_union& first,
		     const class_or_union& second) const
  {
    const environment& env = first.get_environment();

    return (env.priv_->left_classes_being_compared_.count(&first)
	    || env.priv_->right_classes_being_compared_.count(&second)
	    || env.priv_->right_classes_being_compared_.count(&first)
	    || env.priv_->left_classes_being_compared_.count(&second));
  }

  /// Test if a pair of class_or_union is being currently compared.
  ///
  ///@param first the first class or union (of the pair) to test for.
  ///
  ///@param second the second class or union (of the pair) to test for.
  ///
  /// @return true if the pair {@p first, @p second} is being
  /// compared, false otherwise.
  bool
  comparison_started(const class_or_union* first,
		     const class_or_union* second) const
  {
    if (first && second)
      return comparison_started(*first, *second);
    return false;
  }

  /// Set the 'is_printing_flat_representation_' boolean to true.
  ///
  /// That boolean marks the fact that the current @ref class_or_union
  /// (and its sub-types graph) is being walked for the purpose of
  /// printing its flat representation.  This is useful to detect
  /// cycles in the graph and avoid endless loops.
  void
  set_printing_flat_representation()
  {is_printing_flat_representation_ = true;}

  /// Set the 'is_printing_flat_representation_' boolean to false.
  ///
  /// That boolean marks the fact that the current @ref class_or_union
  /// (and its sub-types graph) is being walked for the purpose of
  /// printing its flat representation.  This is useful to detect
  /// cycles in the graph and avoid endless loops.
  void
  unset_printing_flat_representation()
  {is_printing_flat_representation_ = false;}

  /// Getter of the 'is_printing_flat_representation_' boolean.
  ///
  /// That boolean marks the fact that the current @ref class_or_union
  /// (and its sub-types graph) is being walked for the purpose of
  /// printing its flat representation.  This is useful to detect
  /// cycles in the graph and avoid endless loops.
  bool
  is_printing_flat_representation() const
  {return is_printing_flat_representation_;}
}; // end struct class_or_union::priv

// <function_type::priv definitions>

/// The type of the private data of the @ref function_type type.
struct function_type::priv
{
  parameters parms_;
  type_base_wptr return_type_;
  interned_string cached_name_;
  interned_string internal_cached_name_;
  interned_string temp_internal_cached_name_;
  bool is_pretty_printing_ = false;
  priv()
  {}

  priv(const parameters&	parms,
       type_base_sptr		return_type)
    : parms_(parms),
      return_type_(return_type)
  {}

  priv(type_base_sptr return_type)
    : return_type_(return_type)
  {}

  /// Mark a given pair of @ref function_type as being compared.
  ///
  /// @param first the first @ref function_type of the pair being
  /// compared, to mark.
  ///
  /// @param second the second @ref function_type of the pair being
  /// compared, to mark.
  void
  mark_as_being_compared(const function_type& first,
			 const function_type& second) const
  {
    const environment& env = first.get_environment();

    env.priv_->left_fn_types_being_compared_.insert(&first);
    env.priv_->right_fn_types_being_compared_.insert(&second);
  }

  /// Mark a given pair of @ref function_type as being compared.
  ///
  /// @param first the first @ref function_type of the pair being
  /// compared, to mark.
  ///
  /// @param second the second @ref function_type of the pair being
  /// compared, to mark.
  void
  unmark_as_being_compared(const function_type& first,
			   const function_type& second) const
  {
    const environment& env = first.get_environment();

    env.priv_->left_fn_types_being_compared_.erase(&first);
    env.priv_->right_fn_types_being_compared_.erase(&second);
  }

  /// Tests if a @ref function_type is currently being compared.
  ///
  /// @param type the function type to take into account.
  ///
  /// @return true if @p type is being compared.
  bool
  comparison_started(const function_type& first,
		     const function_type& second) const
  {
    const environment& env = first.get_environment();

    return (env.priv_->left_fn_types_being_compared_.count(&first)
	    ||
	    env.priv_->right_fn_types_being_compared_.count(&second));
  }

  /// Set the 'is_pretty_printing_' boolean to true.
  ///
  /// That boolean marks the fact that the current @ref function_type
  /// (and its sub-types graph) is being walked for the purpose of
  /// printing its flat representation.  This is useful to detect
  /// cycles in the graph and avoid endless loops.
  void
  set_is_pretty_printing()
  {is_pretty_printing_ = true;}

  /// Set the 'is_pretty_printing_' boolean to false.
  ///
  /// That boolean marks the fact that the current @ref function_type
  /// (and its sub-types graph) is being walked for the purpose of
  /// printing its flat representation.  This is useful to detect
  /// cycles in the graph and avoid endless loops.
  void
  unset_is_pretty_printing()
  {is_pretty_printing_ = false;}

  /// Getter of the 'is_pretty_printing_' boolean.
  ///
  /// That boolean marks the fact that the current @ref function_type
  /// (and its sub-types graph) is being walked for the purpose of
  /// printing its flat representation.  This is useful to detect
  /// cycles in the graph and avoid endless loops.
  bool
  is_pretty_printing() const
  {return is_pretty_printing_;}
};// end struc function_type::priv

// </function_type::priv definitions>

size_t
get_canonical_type_index(const type_base& t);

bool
type_originates_from_corpus(type_base_sptr t, corpus_sptr& c);
} // end namespace ir

} // end namespace abigail

#endif // __ABG_IR_PRIV_H__
