// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- Mode: C++ -*-
//
// Copyright (C) 2016-2023 Red Hat, Inc.
//
// Author: Dodji Seketeli

#ifndef __ABG_SUPPRESSION_H__
#define __ABG_SUPPRESSION_H__

#include <unordered_set>

#include "abg-ini.h"
#include "abg-ir.h"

namespace abigail
{

class fe_iface;

/// @brief an engine to suppress the parts of the result of comparing
/// two sets of ABI artifacts.
///
/// The user specifies the kind of changes between ABI artefact she
/// wants to see suppressed.  That suppression specification is done
/// in an INI format.
///
/// That INI file is parsed and represented internally using the types
/// that are defined in this namespace.
namespace suppr
{
using std::unordered_set;
using std::string;
using std::shared_ptr;
using std::vector;
using comparison::diff;
using comparison::diff_context_sptr;

/// Base type of a direct suppression specifications types.
///
/// This abstracts a suppression specification.  It's a way to specify
/// how to drop reports about a particular diff node on the floor, if
/// it matches the supppression specification.
///
/// Note that a direct suppression specification suppresses (for
/// reporting purposes) the diff node that it matches.  A negated
/// suppression specification, however, suppresses a diff node that it
/// DOES NOT match.  A Negated suppression specification is abstracted
/// by the class @ref negated_suppression_base.
class suppression_base
{
public:
  class priv; // declare publicly to allow subclasses to reuse the priv
private:
  // Forbid default constructor
  suppression_base();

public:
  std::unique_ptr<priv> priv_;

  suppression_base(const string& label);

  suppression_base(const string& label,
		   const string& file_name_regex_str,
		   const string& file_name_not_regex_str);

  bool
  get_drops_artifact_from_ir() const;

  void
  set_drops_artifact_from_ir(bool);

  bool
  get_is_artificial() const;

  void
  set_is_artificial(bool);

  const string
  get_label() const;

  void
  set_label(const string&);

  void
  set_file_name_regex_str(const string& regexp);

  const string&
  get_file_name_regex_str() const;

  void
  set_file_name_not_regex_str(const string& regexp);

  const string&
  get_file_name_not_regex_str() const;

  bool
  has_file_name_related_property() const;

  void
  set_soname_regex_str(const string& regexp);

  const string&
  get_soname_regex_str() const;

  void
  set_soname_not_regex_str(const string& regexp);

  const string&
  get_soname_not_regex_str() const;

  bool
  has_soname_related_property() const;

  virtual bool
  suppresses_diff(const diff*) const = 0;

  virtual ~suppression_base();

  friend bool
  suppression_matches_soname(const string& soname,
			     const suppression_base& suppr);

  friend bool
  suppression_matches_soname_or_filename(const string& soname,
					 const string& filename,
					 const suppression_base& suppr);
}; // end class suppression_base

/// Convenience typedef for a shared pointer to a @ref suppression.
typedef shared_ptr<suppression_base> suppression_sptr;

/// Convenience typedef for a vector of @ref suppression_sptr
typedef vector<suppression_sptr> suppressions_type;

void
read_suppressions(std::istream& input,
		  suppressions_type& suppressions);

void
read_suppressions(const string& file_path,
		  suppressions_type& suppressions);

class type_suppression;

/// Convenience typedef for a shared pointer to type_suppression.
typedef shared_ptr<type_suppression> type_suppression_sptr;

/// Convenience typedef for vector of @ref type_suppression_sptr.
typedef vector<type_suppression_sptr> type_suppressions_type;

/// The base class of suppression specifications that are defined by
/// the negation of matching clauses.
///
/// A direct suppression specification suppresses (for reporting
/// purposes) the diff node that it matches.  A negated suppression
/// specification suppresses a diff node that it DOES NOT match.
class negated_suppression_base
{
public:
  negated_suppression_base();

  virtual ~negated_suppression_base();
}; // end class negated_suppression_base.

/// A convenience typedef for a shared pointer to @ref
/// negated_suppression_base.
typedef shared_ptr<negated_suppression_base> negated_suppression_sptr;

/// Convenience typedef for a vector of @ref negated_suppression_sptr
typedef vector<negated_suppression_sptr> negated_suppressions_type;

bool
is_negated_suppression(const suppression_base&);

const negated_suppression_base*
is_negated_suppression(const suppression_base*);

negated_suppression_sptr
is_negated_suppression(const suppression_sptr&);

/// Abstraction of a type suppression specification.
///
/// Specifies under which condition reports about a type diff node
/// should be dropped on the floor.
class type_suppression : public suppression_base
{
  class priv;

  // Forbid this;
  type_suppression();

public:
  std::unique_ptr<priv> priv_;

  /// The kind of the type the current type suppression is supposed to
  /// be about.
  enum type_kind
  {
    UNKNOWN_TYPE_KIND,
    CLASS_TYPE_KIND,
    STRUCT_TYPE_KIND,
    UNION_TYPE_KIND,
    ENUM_TYPE_KIND,
    ARRAY_TYPE_KIND,
    TYPEDEF_TYPE_KIND,
    BUILTIN_TYPE_KIND
  }; // end enum type_kind

  /// The different ways through which the type diff has been reached.
  enum reach_kind
  {
    /// The type diff has been reached (from a function or variable
    /// change) directly.
    DIRECT_REACH_KIND = 0,

    /// The type diff has been reached (from a function or variable
    /// change) through a pointer.
    POINTER_REACH_KIND,

    /// The type diff has been reached (from a function or variable
    /// change) through a reference; you know, like a c++ reference..
    REFERENCE_REACH_KIND,

    /// The type diff has been reached (from a function or variable
    /// change) through either a reference or a pointer.
    REFERENCE_OR_POINTER_REACH_KIND
  }; // end enum reach_kind

  class insertion_range;
  /// A convenience typedef for a shared pointer to @ref
  /// insertion_range.
  typedef shared_ptr<insertion_range> insertion_range_sptr;
  /// A convenience typedef for a vector of @ref insertion_range_sptr.
  typedef vector<insertion_range_sptr> insertion_ranges;

  type_suppression(const string& label,
		   const string& type_name_regexp,
		   const string& type_name);

  virtual ~type_suppression();

  void
  set_type_name_regex_str(const string& name_regex_str);

  const string&
  get_type_name_regex_str() const;

  void
  set_type_name_not_regex_str(const string& name_regex_str);

  const string&
  get_type_name_not_regex_str() const;

  void
  set_type_name(const string& name);

  const string&
  get_type_name() const;

  bool
  get_consider_type_kind() const;

  void
  set_consider_type_kind(bool f);

  void
  set_type_kind(type_kind k);

  type_kind
  get_type_kind() const;

  bool
  get_consider_reach_kind() const;

  void
  set_consider_reach_kind(bool f);

  reach_kind
  get_reach_kind() const;

  void
  set_reach_kind(reach_kind k);

  bool
  get_has_size_change() const;

  void
  set_has_size_change(bool flag);

  const string_set_type&
  get_potential_data_member_names() const;

  void
  set_potential_data_member_names(const string_set_type&) const;

  const string&
  get_potential_data_member_names_regex_str() const;

  void
  set_potential_data_member_names_regex_str(const string&) const;

  void
  set_data_member_insertion_ranges(const insertion_ranges& r);

  const insertion_ranges&
  get_data_member_insertion_ranges() const;

  insertion_ranges&
  get_data_member_insertion_ranges();

  const unordered_set<string>&
  get_source_locations_to_keep() const;

  unordered_set<string>&
  get_source_locations_to_keep();

  void
  set_source_locations_to_keep(const unordered_set<string>&);

  const string&
  get_source_location_to_keep_regex_str() const;

  void
  set_source_location_to_keep_regex_str(const string&);

  const vector<string>&
  get_changed_enumerator_names() const;

  void
  set_changed_enumerator_names(const vector<string>&);

  const vector<regex::regex_t_sptr>&
  get_changed_enumerators_regexp() const;

  void
  set_changed_enumerators_regexp(const vector<regex::regex_t_sptr>&);

  virtual bool
  suppresses_diff(const diff* diff) const;

  bool
  suppresses_type(const type_base_sptr& type,
		  const diff_context_sptr& ctxt) const;

  bool
  suppresses_type(const type_base_sptr& type) const;

  bool
  suppresses_type(const type_base_sptr& type,
		  const scope_decl* type_scope) const;
}; // end type_suppression

type_suppression_sptr
is_type_suppression(const suppression_sptr);

/// The abstraction of a range of offsets in which a member of a type
/// might get inserted.
class type_suppression::insertion_range
{
  struct priv;
  std::unique_ptr<priv> priv_;

public:

  class boundary;
  class integer_boundary;
  class fn_call_expr_boundary;
  class named_boundary;

  /// Convenience typedef for a shared_ptr to @ref boundary
  typedef shared_ptr<boundary> boundary_sptr;

  /// Convenience typedef for a shared_ptr to a @ref integer_boundary
  typedef shared_ptr<integer_boundary> integer_boundary_sptr;

  /// Convenience typedef for a shared_ptr to a @ref
  /// fn_call_expr_boundary
  typedef shared_ptr<fn_call_expr_boundary> fn_call_expr_boundary_sptr;

  /// Convenience typedef for a shared_ptr to a @ref
  /// named_boundary
  typedef shared_ptr<named_boundary> named_boundary_sptr;

  insertion_range();

  insertion_range(boundary_sptr begin, boundary_sptr end);

  boundary_sptr
  begin() const;

  boundary_sptr
  end() const;

  static insertion_range::integer_boundary_sptr
  create_integer_boundary(int value);

  static insertion_range::fn_call_expr_boundary_sptr
  create_fn_call_expr_boundary(ini::function_call_expr_sptr);

  static insertion_range::fn_call_expr_boundary_sptr
  create_fn_call_expr_boundary(const string&);

  static insertion_range::named_boundary_sptr
  create_named_boundary(const string&);

  static bool
  eval_boundary(const boundary_sptr	boundary,
		const class_or_union*	context,
		uint64_t&		value);

  static bool
  boundary_value_is_end(uint64_t value);
}; // end class insertion_range

type_suppression::insertion_range::integer_boundary_sptr
is_integer_boundary(type_suppression::insertion_range::boundary_sptr);

type_suppression::insertion_range::fn_call_expr_boundary_sptr
is_fn_call_expr_boundary(type_suppression::insertion_range::boundary_sptr);

type_suppression::insertion_range::named_boundary_sptr
is_named_boundary(type_suppression::insertion_range::boundary_sptr);

/// The abstraction of the boundary of an @ref insertion_range, in the
/// context of a @ref type_suppression
class type_suppression::insertion_range::boundary
{
  struct priv;
  std::unique_ptr<priv> priv_;

public:
  boundary();
  virtual ~boundary();
};// end class type_suppression::insertion_range::boundary

/// An @ref insertion_range boundary that is expressed as an integer
/// value.  That integer value is usually a bit offset.
class type_suppression::insertion_range::integer_boundary
  : public type_suppression::insertion_range::boundary
{
  struct priv;
  std::unique_ptr<priv> priv_;

  integer_boundary();

public:
  integer_boundary(uint64_t value);
  uint64_t as_integer() const;
  operator uint64_t () const;
  ~integer_boundary();
}; //end class type_suppression::insertion_range::integer_boundary

/// An @ref insertion_range boundary that is expressed as function
/// call expression.  The (integer) value of that expression is
/// usually a bit offset.
class type_suppression::insertion_range::fn_call_expr_boundary
  : public type_suppression::insertion_range::boundary
{
  struct priv;
  std::unique_ptr<priv> priv_;

  fn_call_expr_boundary();

public:
  fn_call_expr_boundary(ini::function_call_expr_sptr expr);
  ini::function_call_expr_sptr as_function_call_expr() const;
  operator ini::function_call_expr_sptr () const;
  ~fn_call_expr_boundary();
}; //end class type_suppression::insertion_range::fn_call_expr_boundary

/// An @ref insertion_range boundary that is expressed as a named
/// constant that is to be evaluated later in the context of a given
/// type and resolved to a bit offset.
class type_suppression::insertion_range::named_boundary
  : public type_suppression::insertion_range::boundary
{
  struct priv;
  std::unique_ptr<priv> priv_;

  named_boundary();

public:
  named_boundary(const string& name);
  const string& get_name() const;
}; //end class type_suppression::insertion_range::named_boundary

/// Abstraction of a negated type suppression specification.
///
/// A negated type suppression suppresses a type if the negation of
/// the equivalent propositions for a @ref type_suppression are valid.
class negated_type_suppression : virtual public type_suppression,
				 virtual public negated_suppression_base
{

public:

  negated_type_suppression(const string& label,
			   const string& type_name_regexp,
			   const string& type_name);

  virtual bool
  suppresses_diff(const diff* diff) const;

  bool
  suppresses_type(const type_base_sptr& type,
		  const diff_context_sptr& ctxt) const;

  bool
  suppresses_type(const type_base_sptr& type) const;

  bool
  suppresses_type(const type_base_sptr& type,
		  const scope_decl* type_scope) const;

  virtual ~negated_type_suppression();
};// end class negated_type_suppression

class function_suppression;

/// Convenience typedef for a shared pointer to function_suppression.
typedef shared_ptr<function_suppression> function_suppression_sptr;

/// Convenience typedef for a vector of @ref function_suppression_sptr.
typedef vector<function_suppression_sptr> function_suppressions_type;

/// Abstraction of a function suppression specification.
///
/// Specifies under which condition reports about a @ref
/// function_decl_diff diff node should be dropped on the floor for
/// the purpose of reporting.
class function_suppression : public suppression_base
{
  struct priv;

public:

  std::unique_ptr<priv> priv_;
  class parameter_spec;

  /// Convenience typedef for shared_ptr of @ref parameter_spec.
  typedef shared_ptr<parameter_spec> parameter_spec_sptr;

  /// Convenience typedef for vector of @ref parameter_spec_sptr.
  typedef vector<parameter_spec_sptr> parameter_specs_type;

  /// The kind of change the current function suppression should apply
  /// to.
  enum change_kind
  {
    UNDEFINED_CHANGE_KIND,
    /// A change in a sub-type of the function.
    FUNCTION_SUBTYPE_CHANGE_KIND = 1,
    /// The function was added to the second subject of the diff.
    ADDED_FUNCTION_CHANGE_KIND = 1 << 1,
    /// The function was deleted from the second subject of the diff.
    DELETED_FUNCTION_CHANGE_KIND = 1 << 2,
    /// This represents all the changes possibly described by this
    /// enum.  It's a logical 'OR' of all the change enumerators
    /// above.
    ALL_CHANGE_KIND = (FUNCTION_SUBTYPE_CHANGE_KIND
		       | ADDED_FUNCTION_CHANGE_KIND
		       | DELETED_FUNCTION_CHANGE_KIND)
  };

  function_suppression();

  function_suppression(const string&		label,
		       const string&		name,
		       const string&		name_regex,
		       const string&		return_type_name,
		       const string&		return_type_regex,
		       parameter_specs_type&	parm_specs,
		       const string&		symbol_name,
		       const string&		symbol_name_regex,
		       const string&		symbol_version,
		       const string&		symbol_version_regex_str);

  virtual ~function_suppression();

  static change_kind
  parse_change_kind(const string&);

  change_kind
  get_change_kind() const;

  void
  set_change_kind(change_kind k);

  const string&
  get_name() const;

  void
  set_name(const string&);

  const string&
  get_name_regex_str() const;

  void
  set_name_regex_str(const string&);

  const string&
  get_name_not_regex_str() const;

  void
  set_name_not_regex_str(const string&);

  const string&
  get_return_type_name() const;

  void
  set_return_type_name(const string&);

  const string&
  get_return_type_regex_str() const;

  void
  set_return_type_regex_str(const string& r);

  const parameter_specs_type&
  get_parameter_specs() const;

  void
  set_parameter_specs(parameter_specs_type&);

  void
  append_parameter_specs(const parameter_spec_sptr);

  const string&
  get_symbol_name() const;

  void
  set_symbol_name(const string& n);

  const string&
  get_symbol_name_regex_str() const;

  void
  set_symbol_name_regex_str(const string&);

  const string&
  get_symbol_name_not_regex_str() const;

  void
  set_symbol_name_not_regex_str(const string&);

  const string&
  get_symbol_version() const;

  void
  set_symbol_version(const string&);

  const string&
  get_symbol_version_regex_str() const;

  void
  set_symbol_version_regex_str(const string&);

  bool
  get_allow_other_aliases() const;

  void
  set_allow_other_aliases(bool f);

  virtual bool
  suppresses_diff(const diff* diff) const;

  bool
  suppresses_function(const function_decl* fn,
		      change_kind k,
		      const diff_context_sptr ctxt) const;

  bool
  suppresses_function(const function_decl_sptr fn,
		      change_kind k,
		      const diff_context_sptr ctxt) const;

  bool
  suppresses_function_symbol(const elf_symbol* sym,
			     change_kind k,
			     const diff_context_sptr ctxt);

  bool
  suppresses_function_symbol(const elf_symbol_sptr sym,
			     change_kind k,
			     const diff_context_sptr ctxt);
}; // end class function_suppression.

function_suppression_sptr
is_function_suppression(const suppression_sptr);

function_suppression::change_kind
operator&(function_suppression::change_kind l,
	  function_suppression::change_kind r);

function_suppression::change_kind
operator|(function_suppression::change_kind l,
	  function_suppression::change_kind r);

/// Abstraction of the specification of a function parameter in a
/// function suppression specification.
class function_suppression::parameter_spec
{
  friend class function_suppression;

  class priv;
  std::unique_ptr<priv> priv_;

  // Forbid this.
  parameter_spec();

public:
  parameter_spec(size_t index,
		 const string& type_name,
		 const string& type_name_regex);

  size_t
  get_index() const;

  void
  set_index(size_t);

  const string&
  get_parameter_type_name() const;

  void
  set_parameter_type_name(const string&);

  const string&
  get_parameter_type_name_regex_str() const;

  void
  set_parameter_type_name_regex_str(const string&);
};// end class function_suppression::parameter_spec

class variable_suppression;

/// A convenience typedef for a shared pointer to @ref
/// variable_suppression.
typedef shared_ptr<variable_suppression> variable_suppression_sptr;

/// A convenience typedef for a vector of @ref
/// variable_suppression_sptr.
typedef vector<variable_suppression_sptr> variable_suppressions_type;

/// The abstraction of a variable suppression specification.
///
/// It specifies under which condition reports about a @ref var_diff
/// diff node should be dropped on the floor for the purpose of
/// reporting.
class variable_suppression : public suppression_base
{
public:

  /// The kind of change the current variable suppression should apply
  /// to.
  enum change_kind
  {
    UNDEFINED_CHANGE_KIND,
    /// A change in a sub-type of the variable.
    VARIABLE_SUBTYPE_CHANGE_KIND = 1,
    /// The variable was added to the second second subject of the
    /// diff.
    ADDED_VARIABLE_CHANGE_KIND = 1 << 1,
    /// The variable was deleted from the second subject of the diff.
    DELETED_VARIABLE_CHANGE_KIND = 1 << 2,
    /// This represents all the changes possibly described by this
    /// enum.  It's a logical 'OR' of all the change enumerators
    /// above.
    ALL_CHANGE_KIND = (VARIABLE_SUBTYPE_CHANGE_KIND
		       | ADDED_VARIABLE_CHANGE_KIND
		       | DELETED_VARIABLE_CHANGE_KIND)
  };

private:
  struct priv;

public:
  std::unique_ptr<priv> priv_;

  variable_suppression(const string& label = "",
		       const string& name = "",
		       const string& name_regex_str = "",
		       const string& symbol_name = "",
		       const string& symbol_name_regex_str = "",
		       const string& symbol_version = "",
		       const string& symbol_version_regex_str = "",
		       const string& type_name = "",
		       const string& type_name_regex_str = "");

  virtual ~variable_suppression();

  static change_kind
  parse_change_kind(const string&);

  change_kind
  get_change_kind() const;

  void
  set_change_kind(change_kind k);

  const string&
  get_name() const;

  void
  set_name(const string&);

  const string&
  get_name_regex_str() const;

  void
  set_name_regex_str(const string&);

  const string&
  get_name_not_regex_str() const;

  void
  set_name_not_regex_str(const string&);

  const string&
  get_symbol_name() const;

  void
  set_symbol_name(const string&);

  const string&
  get_symbol_name_regex_str() const;

  void
  set_symbol_name_regex_str(const string&);

  const string&
  get_symbol_name_not_regex_str() const;

  void
  set_symbol_name_not_regex_str(const string&);

  const string&
  get_symbol_version() const;

  void
  set_symbol_version(const string&);

  const string&
  get_symbol_version_regex_str() const;

  void
  set_symbol_version_regex_str(const string&);

  const string&
  get_type_name() const;

  void
  set_type_name(const string&);

  const string&
  get_type_name_regex_str() const;

  void
  set_type_name_regex_str(const string&);

  bool
  suppresses_diff(const diff* d) const;

  bool
  suppresses_variable(const var_decl* var,
		      change_kind k,
		      const diff_context_sptr cxt) const;

  bool
  suppresses_variable(const var_decl_sptr var,
		      change_kind k,
		      const diff_context_sptr cxt) const;

  bool
  suppresses_variable_symbol(const elf_symbol* sym,
			     change_kind k,
			     const diff_context_sptr cxt) const;

  bool
  suppresses_variable_symbol(const elf_symbol_sptr fn,
			     change_kind k,
			     const diff_context_sptr cxt) const;
}; // end class variable_suppression

variable_suppression_sptr
is_variable_suppression(const suppression_sptr);

variable_suppression::change_kind
operator&(variable_suppression::change_kind l,
	  variable_suppression::change_kind r);

variable_suppression::change_kind
operator|(variable_suppression::change_kind l,
	  variable_suppression::change_kind r);

class file_suppression;

/// A convenience typedef for a shared_ptr to @ref file_suppression
typedef shared_ptr<file_suppression> file_suppression_sptr;

/// Abstraction of a suppression specification to avoid loading a
/// file.
///
/// This can be used by a tool that loads (binary) files, to know
/// which file it has to avoid loading.
class file_suppression: public suppression_base
{
  std::unique_ptr<priv> priv_;

  // Forbid this
  file_suppression();

public:

  file_suppression(const string& label,
		   const string& file_name_regex,
		   const string& file_name_not_regex);

  virtual bool
  suppresses_diff(const diff* diff) const;

  bool
  suppresses_file(const string& file_path);

  virtual ~file_suppression();
}; // end file_suppression

file_suppression_sptr
is_file_suppression(const suppression_sptr);

file_suppression_sptr
file_is_suppressed(const string& file_path,
		   const suppressions_type& suppressions);

bool
suppression_matches_soname(const string& soname,
			   const suppression_base& suppr);

bool
suppression_matches_soname_or_filename(const string& soname,
				       const string& filename,
				       const suppression_base& suppr);

const char*
get_private_types_suppr_spec_label();

bool
is_private_type_suppr_spec(const type_suppression&);

bool
is_private_type_suppr_spec(const suppression_sptr& s);

bool
suppression_can_match(const fe_iface&,
		      const suppression_base&);

bool
suppression_matches_function_name(const fe_iface&,
				  const suppr::function_suppression&,
				  const string&);

bool
suppression_matches_function_sym_name(const fe_iface&,
				      const suppr::function_suppression& s,
				      const string& fn_linkage_name);

bool
suppression_matches_variable_name(const fe_iface&,
				  const suppr::variable_suppression& s,
				  const string& var_name);

bool
suppression_matches_variable_sym_name(const fe_iface&,
				      const suppr::variable_suppression&,
				      const string&);

bool
suppression_matches_type_name_or_location(const fe_iface&,
					  const suppr::type_suppression&,
					  const string&,
					  const location&);

bool
is_elf_symbol_suppressed(const fe_iface&,
			 const elf_symbol_sptr& symbol);

bool
is_elf_symbol_suppressed(const fe_iface&,
			 const string& sym_name,
			 elf_symbol::type sym_type);

bool
is_function_suppressed(const fe_iface&	fe,
		       const string&		fn_name,
		       const string&		fn_linkage_name,
		       bool			require_drop_property = false);

bool
is_variable_suppressed(const fe_iface&	fe,
		       const string&	var_name,
		       const string&	var_linkage_name,
		       bool			require_drop_property = false);

bool
is_type_suppressed(const fe_iface&	fe,
		   const string&	type_name,
		   const location&	type_location,
		   bool&		type_is_private,
		   bool			require_drop_property = false);

bool
is_data_member_offset_in_range(const var_decl_sptr&,
			       const type_suppression::insertion_range_sptr&,
			       const class_or_union*);

} // end namespace suppr


} // end namespace abigail

#endif //__ABG_SUPPRESSION_H__
