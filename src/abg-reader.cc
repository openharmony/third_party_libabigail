// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- mode: C++ -*-
//
// Copyright (C) 2013-2023 Red Hat, Inc.

/// @file
///
/// This file contains the definitions of the entry points to
/// de-serialize an instance of @ref abigail::translation_unit from an
/// ABI Instrumentation file in libabigail native XML format.  This
/// native XML format is named "ABIXML".

#include "config.h"
#include <assert.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlstring.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <sstream>
#include <unordered_map>

#include "abg-suppression-priv.h"

#include "abg-internal.h"
#include "abg-symtab-reader.h"

// <headers defining libabigail's API go under here>
ABG_BEGIN_EXPORT_DECLARATIONS

#include "abg-libxml-utils.h"
#include "abg-reader.h"
#include "abg-corpus.h"
#include "abg-fe-iface.h"
#include "abg-tools-utils.h"

ABG_END_EXPORT_DECLARATIONS
// </headers defining libabigail's API>

namespace abigail
{

using xml::xml_char_sptr;

/// The namespace for the native XML file format reader.
namespace abixml
{
using std::string;
using std::deque;
using std::shared_ptr;
using std::unordered_map;
using std::dynamic_pointer_cast;
using std::vector;
using std::istream;

class reader;

static bool	read_is_declaration_only(xmlNodePtr, bool&);
static bool	read_is_artificial(xmlNodePtr, bool&);
static bool	read_tracking_non_reachable_types(xmlNodePtr, bool&);
static bool	read_is_non_reachable_type(xmlNodePtr, bool&);
static bool	read_naming_typedef_id_string(xmlNodePtr, string&);
static bool	read_type_id_string(xmlNodePtr, string&);
#ifdef WITH_DEBUG_SELF_COMPARISON
static bool	maybe_map_type_with_type_id(const type_base_sptr&,
					    xmlNodePtr);
static bool	maybe_map_type_with_type_id(const type_base_sptr&,
					    const string&);

#define MAYBE_MAP_TYPE_WITH_TYPE_ID(type, xml_node) \
  maybe_map_type_with_type_id(type, xml_node)
#else
#define MAYBE_MAP_TYPE_WITH_TYPE_ID(type, xml_node)
#endif
static void	maybe_set_naming_typedef(reader& rdr,
					 xmlNodePtr,
					 const decl_base_sptr &);
class reader;

static int advance_cursor(reader& rdr);

static void
handle_version_attribute(xml::reader_sptr& reader, corpus& corp);

static void
walk_xml_node_to_map_type_ids(reader& rdr, xmlNodePtr node);

static bool
read_elf_needed_from_input(reader& rdr, vector<string>& needed);

static bool
read_symbol_db_from_input(reader&			rdr,
			  string_elf_symbols_map_sptr&	fn_symdb,
			  string_elf_symbols_map_sptr&	var_symdb);

static translation_unit_sptr
read_translation_unit_from_input(fe_iface& rdr);

static decl_base_sptr
build_ir_node_for_void_type(reader& rdr);

static decl_base_sptr
build_ir_node_for_void_pointer_type(reader& rdr);

/// The ABIXML reader object.
///
/// This abstracts the context in which the current ABI
/// instrumentation dump is being de-serialized.  It carries useful
/// information needed during the de-serialization, but that does not
/// make sense to be stored in the final resulting in-memory
/// representation of ABI Corpus.
class reader : public fe_iface
{
public:

  typedef unordered_map<string, vector<type_base_sptr> >
  types_map_type;

  typedef unordered_map<string,
			vector<type_base_sptr> >::const_iterator
  const_types_map_it;

  typedef unordered_map<string,
			vector<type_base_sptr> >::iterator
  types_map_it;

  typedef unordered_map<string,
			shared_ptr<function_tdecl> >::const_iterator
  const_fn_tmpl_map_it;

  typedef unordered_map<string,
			shared_ptr<class_tdecl> >::const_iterator
  const_class_tmpl_map_it;

  typedef unordered_map<string, xmlNodePtr> string_xml_node_map;

  typedef unordered_map<xmlNodePtr, decl_base_sptr> xml_node_decl_base_sptr_map;

  friend vector<type_base_sptr>* get_types_from_type_id(reader&,
							const string&);

  friend unordered_map<type_or_decl_base*, vector<type_or_decl_base*>>*
	 get_artifact_used_by_relation_map(reader& rdr);

private:
  types_map_type					m_types_map;
  unordered_map<string, shared_ptr<function_tdecl> >	m_fn_tmpl_map;
  unordered_map<string, shared_ptr<class_tdecl> >	m_class_tmpl_map;
  vector<type_base_sptr>				m_types_to_canonicalize;
  string_xml_node_map					m_id_xml_node_map;
  xml_node_decl_base_sptr_map				m_xml_node_decl_map;
  xml::reader_sptr					m_reader;
  xmlNodePtr						m_corp_node;
  deque<shared_ptr<decl_base> >			m_decls_stack;
  bool							m_tracking_non_reachable_types;
  bool							m_drop_undefined_syms;
#ifdef WITH_SHOW_TYPE_USE_IN_ABILINT
  unordered_map<type_or_decl_base*,
		vector<type_or_decl_base*>>		m_artifact_used_by_map;
#endif

  reader();

public:
  reader(xml::reader_sptr reader,
	 environment&	env)
    : fe_iface("", env),
      m_reader(reader),
      m_corp_node(),
      m_tracking_non_reachable_types(),
      m_drop_undefined_syms()
  {
  }

  /// Test if logging was requested.
  ///
  /// @return true iff logging was requested.
  bool
  do_log() const
  {return options().do_log;}

  /// Getter for the flag that tells us if we are tracking types that
  /// are not reachable from global functions and variables.
  ///
  /// @return true iff we are tracking types that are not reachable
  /// from global functions and variables.
  bool
  tracking_non_reachable_types() const
  {return m_tracking_non_reachable_types;}

  /// Setter for the flag that tells us if we are tracking types that
  /// are not reachable from global functions and variables.
  ///
  /// @param f the new value of the flag.
  /// from global functions and variables.
  void
  tracking_non_reachable_types(bool f)
  {m_tracking_non_reachable_types = f;}

  /// Getter for the flag that tells us if we are dropping functions
  /// and variables that have undefined symbols.
  ///
  /// @return true iff we are dropping functions and variables that have
  /// undefined symbols.
  bool
  drop_undefined_syms() const
  {return m_drop_undefined_syms;}

  /// Setter for the flag that tells us if we are dropping functions
  /// and variables that have undefined symbols.
  ///
  /// @param f the new value of the flag.
  void
  drop_undefined_syms(bool f)
  {m_drop_undefined_syms = f;}

  /// Getter of the path to the ABI file.
  ///
  /// @return the path to the native xml abi file.
  const string&
  get_path() const
  {return corpus_path();}

  /// Setter of the path to the ABI file.
  ///
  /// @param the new path to the native ABI file.
  void
  set_path(const string& s)
  {
    corpus_path(s);
  }

  /// Getter for the environment of this reader.
  ///
  /// @return the environment of this reader.
  environment&
  get_environment()
  {return options().env;}

  /// Getter for the environment of this reader.
  ///
  /// @return the environment of this reader.
  const environment&
  get_environment() const
  {return const_cast<reader*>(this)->get_environment();}

  xml::reader_sptr
  get_libxml_reader() const
  {return m_reader;}

  /// Getter of the current XML node in the corpus element sub-tree
  /// that needs to be processed.
  ///
  /// @return the current XML node in the corpus element sub-tree that
  /// needs to be processed.
  xmlNodePtr
  get_corpus_node() const
  {return m_corp_node;}

  /// Setter of the current XML node in the corpus element sub-tree
  /// that needs to be processed.
  ///
  /// @param node set the current XML node in the corpus element
  /// sub-tree that needs to be processed.
  void
  set_corpus_node(xmlNodePtr node)
  {m_corp_node = node;}

  const string_xml_node_map&
  get_id_xml_node_map() const
  {return m_id_xml_node_map;}

  string_xml_node_map&
  get_id_xml_node_map()
  {return m_id_xml_node_map;}

  void
  clear_id_xml_node_map()
  {get_id_xml_node_map().clear();}

  const xml_node_decl_base_sptr_map&
  get_xml_node_decl_map() const
  {return m_xml_node_decl_map;}

  xml_node_decl_base_sptr_map&
  get_xml_node_decl_map()
  {return m_xml_node_decl_map;}

  void
  map_xml_node_to_decl(xmlNodePtr node,
		       decl_base_sptr decl)
  {
    if (node)
      get_xml_node_decl_map()[node]= decl;
  }

  decl_base_sptr
  get_decl_for_xml_node(xmlNodePtr node) const
  {
    xml_node_decl_base_sptr_map::const_iterator i =
      get_xml_node_decl_map().find(node);

    if (i != get_xml_node_decl_map().end())
      return i->second;

    return decl_base_sptr();
  }

  void
  clear_xml_node_decl_map()
  {get_xml_node_decl_map().clear();}

  void
  map_id_and_node (const string& id,
		   xmlNodePtr node)
  {
    if (!node)
      return;

    string_xml_node_map::iterator i = get_id_xml_node_map().find(id);
    if (i != get_id_xml_node_map().end())
      {
	bool is_declaration = false;
	read_is_declaration_only(node, is_declaration);
	if (is_declaration)
	  i->second = node;
      }
    else
      get_id_xml_node_map()[id] = node;
  }

  xmlNodePtr
  get_xml_node_from_id(const string& id) const
  {
    string_xml_node_map::const_iterator i = get_id_xml_node_map().find(id);
    if (i != get_id_xml_node_map().end())
     return i->second;
    return 0;
  }

  scope_decl_sptr
  get_scope_for_node(xmlNodePtr node,
		     access_specifier& access);

  scope_decl_sptr
  get_scope_for_node(xmlNodePtr node);

  scope_decl*
  get_scope_ptr_for_node(xmlNodePtr node);

  // This is defined later, after build_type() is declared, because it
  // uses it.
  type_base_sptr
  build_or_get_type_decl(const string& id,
			 bool add_decl_to_scope);

  /// Return the first type already seen, that is identified by a
  /// given ID.
  ///
  /// Note that for a type to be "identified" by id, the function
  /// key_type_decl must have been previously called with that type
  /// and with id.
  ///
  /// @param id the id to consider.
  ///
  /// @return the type identified by the unique id id, or a null
  /// pointer if no type has ever been associated with id before.
  type_base_sptr
  get_type_decl(const string& id) const
  {
    const_types_map_it i = m_types_map.find(id);
    if (i == m_types_map.end())
      return type_base_sptr();
    type_base_sptr result = i->second[0];
    return result;
  }

  /// Return the vector of types already seen, that are identified by
  /// a given ID.
  ///
  /// Note that for a type to be "identified" by id, the function
  /// key_type_decl must have been previously called with that type
  /// and with id.
  ///
  /// @param id the id to consider.
  ///
  /// @return thevector of types already seen, that are identified by
  /// a given ID, or 0 if no type has ever been associated with @p id
  /// before.
  const vector<type_base_sptr>*
  get_all_type_decls(const string& id) const
  {
    const_types_map_it i = m_types_map.find(id);
    if (i == m_types_map.end())
      return 0;
    else
      return &i->second;
  }

  /// Return the function template that is identified by a unique ID.
  ///
  /// Note that for a function template to be identified by id, the
  /// function key_fn_tmpl_decl must have been previously called with
  /// that function template and with id.
  ///
  /// @param id the ID to consider.
  ///
  /// @return the function template identified by id, or a null
  /// pointer if no function template has ever been associated with
  /// id before.
  shared_ptr<function_tdecl>
  get_fn_tmpl_decl(const string& id) const
  {
    const_fn_tmpl_map_it i = m_fn_tmpl_map.find(id);
    if (i == m_fn_tmpl_map.end())
      return shared_ptr<function_tdecl>();
    return i->second;
  }

  /// Return the class template that is identified by a unique ID.
  ///
  /// Note that for a class template to be identified by id, the
  /// function key_class_tmpl_decl must have been previously called
  /// with that class template and with id.
  ///
  /// @param id the ID to consider.
  ///
  /// @return the class template identified by id, or a null pointer
  /// if no class template has ever been associated with id before.
  shared_ptr<class_tdecl>
  get_class_tmpl_decl(const string& id) const
  {
    const_class_tmpl_map_it i = m_class_tmpl_map.find(id);
    if (i == m_class_tmpl_map.end())
      return shared_ptr<class_tdecl>();
    return i->second;
  }

  /// Return the current lexical scope.
  scope_decl*
  get_cur_scope() const
  {
    shared_ptr<decl_base> cur_decl = get_cur_decl();

    if (dynamic_cast<scope_decl*>(cur_decl.get()))
      // The current decl is a scope_decl, so it's our lexical scope.
      return dynamic_pointer_cast<scope_decl>(cur_decl).get();
    else if (cur_decl)
      // The current decl is not a scope_decl, so our lexical scope is
      // the scope of this decl.
      return cur_decl->get_scope();
    else
      // We have no scope set.
      return 0;
  }

  decl_base_sptr
  get_cur_decl() const
  {
    if (m_decls_stack.empty())
      return shared_ptr<decl_base>(static_cast<decl_base*>(0));
    return m_decls_stack.back();
  }

  translation_unit*
  get_translation_unit()
  {
    const global_scope* global = 0;
    for (deque<shared_ptr<decl_base> >::reverse_iterator i =
	   m_decls_stack.rbegin();
	 i != m_decls_stack.rend();
	 ++i)
      if (decl_base_sptr d = *i)
	if ((global = get_global_scope(d)))
	  break;

    if (global)
      return global->get_translation_unit();

    return 0;
  }

  /// Test if a given type is from the current translation unit.
  ///
  /// @param type the type to consider.
  ///
  /// @return true iff the type is from the current translation unit.
  bool
  type_is_from_translation_unit(type_base_sptr type)
  {
    decl_base_sptr d = get_type_declaration(type);
    if (d)
      return (ir::get_translation_unit(d) == get_translation_unit());
    else if (function_type_sptr fn_type = is_function_type(type))
      return bool(lookup_function_type(fn_type, *get_translation_unit()));
    else
      return false;
  }

  void
  push_decl(decl_base_sptr d)
  {
    m_decls_stack.push_back(d);
  }

  decl_base_sptr
  pop_decl()
  {
    if (m_decls_stack.empty())
      return decl_base_sptr();

    shared_ptr<decl_base> t = get_cur_decl();
    m_decls_stack.pop_back();
    return t;
  }

  /// Pop all decls until a give scope is popped.
  ///
  /// @param scope the scope to pop.
  ///
  /// @return true if the scope was popped, false otherwise.  Note
  /// that if the scope wasn't found, it might mean that many other
  /// decls were popped.
  bool
  pop_scope(scope_decl_sptr scope)
  {
    decl_base_sptr d;
    do
      {
	d = pop_decl();
	scope_decl_sptr s = dynamic_pointer_cast<scope_decl>(d);
	if (s == scope)
	  break;
      }
    while (d);

    if (!d)
      return false;

    return dynamic_pointer_cast<scope_decl>(d) == scope;
  }

  /// like @ref pop_scope, but if the scope couldn't be popped, the
  /// function aborts the execution of the process.
  ///
  /// @param scope the scope to pop.
  void
  pop_scope_or_abort(scope_decl_sptr scope)
  {ABG_ASSERT(pop_scope(scope));}

  void
  clear_decls_stack()
  {m_decls_stack.clear();}

  void
  clear_type_map()
  {m_types_map.clear();}

  /// Clean the vector of types to canonicalize after the translation
  /// unit has been read.
  void
  clear_types_to_canonicalize()
  {m_types_to_canonicalize.clear();}


  /// Test if two types are equal, without comparing them structurally.
  ///
  /// This either tests that type pointers are equal, or it tests
  /// their names.  This is because it might be two early to compare
  /// types structurally because we are not necessarily done building
  /// them yet.
  ///
  /// @param t1 the first type to compare.
  ///
  /// @param t2 the second type to compare.
  ///
  /// @return true iff the types are equal.
  bool
  types_equal(type_base_sptr t1, type_base_sptr t2)
  {
    if (t1.get() == t2.get())
      return true;

    // We are going to test qualified names only if both types have
    // already been added to their scope.
    bool qualified = (get_type_scope(t1) && get_type_scope(t2));

    return (get_type_name(t1, qualified)
	    == get_type_name(t2, qualified));
  }

  /// Associate an ID with a type.
  ///
  /// @param type the type to associate with the ID.
  ///
  /// @param id the ID to associate to the type.
  ///
  /// @return true upon successful completion.
  bool
  key_type_decl(const type_base_sptr& type, const string& id)
  {
    if (!type)
      return false;

    m_types_map[id].push_back(type);

    return true;
  }

  /// Associate an ID to a function template.
  ///
  /// @param fn_tmpl_decl the function template to consider.
  ///
  /// @param id the ID to associate to the function template.
  ///
  /// @return true upon successful completion, false otherwise.  Note
  /// that the function returns false if an ID was previously
  /// associated to the function template.
  bool
  key_fn_tmpl_decl(shared_ptr<function_tdecl> fn_tmpl_decl,
		   const string& id)
  {
    ABG_ASSERT(fn_tmpl_decl);

    const_fn_tmpl_map_it i = m_fn_tmpl_map.find(id);
    if (i != m_fn_tmpl_map.end())
      return false;

    m_fn_tmpl_map[id] = fn_tmpl_decl;
    return true;
  }

  /// Associate an ID to a class template.
  ///
  /// @param class_tmpl_decl the class template to consider.
  ///
  /// @param id the ID to associate to the class template.
  ///
  /// @return true upon successful completion, false otherwise.  Note
  /// that the function returns false if an ID was previously
  /// associated to the class template.
  bool
  key_class_tmpl_decl(shared_ptr<class_tdecl> class_tmpl_decl,
		      const string& id)
  {
    ABG_ASSERT(class_tmpl_decl);

    const_class_tmpl_map_it i = m_class_tmpl_map.find(id);
    if (i != m_class_tmpl_map.end())
      return false;

    m_class_tmpl_map[id] = class_tmpl_decl;
    return true;
  }

#ifdef WITH_SHOW_TYPE_USE_IN_ABILINT
  /// Record that an artifact is used by another one.
  ///
  /// If a type is "used" by another one (as in the type is a sub-type
  /// of another one), this function records that relation.
  ///
  /// @param used the type that is used.
  ///
  /// @param user the type that uses @p used.
  void
  record_artifact_as_used_by(type_or_decl_base* used,
			     type_or_decl_base* user)
  {
    if (m_artifact_used_by_map.find(used) == m_artifact_used_by_map.end())
      {
	vector<type_or_decl_base*> v;
	m_artifact_used_by_map[used] = v;
      }
    m_artifact_used_by_map[used].push_back(user);
  }

  /// Record that an artifact is used by another one.
  ///
  /// If a type is "used" by another one (as in the type is a sub-type
  /// of another one), this function records that relation.
  ///
  /// @param used the type that is used.
  ///
  /// @param user the type that uses @p used.
  void
  record_artifact_as_used_by(const type_or_decl_base_sptr& used,
			     const type_or_decl_base_sptr& user)
  {record_artifact_as_used_by(used.get(), user.get());}

  /// Record the sub-types of a fn-decl as being used by the fn-decl.
  ///
  /// @param fn the function decl to consider.
  void
  record_artifacts_as_used_in_fn_decl(const function_decl *fn)
  {
    if (!fn)
      return;

    type_base_sptr t = fn->get_return_type();
    record_artifact_as_used_by(t.get(), const_cast<function_decl*>(fn));

    for (auto pit : fn->get_parameters())
      {
	type_base_sptr t = pit->get_type();
	record_artifact_as_used_by(t.get(), const_cast<function_decl*>(fn));
      }
  }

  /// Record the sub-types of a function decl as being used by it.
  ///
  /// @param fn the function decl to consider.
  void
  record_artifacts_as_used_in_fn_decl(const function_decl_sptr& fn)
  {record_artifacts_as_used_in_fn_decl(fn.get());}

  /// Record the sub-types of a function type as being used by it.
  ///
  /// @param fn_type the function decl to consider.
  void
  record_artifacts_as_used_in_fn_type(const function_type *fn_type)
  {
    if (!fn_type)
      return;

    type_base_sptr t = fn_type->get_return_type();
    record_artifact_as_used_by(t.get(), const_cast<function_type*>(fn_type));

    for (auto pit : fn_type->get_parameters())
      {
	type_base_sptr t = pit->get_type();
	record_artifact_as_used_by(t.get(),
				   const_cast<function_type*>(fn_type));
      }
  }

  /// Record the sub-types of a function type as being used by it.
  ///
  /// @param fn_type the function decl to consider.
  void
  record_artifacts_as_used_in_fn_type(const function_type_sptr& fn_type)
  {record_artifacts_as_used_in_fn_type(fn_type.get());}
#endif

  /// This function must be called on each declaration that is created
  /// during the parsing.  It adds the declaration to the scope that
  /// its XML node belongs to and updates the state of the parsing
  /// context accordingly.
  ///
  /// @param decl the newly created declaration.
  ///
  /// @param node the xml node @p decl originated from.
  void
  push_decl_to_scope(const decl_base_sptr& decl, xmlNodePtr node)
  {
    scope_decl* scope = nullptr;
    scope = get_scope_ptr_for_node(node);
    return push_decl_to_scope(decl, scope);
  }

  /// This function must be called on each declaration that is created during
  /// the parsing.  It adds the declaration to the current scope, and updates
  /// the state of the parsing context accordingly.
  ///
  /// @param decl the newly created declaration.
  void
  push_decl_to_scope(const decl_base_sptr& decl,
		     scope_decl* scope)
  {
    ABG_ASSERT(decl);
    if (scope)
      add_decl_to_scope(decl, scope);
    if (!decl->get_translation_unit())
      decl->set_translation_unit(get_translation_unit());
    ABG_ASSERT(decl->get_translation_unit());
    push_decl(decl);
  }

  /// This function must be called on each type decl that is created
  /// during the parsing.  It adds the type decl to the current scope
  /// and associates a unique ID to it.
  ///
  /// @param t type_decl
  ///
  /// @param id the unique ID to be associated to t
  ///
  /// @param scope the scope to add the type to.
  ///
  /// @return true upon successful completion.
  ///
  bool
  push_and_key_type_decl(const type_base_sptr& t,
			 const string& id,
			 scope_decl* scope)
  {
    decl_base_sptr decl = get_type_declaration(t);
    ABG_ASSERT(decl);

    push_decl_to_scope(decl, scope);
    if (!t->get_translation_unit())
      t->set_translation_unit(get_translation_unit());
    ABG_ASSERT(t->get_translation_unit());
    key_type_decl(t, id);
    return true;
  }

  /// This function must be called on each type decl that is created
  /// during the parsing.  It adds the type decl to the current scope
  /// and associates a unique ID to it.
  ///
  /// @param t the type to consider.
  ///
  /// @param node the XML it originates from.
  ///
  /// @return true upon successful completion.
  ///
  bool
  push_and_key_type_decl(const type_base_sptr& t,
			 const xmlNodePtr node,
			 bool add_to_current_scope)
  {
    string id;
    if (!read_type_id_string(node, id))
      return false;

    scope_decl* scope = nullptr;
    if (add_to_current_scope && !is_unique_type(t))
      scope = get_scope_ptr_for_node(node);
    return push_and_key_type_decl(t, id, scope);
  }

  /// Getter for the object that determines if a given declaration
  /// ought to be put in the set of exported decls of the current
  /// corpus.
  ///
  /// @return the exported decls builder.
  corpus::exported_decls_builder*
  get_exported_decls_builder()
  {return corpus()->get_exported_decls_builder().get();}

  /// Test if there are suppression specifications (associated to the
  /// current corpus) that match a given SONAME or file name.
  ///
  /// @param soname the SONAME to consider.
  ///
  /// @param the file name to consider.
  ///
  /// @return true iff there are suppression specifications (associated to the
  /// current corpus) that match the SONAME denoted by @p soname or
  /// the file name denoted by @p filename.
  bool
  corpus_is_suppressed_by_soname_or_filename(const string& soname,
					     const string& filename)
  {
    using suppr::suppressions_type;
    using suppr::file_suppression_sptr;
    using suppr::is_file_suppression;

    for (suppressions_type::const_iterator s = suppressions().begin();
	 s != suppressions().end();
	 ++s)
      if (file_suppression_sptr suppr = is_file_suppression(*s))
	if (suppr::suppression_matches_soname_or_filename(soname, filename,
							  *suppr))
	  return true;

    return false;
  }

  /// Clear all the data that must absolutely be cleared at the end of
  /// the parsing of a translation unit.
  void
  clear_per_translation_unit_data()
  {
  }

  /// Clear all the data that must absolutely be cleared at the end of
  /// the parsing of an ABI corpus.
  void
  clear_per_corpus_data()
  {
    clear_type_map();
    clear_types_to_canonicalize();
    clear_xml_node_decl_map();
    clear_id_xml_node_map();
    clear_decls_stack();
  }

#ifdef WITH_DEBUG_SELF_COMPARISON
  /// Perform a debugging routine for the "self-comparison" mode.
  ///
  /// This is done when this command is on:
  ///
  ///   "abidw --debug-abidiff".
  ///
  /// Consider a type 't' built from an XML element from the abixml
  /// reader and that has just been canonicalized.
  ///
  /// This function checks if the canonical type of 't' is the same as
  /// the canonical type of the type which was saved into the abixml
  /// with the same "type-id" as the one of 't'.
  ///
  /// Note that at abixml saving time, a debugging file was saved on
  /// disk to record the mapping of canonical type pointers and their
  /// type-ids.  Right before reading the abixml again, that file was
  /// read again and the mapping was loaded in the map returned by
  /// environment::get_type_id_canonical_type_map().
  void
  maybe_check_abixml_canonical_type_stability(type_base_sptr& t)
  {
    if (!get_environment().self_comparison_debug_is_on()
	|| get_environment().get_type_id_canonical_type_map().empty())
      return ;

    if (class_decl_sptr c = is_class_type(t))
      if (odr_is_relevant(*c) && c->get_is_declaration_only())
	// Declaration-only classes don't have canonical types in
	// environments where ODR is relevant (like in C++).
	return;

    // Let's get the type-id of this type as recorded in the
    // originating abixml file.
    string type_id =
      get_environment().get_type_id_from_pointer(reinterpret_cast<uintptr_t>(t.get()));

    if (!type_id.empty())
      {
	// Now let's get the canonical type that initially led to the
	// serialization of a type with this type-id, when the abixml
	// was being serialized.
	auto j = get_environment().get_type_id_canonical_type_map().find(type_id);
	if (j == get_environment().get_type_id_canonical_type_map().end())
	  {
	    if (t->get_naked_canonical_type())
	      std::cerr << "error: no type with type-id: '"
			<< type_id
			<< "' could be read back from the typeid file\n";
	  }
	else if (j->second
		 != reinterpret_cast<uintptr_t>(t->get_canonical_type().get()))
	  // So the canonical type of 't' (at abixml de-serialization
	  // time) is different from the canonical type that led to
	  // the serialization of 't' at abixml serialization time.
	  // Report this because it needs further debugging.
	  std::cerr << "error: canonical type for type '"
		    << t->get_pretty_representation(/*internal=*/true,
						    /*qualified=*/true)
		    << "' of type-id '" << type_id
		    << "' changed from '" << std::hex
		    << j->second << "' to '" << std::hex
		    << reinterpret_cast<uintptr_t>(t->get_canonical_type().get())
		    << std::dec
		    << "'\n";
	    }
  }
#endif

  /// Test if a type should be canonicalized early.  If so,
  /// canonicalize it right away.  Otherwise, schedule it for late
  /// canonicalizing; that is, schedule it so that it's going to be
  /// canonicalized when the translation unit is fully read.
  ///
  /// @param t the type to consider for canonicalizing.
  void
  maybe_canonicalize_type(type_base_sptr t,
			  bool force_delay = false)
  {
    if (!t)
      return;

    if (t->get_canonical_type())
      return;

    // If this class has some non-canonicalized sub type, then wait
    // for the when we've read all the translation unit to
    // canonicalize all of its non-canonicalized sub types and then we
    // can canonicalize this one.
    //
    // Also, if this is a declaration-only class, wait for the end of
    // the translation unit reading so that we have its definition and
    // then we'll use that for canonicalizing it.
    if (!force_delay
	&& !type_has_non_canonicalized_subtype(t)
	&& !is_class_type(t)
	&& !is_union_type(t)
	// Below are types that *must* be canonicalized only after
	// they are added to their context; but then this function
	// might be called to early, before they are actually added to
	// their context.
	//
	// TODO: make sure this function is called after types are
	// added to their context, so that we can try to
	// early-canonicalize some of these types, reducing the size
	// of the set of types to put on the side, waiting for being
	// canonicalized.
	&& !is_method_type(t)
	&& !is_reference_type(t)
	&& !is_pointer_type(t)
	&& !is_array_type(t)
	&& !is_qualified_type(t)
	&& !is_typedef(t)
	&& !is_enum_type(t)
	&& !is_function_type(t))
      {
	canonicalize(t);
#ifdef WITH_DEBUG_SELF_COMPARISON
	maybe_check_abixml_canonical_type_stability(t);
#endif
      }
    else
      {
	// We do not want to try to canonicalize a class type that
	// hasn't been properly added to its context.
	if (class_decl_sptr c = is_class_type(t))
	  ABG_ASSERT(c->get_scope());

	schedule_type_for_late_canonicalizing(t);
      }
  }

  /// Schedule a type for being canonicalized after the current
  /// translation unit is read.
  ///
  /// @param t the type to consider for canonicalization.
  void
  schedule_type_for_late_canonicalizing(type_base_sptr t)
  {m_types_to_canonicalize.push_back(t);}

  /// Perform the canonicalizing of types that ought to be done after
  /// the current translation unit is read.  This function is called
  /// when the current corpus is fully built.
  void
  perform_late_type_canonicalizing()
  {
    for (vector<type_base_sptr>::iterator i = m_types_to_canonicalize.begin();
	 i != m_types_to_canonicalize.end();
	 ++i)
      {
	canonicalize(*i);
#ifdef WITH_DEBUG_SELF_COMPARISON
	maybe_check_abixml_canonical_type_stability(*i);
#endif
      }
  }

  /// Test whether if a given function suppression matches a function
  /// designated by a regular expression that describes its name.
  ///
  /// @param s the suppression specification to evaluate to see if it
  /// matches a given function name.
  ///
  /// @param fn_name the name of the function of interest.  Note that
  /// this name must be *non* qualified.
  ///
  /// @return true iff the suppression specification @p s matches the
  /// function whose name is @p fn_name.
  bool
  suppression_matches_function_name(const suppr::function_suppression_sptr& s,
				    const string& fn_name) const
  {
    if (!s)
      return false;
    return suppression_matches_function_name(*s, fn_name);
  }

  /// Tests if a suppression specification can match ABI artifacts
  /// coming from the ABI corpus being analyzed.
  ///
  /// This tests if the suppression matches the soname of and binary
  /// name of the corpus being analyzed.
  ///
  /// @param s the suppression specification to consider.
  bool
  suppression_can_match(const suppr::suppression_base& s) const
  {
    corpus_sptr corp = corpus();

    if (!s.priv_->matches_soname(corp->get_soname()))
      if (s.has_soname_related_property())
	// The suppression has some SONAME related properties, but
	// none of them match the SONAME of the current binary.  So
	// the suppression cannot match the current binary.
	return false;

    if (!s.priv_->matches_binary_name(corp->get_path()))
      if (s.has_file_name_related_property())
	// The suppression has some file_name related properties, but
	// none of them match the file name of the current binary.  So
	// the suppression cannot match the current binary.
	return false;

    return true;
  }

  /// Test whether if a given function suppression matches a function
  /// designated by a regular expression that describes its name.
  ///
  /// @param s the suppression specification to evaluate to see if it
  /// matches a given function name.
  ///
  /// @param fn_name the name of the function of interest.  Note that
  /// this name must be *non* qualified.
  ///
  /// @return true iff the suppression specification @p s matches the
  /// function whose name is @p fn_name.
  bool
  suppression_matches_function_name(const suppr::function_suppression& s,
				    const string& fn_name) const
  {
    if (!s.get_drops_artifact_from_ir()
	|| !suppression_can_match(s))
      return false;

    return suppr::suppression_matches_function_name(s, fn_name);
  }

  /// Test if a given type suppression specification matches a type
  /// designated by its name and location.
  ///
  /// @param s the suppression specification to consider.
  ///
  /// @param type_name the fully qualified type name to consider.
  ///
  /// @param type_location the type location to consider.
  ///
  /// @return true iff the type suppression specification matches a
  /// type of a given name and location.
  bool
  suppression_matches_type_name_or_location(const suppr::type_suppression& s,
					    const string& type_name,
					    const location& type_location) const
  {
    if (!suppression_can_match(s))
      return false;

    return suppr::suppression_matches_type_name_or_location(s, type_name,
							    type_location);
  }

  virtual ir::corpus_sptr
  read_corpus(fe_iface::status& status)
  {
    corpus_sptr nil;

    xml::reader_sptr xml_reader = get_libxml_reader();
    if (!xml_reader)
      return nil;

    // This is to remember to call xmlTextReaderNext if we ever call
    // xmlTextReaderExpand.
    bool call_reader_next = false;

    xmlNodePtr node = get_corpus_node();
    if (!node)
      {
	// The document must start with the abi-corpus node.
	int status = 1;
	while (status == 1
	       && XML_READER_GET_NODE_TYPE(xml_reader) != XML_READER_TYPE_ELEMENT)
	  status = advance_cursor (*this);

	if (status != 1 || !xmlStrEqual (XML_READER_GET_NODE_NAME(xml_reader).get(),
					 BAD_CAST("abi-corpus")))
	  return nil;

#ifdef WITH_DEBUG_SELF_COMPARISON
	if (get_environment().self_comparison_debug_is_on())
	  get_environment().set_self_comparison_debug_input(corpus());
#endif

	if (!corpus_group())
	  clear_per_corpus_data();

	ir::corpus& corp = *corpus();

	corp.set_origin(corpus::NATIVE_XML_ORIGIN);

	handle_version_attribute(xml_reader, corp);

	xml::xml_char_sptr path_str = XML_READER_GET_ATTRIBUTE(xml_reader, "path");
	string path;

	if (path_str)
	  {
	    path = reinterpret_cast<char*>(path_str.get());
	    corpus_path(path);
	    corp.set_path(path);
	  }

	xml::xml_char_sptr architecture_str =
	  XML_READER_GET_ATTRIBUTE(xml_reader, "architecture");
	if (architecture_str)
	  corp.set_architecture_name
	    (reinterpret_cast<char*>(architecture_str.get()));

	xml::xml_char_sptr soname_str =
	  XML_READER_GET_ATTRIBUTE(xml_reader, "soname");
	string soname;

	if (soname_str)
	  {
	    soname = reinterpret_cast<char*>(soname_str.get());
	    dt_soname(soname);
	    corp.set_soname(soname);
	  }

	// Apply suppression specifications here to honour:
	//
	//   [suppress_file]
	//     (soname_regexp
	//      |soname_not_regexp
	//      |file_name_regexp
	//      |file_name_not_regexp) = <soname-or-file-name>
	if ((!soname.empty() || !path.empty())
	    && corpus_is_suppressed_by_soname_or_filename(soname, path))
	  return nil;

	node = xmlTextReaderExpand(xml_reader.get());
	if (!node)
	  return nil;

	call_reader_next = true;
      }
    else
      {
#ifdef WITH_DEBUG_SELF_COMPARISON
	if (get_environment().self_comparison_debug_is_on())
	  get_environment().set_self_comparison_debug_input(corpus());
#endif

	if (!corpus_group())
	  clear_per_corpus_data();

	ir::corpus& corp = *corpus();
	corp.set_origin(corpus::NATIVE_XML_ORIGIN);

	xml::xml_char_sptr path_str = XML_NODE_GET_ATTRIBUTE(node, "path");
	if (path_str)
	  corp.set_path(reinterpret_cast<char*>(path_str.get()));

	xml::xml_char_sptr architecture_str =
	  XML_NODE_GET_ATTRIBUTE(node, "architecture");
	if (architecture_str)
	  corp.set_architecture_name
	    (reinterpret_cast<char*>(architecture_str.get()));

	xml::xml_char_sptr soname_str =
	  XML_NODE_GET_ATTRIBUTE(node, "soname");
	if (soname_str)
	  corp.set_soname(reinterpret_cast<char*>(soname_str.get()));
      }

    // If the corpus element node has children nodes, make
    // get_corpus_node() returns the first child element node of
    // the corpus element that *needs* to be processed.
    if (node->children)
      {
	xmlNodePtr n = xmlFirstElementChild(node);
	set_corpus_node(n);
      }

    ir::corpus& corp = *corpus();

    walk_xml_node_to_map_type_ids(*this, node);

    // Read the needed element
    vector<string> needed;
    read_elf_needed_from_input(*this, needed);
    if (!needed.empty())
      corp.set_needed(needed);

    string_elf_symbols_map_sptr fn_sym_db, var_sym_db;

    // Read the symbol databases.
    read_symbol_db_from_input(*this, fn_sym_db, var_sym_db);

    // Note that it's possible that both fn_sym_db and var_sym_db are nil,
    // due to potential suppression specifications.  That's fine.
    corp.set_symtab(symtab_reader::symtab::load(fn_sym_db, var_sym_db));

    get_environment().canonicalization_is_done(false);

    // Read the translation units.
    while (read_translation_unit_from_input(*this))
      ;

    if (tracking_non_reachable_types())
      {
	bool is_tracking_non_reachable_types = false;
	read_tracking_non_reachable_types(node, is_tracking_non_reachable_types);

	ABG_ASSERT
	  (corp.recording_types_reachable_from_public_interface_supported()
	   == is_tracking_non_reachable_types);
      }


    tools_utils::timer t;
    if (do_log())
      {
	std::cerr << "perform late type canonicalization ...\n";
	t.start();
      }

    perform_late_type_canonicalizing();

    if (do_log())
      {
	t.stop();
	std::cerr << "late type canonicalization DONE@"
		  << corpus()->get_path()
		  << ":" << t << "\n";
      }

    get_environment().canonicalization_is_done(true);

    if (call_reader_next)
      {
	// This is the necessary counter-part of the xmlTextReaderExpand()
	// call at the beginning of the function.
	xmlTextReaderNext(xml_reader.get());
	// The call above invalidates the xml node returned by
	// xmlTextReaderExpand, which is can still be accessed via
	// set_corpus_node.
	set_corpus_node(0);
      }
    else
      {
	node = get_corpus_node();
	node = xmlNextElementSibling(node);
	if (!node)
	  {
	    node = get_corpus_node();
	    if (node)
	      node = xmlNextElementSibling(node->parent);
	  }
	set_corpus_node(node);
      }

    status = STATUS_OK;
    return corpus();
  }
};// end class reader

typedef shared_ptr<reader> reader_sptr;

static int	advance_cursor(reader&);
static bool read_translation_unit(fe_iface&, translation_unit&, xmlNodePtr);
static translation_unit_sptr get_or_read_and_add_translation_unit(reader&, xmlNodePtr);
static translation_unit_sptr read_translation_unit_from_input(fe_iface&);
static bool	read_symbol_db_from_input(reader&,
					  string_elf_symbols_map_sptr&,
					  string_elf_symbols_map_sptr&);
static bool	read_location(const reader&, xmlNodePtr, location&);
static bool	read_artificial_location(const reader&,
					 xmlNodePtr, location&);
static bool     maybe_set_artificial_location(const reader&,
					      xmlNodePtr,
					      type_or_decl_base_sptr);
static bool	read_visibility(xmlNodePtr, decl_base::visibility&);
static bool	read_binding(xmlNodePtr, decl_base::binding&);
static bool	read_access(xmlNodePtr, access_specifier&);
static bool	read_size_and_alignment(xmlNodePtr, size_t&, size_t&);
static bool	read_static(xmlNodePtr, bool&);
static bool	read_offset_in_bits(xmlNodePtr, size_t&);
static bool	read_cdtor_const(xmlNodePtr, bool&, bool&, bool&);
static bool	read_is_virtual(xmlNodePtr, bool&);
static bool	read_is_struct(xmlNodePtr, bool&);
static bool	read_is_anonymous(xmlNodePtr, bool&);
static bool	read_elf_symbol_type(xmlNodePtr, elf_symbol::type&);
static bool	read_elf_symbol_binding(xmlNodePtr, elf_symbol::binding&);
static bool	read_elf_symbol_visibility(xmlNodePtr,
					   elf_symbol::visibility&);

static namespace_decl_sptr
build_namespace_decl(reader&, const xmlNodePtr, bool);

// <build a c++ class from an instance of xmlNodePtr>
//
// Note that whenever a new function to build a type is added here,
// you should make sure to call it from the build_type function, which
// should be the last function of the list of declarated function
// below.

static elf_symbol_sptr
build_elf_symbol(reader&, const xmlNodePtr, bool);

static elf_symbol_sptr
build_elf_symbol_from_reference(reader&, const xmlNodePtr);

static string_elf_symbols_map_sptr
build_elf_symbol_db(reader&, const xmlNodePtr, bool);

static function_decl::parameter_sptr
build_function_parameter (reader&, const xmlNodePtr);

static function_decl_sptr
build_function_decl(reader&, const xmlNodePtr,
		    class_or_union_sptr, bool, bool);

static function_decl_sptr
build_function_decl_if_not_suppressed(reader&, const xmlNodePtr,
				      class_or_union_sptr, bool, bool);

static bool
function_is_suppressed(const reader& rdr,
		       xmlNodePtr node);

static var_decl_sptr
build_var_decl_if_not_suppressed(reader&, const xmlNodePtr, bool);

static var_decl_sptr
build_var_decl(reader&, const xmlNodePtr, bool);

static bool
variable_is_suppressed(const reader& rdr,
		       xmlNodePtr node);

static shared_ptr<type_decl>
build_type_decl(reader&, const xmlNodePtr, bool);

static qualified_type_def_sptr
build_qualified_type_decl(reader&, const xmlNodePtr, bool);

static shared_ptr<pointer_type_def>
build_pointer_type_def(reader&, const xmlNodePtr, bool);

static shared_ptr<reference_type_def>
build_reference_type_def(reader&, const xmlNodePtr, bool);

static shared_ptr<function_type>
build_function_type(reader&, const xmlNodePtr, bool);

static array_type_def::subrange_sptr
build_subrange_type(reader&, const xmlNodePtr, bool);

static array_type_def_sptr
build_array_type_def(reader&, const xmlNodePtr, bool);

static enum_type_decl_sptr
build_enum_type_decl(reader&, const xmlNodePtr, bool);

static shared_ptr<typedef_decl>
build_typedef_decl(reader&, const xmlNodePtr, bool);

static class_decl_sptr
build_class_decl(reader&, const xmlNodePtr, bool);

static union_decl_sptr
build_union_decl(reader&, const xmlNodePtr, bool);

static shared_ptr<function_tdecl>
build_function_tdecl(reader&, const xmlNodePtr, bool);

static shared_ptr<class_tdecl>
build_class_tdecl(reader&, const xmlNodePtr, bool);

static type_tparameter_sptr
build_type_tparameter(reader&, const xmlNodePtr,
		      unsigned, template_decl_sptr);

static type_composition_sptr
build_type_composition(reader&, const xmlNodePtr,
		       unsigned, template_decl_sptr);

static non_type_tparameter_sptr
build_non_type_tparameter(reader&, const xmlNodePtr,
			  unsigned, template_decl_sptr);

static template_tparameter_sptr
build_template_tparameter(reader&, const xmlNodePtr,
			  unsigned, template_decl_sptr);

static template_parameter_sptr
build_template_parameter(reader&, const xmlNodePtr,
			 unsigned, template_decl_sptr);

// Please make this build_type function be the last one of the list.
// Note that it should call each type-building function above.  So
// please make sure to update it accordingly, whenever a new
// type-building function is added here.
static shared_ptr<type_base>
build_type(reader&, const xmlNodePtr, bool);
// </build a c++ class  from an instance of xmlNodePtr>

static type_or_decl_base_sptr	handle_element_node(reader&, xmlNodePtr, bool);
static decl_base_sptr	handle_type_decl(reader&, xmlNodePtr, bool);
static decl_base_sptr	handle_namespace_decl(reader&, xmlNodePtr, bool);
static decl_base_sptr	handle_qualified_type_decl(reader&,
						   xmlNodePtr, bool);
static decl_base_sptr	handle_pointer_type_def(reader&,
						xmlNodePtr, bool);
static decl_base_sptr	handle_reference_type_def(reader&,
						  xmlNodePtr, bool);
static type_base_sptr	handle_function_type(reader&,
					     xmlNodePtr, bool);
static decl_base_sptr	handle_array_type_def(reader&,
					      xmlNodePtr, bool);
static decl_base_sptr	handle_enum_type_decl(reader&, xmlNodePtr, bool);
static decl_base_sptr	handle_typedef_decl(reader&, xmlNodePtr, bool);
static decl_base_sptr	handle_var_decl(reader&, xmlNodePtr, bool);
static decl_base_sptr	handle_function_decl(reader&, xmlNodePtr, bool);
static decl_base_sptr	handle_class_decl(reader&, xmlNodePtr, bool);
static decl_base_sptr	handle_union_decl(reader&, xmlNodePtr, bool);
static decl_base_sptr	handle_function_tdecl(reader&, xmlNodePtr, bool);
static decl_base_sptr	handle_class_tdecl(reader&, xmlNodePtr, bool);

#ifdef WITH_SHOW_TYPE_USE_IN_ABILINT
#define RECORD_ARTIFACT_AS_USED_BY(rdr, used, user) \
  rdr.record_artifact_as_used_by(used,user)
#define RECORD_ARTIFACTS_AS_USED_IN_FN_DECL(rdr, fn) \
  rdr.record_artifacts_as_used_in_fn_decl(fn)
#define RECORD_ARTIFACTS_AS_USED_IN_FN_TYPE(rdr, fn_type)\
  rdr.record_artifacts_as_used_in_fn_type(fn_type)
#else
#define RECORD_ARTIFACT_AS_USED_BY(rdr, used, user)
#define RECORD_ARTIFACTS_AS_USED_IN_FN_DECL(rdr, fn)
#define RECORD_ARTIFACTS_AS_USED_IN_FN_TYPE(rdr, fn_type)
#endif

/// Get the IR node representing the scope for a given XML node.
///
/// This function might trigger the building of a full sub-tree of IR.
///
/// @param node the XML for which to return the scope decl.  If its
/// parent XML node has no corresponding IR node, that IR node is constructed.
///
/// @param access the access specifier of the node in its scope, if
/// applicable.  If the node doesn't have any access specifier
/// provided in its scope, then the parameter is set to no_access.
///
/// @return the IR node representing the scope of the IR node for the
/// XML node given in argument.
scope_decl_sptr
reader::get_scope_for_node(xmlNodePtr node, access_specifier& access)
{
  scope_decl_sptr nil, scope;
  if (!node)
    return nil;

  xmlNodePtr parent = node->parent;
  access = no_access;
  if (parent
      && (xmlStrEqual(parent->name, BAD_CAST("data-member"))
	  || xmlStrEqual(parent->name, BAD_CAST("member-type"))
	  || xmlStrEqual(parent->name, BAD_CAST("member-function"))
	  || xmlStrEqual(parent->name, BAD_CAST("member-template"))
	  || xmlStrEqual(parent->name, BAD_CAST("template-parameter-type-composition"))
	  || xmlStrEqual(parent->name, BAD_CAST("array-type-def"))))
    {
      read_access(parent, access);
      parent = parent->parent;
    }

  xml_node_decl_base_sptr_map::const_iterator i =
    get_xml_node_decl_map().find(parent);
  if (i == get_xml_node_decl_map().end())
    {
      if (xmlStrEqual(parent->name, BAD_CAST("abi-instr")))
	{
	  translation_unit_sptr tu =
	    get_or_read_and_add_translation_unit(*this, parent);
	  return tu->get_global_scope();
	}

      access_specifier a = no_access;
      scope_decl_sptr parent_scope = get_scope_for_node(parent, a);
      push_decl(parent_scope);
      scope = dynamic_pointer_cast<scope_decl>
	(handle_element_node(*this, parent, /*add_decl_to_scope=*/true));
      ABG_ASSERT(scope);
      pop_scope_or_abort(parent_scope);
    }
  else
    scope = dynamic_pointer_cast<scope_decl>(i->second);

  return scope;
}

/// Get the IR node representing the scope for a given XML node.
///
/// This function might trigger the building of a full sub-tree of IR.
///
/// @param node the XML for which to return the scope decl.  If its
/// parent XML node has no corresponding IR node, that IR node is constructed.
///
/// @return the IR node representing the scope of the IR node for the
/// XML node given in argument.
scope_decl_sptr
reader::get_scope_for_node(xmlNodePtr node)
{
  access_specifier access;
  return get_scope_for_node(node, access);
}

/// Get the IR node representing the scope for a given XML node.
///
/// This function might trigger the building of a full sub-tree of IR.
///
/// @param node the XML for which to return the scope decl.  If its
/// parent XML node has no corresponding IR node, that IR node is constructed.
///
/// @return the IR node representing the scope of the IR node for the
/// XML node given in argument.
scope_decl*
reader::get_scope_ptr_for_node(xmlNodePtr node)
{
  scope_decl_sptr scope = get_scope_for_node(node);
  if (scope)
    return scope.get();
  return nullptr;
}

/// Get the type declaration IR node that matches a given XML type node ID.
///
/// If no IR node has been built for this ID, this function builds the
/// type declaration IR node and returns it.  Subsequent invocation of
/// this function with this ID will just return that ID previously returned.
///
/// @param id the XML node ID to consider.
///
/// @return the type declaration for the ID given in parameter.
type_base_sptr
reader::build_or_get_type_decl(const string& id, bool add_decl_to_scope)
{
  type_base_sptr t = get_type_decl(id);

  if (!t)
    {
      xmlNodePtr n = get_xml_node_from_id(id);
      ABG_ASSERT(n);

      scope_decl_sptr scope;
      access_specifier access = no_access;
      if (add_decl_to_scope)
	{
	  scope = get_scope_for_node(n, access);
	  /// In some cases, if for instance the scope of 'n' is a
	  /// namespace, get_scope_for_node() can trigger the building
	  /// of what is underneath of the namespace, if that has not
	  /// already been done.  So after that, the IR node for 'n'
	  /// might have been built; let's try to see if we are in
	  /// that case.  Otherwise, we'll just build the IR node for
	  /// 'n' ourselves.
	  if ((t = get_type_decl(id)))
	    return t;
	  ABG_ASSERT(scope);
	  push_decl(scope);
	}

      t = build_type(*this, n, add_decl_to_scope);
      ABG_ASSERT(t);
      if (is_member_type(t) && access != no_access)
	{
	  ABG_ASSERT(add_decl_to_scope);
	  decl_base_sptr d = get_type_declaration(t);
	  ABG_ASSERT(d);
	  set_member_access_specifier(d, access);
	}
      map_xml_node_to_decl(n, get_type_declaration(t));

      if (add_decl_to_scope)
	pop_scope_or_abort(scope);

      maybe_canonicalize_type(t, !add_decl_to_scope);
    }
  return t;
}

/// Moves the xmlTextReader cursor to the next xml node in the input
/// document.  Return 1 of the parsing was successful, 0 if no input
/// xml token is left, or -1 in case of error.
///
/// @param rdr the ABIXML reader
///
static int
advance_cursor(reader& rdr)
{
  xml::reader_sptr reader = rdr.get_libxml_reader();
  return xmlTextReaderRead(reader.get());
}

/// Walk an entire XML sub-tree to build a map where the key is the
/// the value of the 'id' attribute (for type definitions) and the value
/// is the xml node containing the 'id' attribute.
///
/// @param rdr the context of the reader.
///
/// @param node the XML sub-tree node to walk.  It must be an element
/// node.
static void
walk_xml_node_to_map_type_ids(reader& rdr,
			      xmlNodePtr node)
{
  xmlNodePtr n = node;

  if (!n || n->type != XML_ELEMENT_NODE)
    return;

  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(n, "id"))
    {
      string id = CHAR_STR(s);
      rdr.map_id_and_node(id, n);
    }

  for (n = xmlFirstElementChild(n); n; n = xmlNextElementSibling(n))
    walk_xml_node_to_map_type_ids(rdr, n);
}

static bool
read_translation_unit(fe_iface& iface, translation_unit& tu, xmlNodePtr node)
{
  abixml::reader& rdr = dynamic_cast<abixml::reader&>(iface);

  if (!rdr.corpus()->is_empty())
    tu.set_corpus(rdr.corpus().get());

  xml::xml_char_sptr addrsize_str =
    XML_NODE_GET_ATTRIBUTE(node, "address-size");
  if (addrsize_str)
    {
      char address_size = atoi(reinterpret_cast<char*>(addrsize_str.get()));
      tu.set_address_size(address_size);
    }

  xml::xml_char_sptr path_str = XML_NODE_GET_ATTRIBUTE(node, "path");
  if (path_str)
    tu.set_path(reinterpret_cast<char*>(path_str.get()));

  xml::xml_char_sptr comp_dir_path_str =
    XML_NODE_GET_ATTRIBUTE(node, "comp-dir-path");
  if (comp_dir_path_str)
    tu.set_compilation_dir_path(reinterpret_cast<char*>
				(comp_dir_path_str.get()));

  xml::xml_char_sptr language_str = XML_NODE_GET_ATTRIBUTE(node, "language");
  if (language_str)
    tu.set_language(string_to_translation_unit_language
		     (reinterpret_cast<char*>(language_str.get())));


  // We are at global scope, as we've just seen the top-most
  // "abi-instr" element.
  rdr.push_decl(tu.get_global_scope());
  rdr.map_xml_node_to_decl(node, tu.get_global_scope());

  if (rdr.get_id_xml_node_map().empty()
      || !rdr.corpus())
    walk_xml_node_to_map_type_ids(rdr, node);

  for (xmlNodePtr n = xmlFirstElementChild(node);
       n;
       n = xmlNextElementSibling(n))
    handle_element_node(rdr, n, /*add_decl_to_scope=*/true);

  rdr.pop_scope_or_abort(tu.get_global_scope());

  xml::reader_sptr reader = rdr.get_libxml_reader();
  if (!reader)
    return false;

  rdr.clear_per_translation_unit_data();

  return true;
}

/// Read a given xml node representing a tranlsation unit.
///
/// If the current corpus already contains a translation unit of the
/// path of the xml node we need to look at, then return that
/// translation unit.  Otherwise, read the translation unit, build a
/// @ref translation_unit out of it, add it to the current corpus and
/// return it.
///
/// @param rdr the ABIXML reader.
///
/// @param node the XML node to consider.
///
/// @return the resulting translation unit.
static translation_unit_sptr
get_or_read_and_add_translation_unit(reader& rdr, xmlNodePtr node)
{
  corpus_sptr corp = rdr.corpus();

  translation_unit_sptr tu;
  string tu_path;
  xml::xml_char_sptr path_str = XML_NODE_GET_ATTRIBUTE(node, "path");

  if (path_str)
    {
      tu_path = reinterpret_cast<char*>(path_str.get());
      ABG_ASSERT(!tu_path.empty());

      if (corp && !corp->is_empty())
	tu = corp->find_translation_unit(tu_path);

      if (tu)
	return tu;
    }

  tu.reset(new translation_unit(rdr.get_environment(), tu_path));
  if (corp && !corp->is_empty())
    corp->add(tu);

  if (read_translation_unit(rdr, *tu, node))
    return tu;

  return translation_unit_sptr();
}

/// Parse the input XML document containing a translation_unit,
/// represented by an 'abi-instr' element node, associated to the current
/// context.
///
/// @param rdr the current input context
///
/// @return the translation unit resulting from the parsing upon
/// successful completion, or nil.
static translation_unit_sptr
read_translation_unit_from_input(fe_iface& iface)
{
  translation_unit_sptr tu, nil;

  abixml::reader& rdr = dynamic_cast<abixml::reader&>(iface);

  xmlNodePtr node = rdr.get_corpus_node();
  if (!node)
    {
      xml::reader_sptr reader = rdr.get_libxml_reader();
      if (!reader)
	return nil;

      // The document must start with the abi-instr node.
      int status = 1;
      while (status == 1
	     && XML_READER_GET_NODE_TYPE(reader) != XML_READER_TYPE_ELEMENT)
	status = advance_cursor (rdr);

      if (status != 1 || !xmlStrEqual (XML_READER_GET_NODE_NAME(reader).get(),
				       BAD_CAST("abi-instr")))
	return nil;

      node = xmlTextReaderExpand(reader.get());
      if (!node)
	return nil;
    }
  else
    {
      node = 0;
      for (xmlNodePtr n = rdr.get_corpus_node();
	   n;
	   n = xmlNextElementSibling(n))
	{
	  if (!xmlStrEqual(n->name, BAD_CAST("abi-instr")))
	    return nil;
	  node = n;
	  break;
	}
    }

  if (node == 0)
    return nil;

  tu = get_or_read_and_add_translation_unit(rdr, node);

  if (rdr.get_corpus_node())
    {
      // We are not in the mode where the current corpus node came
      // from a local invocation of xmlTextReaderExpand.  So let's set
      // rdr.get_corpus_node to the next child element node of the
      // corpus that needs to be processed.
      node = xmlNextElementSibling(node);
      rdr.set_corpus_node(node);
    }

  return tu;
}

/// Parse the input XML document that may contain function symbol and
/// variable symbol databases.
///
/// A function symbols database is an XML element named
/// "elf-function-symbols" and a variable symbols database is an XML
/// element named "elf-variable-symbols."  They contains "elf-symbol"
/// XML elements.
///
/// @param rdr the reader to use for the parsing.
///
/// @param fn_symdb any resulting function symbol database object, if
/// elf-function-symbols was present.
///
/// @param var_symdb any resulting variable symbol database object, if
/// elf-variable-symbols was present.
///
/// @return true upon successful parsing, false otherwise.
static bool
read_symbol_db_from_input(reader&		 rdr,
			  string_elf_symbols_map_sptr& fn_symdb,
			  string_elf_symbols_map_sptr& var_symdb)
{
  xml::reader_sptr reader = rdr.get_libxml_reader();
  if (!reader)
    return false;

  if (!rdr.get_corpus_node())
    for (;;)
      {
	int status = 1;
	while (status == 1
	       && XML_READER_GET_NODE_TYPE(reader) != XML_READER_TYPE_ELEMENT)
	  status = advance_cursor (rdr);

	if (status != 1)
	  return false;

	bool has_fn_syms = false, has_var_syms = false;
	if (xmlStrEqual (XML_READER_GET_NODE_NAME(reader).get(),
			 BAD_CAST("elf-function-symbols")))
	  has_fn_syms = true;
	else if (xmlStrEqual (XML_READER_GET_NODE_NAME(reader).get(),
			      BAD_CAST("elf-variable-symbols")))
	  has_var_syms = true;
	else
	  break;

	xmlNodePtr node = xmlTextReaderExpand(reader.get());
	if (!node)
	  return false;

	if (has_fn_syms)
	  fn_symdb = build_elf_symbol_db(rdr, node, true);
	else if (has_var_syms)
	  var_symdb = build_elf_symbol_db(rdr, node, false);

	xmlTextReaderNext(reader.get());
      }
  else
    for (xmlNodePtr n = rdr.get_corpus_node(); n; n = xmlNextElementSibling(n))
      {
	bool has_fn_syms = false, has_var_syms = false;
	if (xmlStrEqual(n->name, BAD_CAST("elf-function-symbols")))
	  has_fn_syms = true;
	else if (xmlStrEqual(n->name, BAD_CAST("elf-variable-symbols")))
	  has_var_syms = true;
	else
	  {
	    rdr.set_corpus_node(n);
	    break;
	  }

	if (has_fn_syms)
	  fn_symdb = build_elf_symbol_db(rdr, n, true);
	else if (has_var_syms)
	  var_symdb = build_elf_symbol_db(rdr, n, false);
	else
	  break;
      }

  return true;
}

/// From an "elf-needed" XML_ELEMENT node, build a vector of strings
/// representing the vector of the dependencies needed by a given
/// corpus.
///
/// @param node the XML_ELEMENT node of name "elf-needed".
///
/// @param needed the output vector of string to populate with the
/// vector of dependency names found on the xml node @p node.
///
/// @return true upon successful completion, false otherwise.
static bool
build_needed(xmlNode* node, vector<string>& needed)
{
  if (!node || !xmlStrEqual(node->name,BAD_CAST("elf-needed")))
    return false;

  for (xmlNodePtr n = xmlFirstElementChild(node);
       n;
       n = xmlNextElementSibling(n))
    {
      if (!xmlStrEqual(n->name, BAD_CAST("dependency")))
	continue;

      string name;
      if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(n, "name"))
	xml::xml_char_sptr_to_string(s, name);

      if (!name.empty())
	needed.push_back(name);
    }

  return true;
}

/// Move to the next xml element node and expext it to be named
/// "elf-needed".  Then read the sub-tree to made of that node and
/// extracts a vector of needed dependencies name from it.
///
/// @param rdr the ABIXML reader used to the xml reading.
///
/// @param needed the resulting vector of dependency names.
///
/// @return true upon successful completion, false otherwise.
static bool
read_elf_needed_from_input(reader&	rdr,
			   vector<string>&	needed)
{
  xml::reader_sptr reader = rdr.get_libxml_reader();
  if (!reader)
    return false;

  xmlNodePtr node = 0;

  if (rdr.get_corpus_node() == 0)
    {
      int status = 1;
      while (status == 1
	     && XML_READER_GET_NODE_TYPE(reader) != XML_READER_TYPE_ELEMENT)
	status = advance_cursor (rdr);

      if (status != 1)
	return false;

      if (!xmlStrEqual (XML_READER_GET_NODE_NAME(reader).get(),
			BAD_CAST("elf-needed")))
	return false;

      node = xmlTextReaderExpand(reader.get());
      if (!node)
	return false;
    }
  else
    {
      for (xmlNodePtr n = rdr.get_corpus_node();
	   n;
	   n = xmlNextElementSibling(n))
	{
	  if (!xmlStrEqual(n->name, BAD_CAST("elf-needed")))
	    return false;
	  node = n;
	  break;
	}
    }

  bool result = false;
  if (node)
    {
      result = build_needed(node, needed);
      node = xmlNextElementSibling(node);
      rdr.set_corpus_node(node);
    }

  return result;
}

/// Add suppressions specifications to the set of suppressions to be
/// used during the construction of the ABI internal representation
/// (the ABI corpus) from ELF and DWARF.
///
/// During the construction of the ABI corpus, ABI artifacts that
/// match the a given suppression specification are dropped on the
/// floor; that is, they are discarded and won't be part of the final
/// ABI corpus.  This is a way to reduce the amount of data held by
/// the final ABI corpus.
///
/// Note that the suppression specifications provided to this function
/// are only considered during the construction of the ABI corpus.
/// For instance, they are not taken into account during e.g
/// comparisons of two ABI corpora that might happen later.  If you
/// want to apply suppression specifications to the comparison (or
/// reporting) of ABI corpora please refer to the documentation of the
/// @ref diff_context type to learn how to set suppressions that are
/// to be used in that context.
///
/// @param rdr the context that is going to be used by functions that
/// read types and declarations information to construct and ABI
/// corpus.
///
/// @param supprs the suppression specifications to be applied during
/// the construction of the ABI corpus.
void
add_reader_suppressions(reader& rdr,
			const suppr::suppressions_type& supprs)
{
  for (suppr::suppressions_type::const_iterator i = supprs.begin();
       i != supprs.end();
       ++i)
    if ((*i)->get_drops_artifact_from_ir())
      rdr.suppressions().push_back(*i);
}

/// Configure the @ref reader so that types not reachable from
/// public interface are taken into account when the abixml file is
/// read.
///
/// @param rdr the @reader to consider.
///
/// @param flag if yes, then types not reachable from public interface
/// are taken into account when the abixml file is read.
void
consider_types_not_reachable_from_public_interfaces(fe_iface& iface,
						    bool flag)
{
  abixml::reader& rdr = dynamic_cast<abixml::reader&>(iface);
  rdr.tracking_non_reachable_types(flag);
}

#ifdef WITH_SHOW_TYPE_USE_IN_ABILINT
/// Get the vector of types that have a given type-id.
///
/// This function is available only if the project has been configured
/// with --enable-show-type-use-in-abilint.
///
/// @param rdr the abixml text reader context to use.
///
/// @param type_id the type-id to consider.
vector<type_base_sptr>*
get_types_from_type_id(fe_iface& iface, const string& type_id)
{
  xml_reader::reader& rdr = dynamic_cast<xml_reader::reader&>(iface);
  auto it = rdr.m_types_map.find(type_id);
  if (it == rdr.m_types_map.end())
    return nullptr;
  return &it->second;
}

/// Get the map that associates an artififact to its users.
///
/// This function is available only if the project has been configured
/// with --enable-show-type-use-in-abilint.
///
/// @param rdr the abixml text reader context to use.
unordered_map<type_or_decl_base*, vector<type_or_decl_base*>>*
get_artifact_used_by_relation_map(fe_iface& iface)
{
  xml_reader::reader& rdr = dynamic_cast<xml_reader::reader&>(iface);
  return &rdr.m_artifact_used_by_map;
}
#endif

/// Read the "version" attribute from the current XML element which is
/// supposed to be a corpus or a corpus group and set the format
/// version to the corpus object accordingly.
///
/// Note that this is a subroutine of read_corpus_from_input and
/// read_corpus_group_from_input.
///
/// @param reader the XML reader to consider.  That reader must be
/// set to an XML element representing a corpus or a corpus group.
///
/// @param corp output parameter.  The corpus object which format
/// version string is going to be set according to the value of the
/// "version" attribute found on the current XML element.
static void
handle_version_attribute(xml::reader_sptr& reader, corpus& corp)
{
  string version_string;
  if (xml_char_sptr s = XML_READER_GET_ATTRIBUTE(reader, "version"))
    xml::xml_char_sptr_to_string(s, version_string);

  vector<string> v;
  if (version_string.empty())
    {
      v.push_back("1");
      v.push_back("0");
    }
  else
    tools_utils::split_string(version_string, ".", v);
  corp.set_format_major_version_number(v[0]);
  corp.set_format_minor_version_number(v[1]);
}

/// Parse the input XML document containing an ABI corpus group,
/// represented by an 'abi-corpus-group' element node, associated to
/// the current context.
///
/// @param rdr the current input context.
///
/// @return the corpus group resulting from the parsing
corpus_group_sptr
read_corpus_group_from_input(fe_iface& iface)
{
  corpus_group_sptr nil;

  abixml::reader& rdr = dynamic_cast<abixml::reader&>(iface);
  xml::reader_sptr reader = rdr.get_libxml_reader();
  if (!reader)
    return nil;

  // The document must start with the abi-corpus-group node.
  int status = 1;
  while (status == 1
	 && XML_READER_GET_NODE_TYPE(reader) != XML_READER_TYPE_ELEMENT)
    status = advance_cursor (rdr);

  if (status != 1 || !xmlStrEqual (XML_READER_GET_NODE_NAME(reader).get(),
				   BAD_CAST("abi-corpus-group")))
    return nil;

  if (!rdr.corpus_group())
    {
      corpus_group_sptr g(new corpus_group(rdr.get_environment(),
					   rdr.get_path()));
      g->set_origin(corpus::NATIVE_XML_ORIGIN);
      rdr.corpus_group(g);
    }

  corpus_group_sptr group = rdr.corpus_group();

  handle_version_attribute(reader, *group);

  xml::xml_char_sptr path_str = XML_READER_GET_ATTRIBUTE(reader, "path");
  if (path_str)
    group->set_path(reinterpret_cast<char*>(path_str.get()));

  xmlNodePtr node = xmlTextReaderExpand(reader.get());
  if (!node)
    return nil;

  node = xmlFirstElementChild(node);
  rdr.set_corpus_node(node);

  corpus_sptr corp;
  fe_iface::status sts;
  while ((corp = rdr.read_corpus(sts)))
    rdr.corpus_group()->add_corpus(corp);

  xmlTextReaderNext(reader.get());

  return rdr.corpus_group();
}

/// De-serialize an ABI corpus group from an input XML document which
/// root node is 'abi-corpus-group'.
///
/// @param in the input stream to read the XML document from.
///
/// @param env the environment to use.  Note that the life time of
/// this environment must be greater than the lifetime of the
/// resulting corpus as the corpus uses resources that are allocated
/// in the environment.
///
/// @return the resulting corpus group de-serialized from the parsing.
/// This is non-null iff the parsing resulted in a valid corpus group.
corpus_group_sptr
read_corpus_group_from_abixml(std::istream* in,
			      environment&  env)
{
  fe_iface_sptr rdr = create_reader(in, env);
  return read_corpus_group_from_input(*rdr);
}

/// De-serialize an ABI corpus group from an XML document file which
/// root node is 'abi-corpus-group'.
///
/// @param path the path to the input file to read the XML document
/// from.
///
/// @param env the environment to use.  Note that the life time of
/// this environment must be greater than the lifetime of the
/// resulting corpus as the corpus uses resources that are allocated
/// in the environment.
///
/// @return the resulting corpus group de-serialized from the parsing.
/// This is non-null if the parsing successfully resulted in a corpus
/// group.
corpus_group_sptr
read_corpus_group_from_abixml_file(const string& path,
				   environment&  env)
{
    fe_iface_sptr rdr = create_reader(path, env);
    corpus_group_sptr group = read_corpus_group_from_input(*rdr);
    return group;
}

/// Parse an ABI instrumentation file (in XML format) at a given path.
///
/// @param input_file a path to the file containing the xml document
/// to parse.
///
/// @param env the environment to use.
///
/// @return the translation unit resulting from the parsing upon
/// successful completion, or nil.
translation_unit_sptr
read_translation_unit_from_file(const string&	input_file,
				environment&	env)
{
  reader rdr(xml::new_reader_from_file(input_file), env);
  translation_unit_sptr tu = read_translation_unit_from_input(rdr);
  env.canonicalization_is_done(false);
  rdr.perform_late_type_canonicalizing();
  env.canonicalization_is_done(true);
  return tu;
}

/// Parse an ABI instrumentation file (in XML format) from an
/// in-memory buffer.
///
/// @param buffer the in-memory buffer containing the xml document to
/// parse.
///
/// @param env the environment to use.
///
/// @return the translation unit resulting from the parsing upon
/// successful completion, or nil.
translation_unit_sptr
read_translation_unit_from_buffer(const string&	buffer,
				  environment&	env)
{
  reader rdr(xml::new_reader_from_buffer(buffer), env);
  translation_unit_sptr tu = read_translation_unit_from_input(rdr);
  env.canonicalization_is_done(false);
  rdr.perform_late_type_canonicalizing();
  env.canonicalization_is_done(true);
  return tu;
}

/// Parse a translation unit from an abixml input from a given
/// context.
///
/// @param rdr the @ref reader to consider.
///
/// @return the constructed @ref translation_unit from the content of
/// the input abixml.
translation_unit_sptr
read_translation_unit(fe_iface& iface)
{
  abixml::reader& rdr = dynamic_cast<abixml::reader&>(iface);
  translation_unit_sptr tu = read_translation_unit_from_input(rdr);
  rdr.options().env.canonicalization_is_done(false);
  rdr.perform_late_type_canonicalizing();
  rdr.options().env.canonicalization_is_done(true);
  return tu;
}

/// This function is called by @ref read_translation_unit_from_input.
/// It handles the current xml element node of the reading context.
/// The result of the "handling" is to build the representation of the
/// xml node and tied it to the current translation unit.
///
/// @param rdr the current parsing context.
///
/// @return true upon successful completion, false otherwise.
static type_or_decl_base_sptr
handle_element_node(reader& rdr, xmlNodePtr node,
		    bool add_to_current_scope)
{
  type_or_decl_base_sptr decl;
  if (!node)
    return decl;

  ((decl = handle_namespace_decl(rdr, node, add_to_current_scope))
   ||(decl = handle_type_decl(rdr, node, add_to_current_scope))
   ||(decl = handle_qualified_type_decl(rdr, node,
					add_to_current_scope))
   ||(decl = handle_pointer_type_def(rdr, node,
				     add_to_current_scope))
   || (decl = handle_reference_type_def(rdr, node, add_to_current_scope))
   || (decl = handle_function_type(rdr, node, add_to_current_scope))
   || (decl = handle_array_type_def(rdr, node, add_to_current_scope))
   || (decl = handle_enum_type_decl(rdr, node,
				    add_to_current_scope))
   || (decl = handle_typedef_decl(rdr, node,
				  add_to_current_scope))
   || (decl = handle_var_decl(rdr, node,
			      add_to_current_scope))
   || (decl = handle_function_decl(rdr, node,
				   add_to_current_scope))
   || (decl = handle_class_decl(rdr, node,
				add_to_current_scope))
   || (decl = handle_union_decl(rdr, node,
				add_to_current_scope))
   || (decl = handle_function_tdecl(rdr, node,
				    add_to_current_scope))
   || (decl = handle_class_tdecl(rdr, node,
				 add_to_current_scope)));

  // If the user wants us to track non-reachable types, then read the
  // 'is-non-reachable-type' attribute on type elements and record
  // reachable types accordingly.
  if (rdr.tracking_non_reachable_types())
    {
      if (type_base_sptr t = is_type(decl))
	{
	  corpus_sptr abi = rdr.corpus();
	  ABG_ASSERT(abi);
	  bool is_non_reachable_type = false;
	  read_is_non_reachable_type(node, is_non_reachable_type);
	  if (!is_non_reachable_type)
	    abi->record_type_as_reachable_from_public_interfaces(*t);
	}
    }

    return decl;
}

/// Parses location attributes on an xmlNodePtr.
///
///@param rdr the current parsing context
///
///@param loc the resulting location.
///
/// @return true upon sucessful parsing, false otherwise.
static bool
read_location(const reader&	rdr,
	      xmlNodePtr		node,
	      location&		loc)
{
  string file_path;
  size_t line = 0, column = 0;

  if (xml_char_sptr f = xml::build_sptr(xmlGetProp(node, BAD_CAST("filepath"))))
    file_path = CHAR_STR(f);

  if (file_path.empty())
    return read_artificial_location(rdr, node, loc);

  if (xml_char_sptr l = xml::build_sptr(xmlGetProp(node, BAD_CAST("line"))))
    line = atoi(CHAR_STR(l));
  else
    return read_artificial_location(rdr, node, loc);

  if (xml_char_sptr c = xml::build_sptr(xmlGetProp(node, BAD_CAST("column"))))
    column = atoi(CHAR_STR(c));

  reader& c = const_cast<reader&>(rdr);
  loc = c.get_translation_unit()->get_loc_mgr().create_new_location(file_path,
								    line,
								    column);
  return true;
}

/// Parses the artificial location attributes on an xmlNodePtr.
///
/// The artificial location is the line number of the xmlNode as well
/// as the URI of the node.
///
///@param rdr the current parsing context
///
///@param loc the resulting location.
///
/// @return true upon sucessful parsing, false otherwise.
static bool
read_artificial_location(const reader& rdr,
			 xmlNodePtr node,
			 location& loc)
{
  if (!node)
    return false;

   string file_path;
   size_t line = 0, column = 0;

   line = node->line;

   if (node->doc)
       file_path = reinterpret_cast<const char*>(node->doc->URL);

   reader& c = const_cast<reader&>(rdr);
   loc =
     c.get_translation_unit()->get_loc_mgr().create_new_location(file_path,
								 line, column);
   loc.set_is_artificial(true);
   return true;
}

/// Set the artificial location of a xmlNode to an artifact.
///
/// The artificial location is the line number of the xmlNode as well
/// as the URI of the node.
///
/// The function sets the artificial location only if the artifact
/// doesn"t already have one.
///
///@param rdr the current parsing context
///
///@param node the XML node to consider.
///
///@param artifact the ABI artifact.
///
/// @return true iff the location was set on the artifact.
static bool
maybe_set_artificial_location(const reader& rdr,
			      xmlNodePtr node,
			      type_or_decl_base_sptr artefact)
{
  if (artefact && !artefact->has_artificial_location())
    {
      location l;
      if (read_artificial_location(rdr, node, l))
	{
	  artefact->set_artificial_location(l);
	  return true;
	}
    }
  return false;
}

/// Parse the visibility attribute.
///
/// @param node the xml node to read from.
///
/// @param vis the resulting visibility.
///
/// @return true upon successful completion, false otherwise.
static bool
read_visibility(xmlNodePtr node, decl_base::visibility& vis)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "visibility"))
    {
      string v = CHAR_STR(s);

      if (v == "default")
	vis = decl_base::VISIBILITY_DEFAULT;
      else if (v == "hidden")
	vis = decl_base::VISIBILITY_HIDDEN;
      else if (v == "internal")
	vis = decl_base::VISIBILITY_INTERNAL;
      else if (v == "protected")
	vis = decl_base::VISIBILITY_PROTECTED;
      else
	vis = decl_base::VISIBILITY_DEFAULT;
      return true;
    }
  return false;
}

/// Parse the "binding" attribute on the current element.
///
/// @param node the xml node to build parse the bind from.
///
/// @param bind the resulting binding attribute.
///
/// @return true upon successful completion, false otherwise.
static bool
read_binding(xmlNodePtr node, decl_base::binding& bind)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "binding"))
    {
      string b = CHAR_STR(s);

      if (b == "global")
	bind = decl_base::BINDING_GLOBAL;
      else if (b == "local")
	bind = decl_base::BINDING_LOCAL;
      else if (b == "weak")
	bind = decl_base::BINDING_WEAK;
      else
	bind = decl_base::BINDING_GLOBAL;
      return true;
    }

  return false;
}

/// Read the 'access' attribute on the current xml node.
///
/// @param node the xml node to consider.
///
/// @param access the access attribute.  Set iff the function returns true.
///
/// @return true upon sucessful completion, false otherwise.
static bool
read_access(xmlNodePtr node, access_specifier& access)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "access"))
    {
      string a = CHAR_STR(s);

      if (a == "private")
	access = private_access;
      else if (a == "protected")
	access = protected_access;
      else if (a == "public")
	access = public_access;
      else
	/// If there is an access specifier of an unsupported value,
	/// we should not assume anything and abort.
	abort();

      return true;
    }
  return false;
}

/// Parse 'size-in-bits' and 'alignment-in-bits' attributes of a given
/// xmlNodePtr reprensting an xml element.
///
/// @param node the xml element node to consider.
///
/// @param size_in_bits the resulting value for the 'size-in-bits'
/// attribute.  This set only if this function returns true and the if
/// the attribute was present on the xml element node.
///
/// @param align_in_bits the resulting value for the
/// 'alignment-in-bits' attribute.  This set only if this function
/// returns true and the if the attribute was present on the xml
/// element node.
///
/// @return true if either one of the two attributes above were set,
/// false otherwise.
static bool
read_size_and_alignment(xmlNodePtr node,
			size_t& size_in_bits,
			size_t& align_in_bits)
{

  bool got_something = false;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "size-in-bits"))
    {
      size_in_bits = atoll(CHAR_STR(s));
      got_something = true;
    }

  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "alignment-in-bits"))
    {
      align_in_bits = atoll(CHAR_STR(s));
      got_something = true;
    }
  return got_something;
}

/// Parse the 'static' attribute of a given xml element node.
///
/// @param node the xml element node to consider.
///
/// @param is_static the resulting the parsing.  Is set if the
/// function returns true.
///
/// @return true if the xml element node has the 'static' attribute
/// set, false otherwise.
static bool
read_static(xmlNodePtr node, bool& is_static)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "static"))
    {
      string b = CHAR_STR(s);
      is_static = b == "yes";
      return true;
    }
  return false;
}

/// Parse the 'layout-offset-in-bits' attribute of a given xml element node.
///
/// @param offset_in_bits set to true if the element node contains the
/// attribute.
///
/// @return true iff the xml element node contains the attribute.
static bool
read_offset_in_bits(xmlNodePtr	node,
		    size_t&	offset_in_bits)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "layout-offset-in-bits"))
    {
      offset_in_bits = strtoull(CHAR_STR(s), 0, 0);
      return true;
    }
  return false;
}

/// Parse the 'constructor', 'destructor' and 'const' attribute of a
/// given xml node.
///
/// @param is_constructor the resulting value of the parsing of the
/// 'constructor' attribute.  Is set if the xml node contains the
/// attribute and if the function returns true.
///
/// @param is_destructor the resulting value of the parsing of the
/// 'destructor' attribute.  Is set if the xml node contains the
/// attribute and if the function returns true.
///
/// @param is_const the resulting value of the parsing of the 'const'
/// attribute.  Is set if the xml node contains the attribute and if
/// the function returns true.
///
/// @return true if at least of the attributes above is set, false
/// otherwise.
///
/// Note that callers of this function should initialize
/// is_constructor, is_destructor and is_const prior to passing them
/// to this function.
static bool
read_cdtor_const(xmlNodePtr	node,
		 bool&		is_constructor,
		 bool&		is_destructor,
		 bool&		is_const)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "constructor"))
    {
      string b = CHAR_STR(s);
      if (b == "yes")
	is_constructor = true;
      else
	is_constructor = false;

      return true;
    }

  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "destructor"))
    {
      string b = CHAR_STR(s);
      if (b == "yes")
	is_destructor = true;
      else
	is_destructor = false;

      return true;
    }

  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "const"))
    {
      string b = CHAR_STR(s);
      if (b == "yes")
	is_const = true;
      else
	is_const = false;

      return true;
    }

  return false;
}

/// Read the "is-declaration-only" attribute of the current xml node.
///
/// @param node the xml node to consider.
///
/// @param is_decl_only is set to true iff the "is-declaration-only" attribute
/// is present and set to "yes".
///
/// @return true iff the is_decl_only attribute was set.
static bool
read_is_declaration_only(xmlNodePtr node, bool& is_decl_only)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "is-declaration-only"))
    {
      string str = CHAR_STR(s);
      if (str == "yes")
	is_decl_only = true;
      else
	is_decl_only = false;
      return true;
    }
  return false;
}

/// Read the "is-artificial" attribute of the current XML node.
///
/// @param node the XML node to consider.
///
/// @param is_artificial this output parameter is set to true iff the
/// "is-artificial" parameter is present and set to 'yes'.
///
/// @return true iff the "is-artificial" parameter was present on the
/// XML node.
static bool
read_is_artificial(xmlNodePtr node, bool& is_artificial)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "is-artificial"))
    {
      string is_artificial_str = CHAR_STR(s) ? CHAR_STR(s) : "";
      is_artificial = is_artificial_str == "yes";
      return true;
    }
  return false;
}

/// Read the 'tracking-non-reachable-types' attribute on the current
/// XML element.
///
/// @param node the current XML element.
///
/// @param tracking_non_reachable_types output parameter.  This is set
/// to true iff the 'tracking-non-reachable-types' attribute is
/// present on the current XML node and set to 'yes'.  In that case,
/// the function returns true.
///
/// @return true iff the 'tracking-non-reachable-types' attribute is
/// present on the current XML node and set to 'yes'.
static bool
read_tracking_non_reachable_types(xmlNodePtr node,
				  bool& tracking_non_reachable_types)
{
  if (xml_char_sptr s =
      XML_NODE_GET_ATTRIBUTE(node, "tracking-non-reachable-types"))
    {
      string tracking_non_reachable_types_str = CHAR_STR(s) ? CHAR_STR(s) : "";
      tracking_non_reachable_types =
	(tracking_non_reachable_types_str == "yes")
	? true
	: false;
      return true;
    }
  return false;
}

/// Read the 'is-non-reachable' attribute on the current XML element.
///
/// @param node the current XML element.
///
/// @param is_non_reachable_type output parameter. This is set to true
/// iff the 'is-non-reachable' attribute is present on the current XML
/// element with a value se to 'yes'.
///
/// @return true iff the 'is-non-reachable' attribute is present on
/// the current XML element with a value se to 'yes'.
static bool
read_is_non_reachable_type(xmlNodePtr node, bool& is_non_reachable_type)
{
  if (xml_char_sptr s =
      XML_NODE_GET_ATTRIBUTE(node, "is-non-reachable"))
    {
      string is_non_reachable_type_str = CHAR_STR(s) ? CHAR_STR(s) : "";
      is_non_reachable_type =
	(is_non_reachable_type_str == "yes")
	? true
	: false;
      return true;
    }
  return false;
}

/// Read the "naming-typedef-id" property from an XML node.
///
/// @param node the XML node to consider.
///
/// @param naming_typedef_id output parameter.  It's set to the
/// content of the "naming-typedef-id" property, if it's present.
///
/// @return true iff the "naming-typedef-id" property exists and was
/// read from @p node.
static bool
read_naming_typedef_id_string(xmlNodePtr node, string& naming_typedef_id)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "naming-typedef-id"))
    {
      naming_typedef_id = xml::unescape_xml_string(CHAR_STR(s));
      return true;
    }
  return false;
}

/// Read the "is-virtual" attribute of the current xml node.
///
/// @param node the xml node to read the attribute from
///
/// @param is_virtual is set to true iff the "is-virtual" attribute is
/// present and set to "yes".
///
/// @return true iff the is-virtual attribute is present.
static bool
read_is_virtual(xmlNodePtr node, bool& is_virtual)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "is-virtual"))
    {
      string str = CHAR_STR(s);
      if (str == "yes")
	is_virtual = true;
      else
	is_virtual = false;
      return true;
    }
  return false;
}

/// Read the 'is-struct' attribute.
///
/// @param node the xml node to read the attribute from.
///
/// @param is_struct is set to true iff the "is-struct" attribute is
/// present and set to "yes".
///
/// @return true iff the "is-struct" attribute is present.
static bool
read_is_struct(xmlNodePtr node, bool& is_struct)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "is-struct"))
    {
      string str = CHAR_STR(s);
      if (str == "yes")
	  is_struct = true;
      else
	is_struct = false;
      return true;
    }
  return false;
}

/// Read the 'is-anonymous' attribute.
///
/// @param node the xml node to read the attribute from.
///
/// @param is_anonymous is set to true iff the "is-anonymous" is present
/// and set to "yes".
///
/// @return true iff the "is-anonymous" attribute is present.
static bool
read_is_anonymous(xmlNodePtr node, bool& is_anonymous)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "is-anonymous"))
    {
      string str = CHAR_STR(s);
      is_anonymous = (str == "yes");
      return true;
    }
  return false;
}

/// Read the 'type' attribute of the 'elf-symbol' element.
///
/// @param node the XML node to read the attribute from.
///
/// @param t the resulting elf_symbol::type.
///
/// @return true iff the function completed successfully.
static bool
read_elf_symbol_type(xmlNodePtr node, elf_symbol::type& t)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "type"))
    {
      string str;
      xml::xml_char_sptr_to_string(s, str);
      if (!string_to_elf_symbol_type(str, t))
	return false;
      return true;
    }
  return false;
}

/// Read the 'binding' attribute of the of the 'elf-symbol' element.
///
/// @param node the XML node to read the attribute from.
///
/// @param b the XML the resulting elf_symbol::binding.
///
/// @return true iff the function completed successfully.
static bool
read_elf_symbol_binding(xmlNodePtr node, elf_symbol::binding& b)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "binding"))
    {
      string str;
      xml::xml_char_sptr_to_string(s, str);
      if (!string_to_elf_symbol_binding(str, b))
	return false;
      return true;
    }
  return false;
}

/// Read the 'visibility' attribute of the of the 'elf-symbol'
/// element.
///
/// @param node the XML node to read the attribute from.
///
/// @param b the XML the resulting elf_symbol::visibility.
///
/// @return true iff the function completed successfully.
static bool
read_elf_symbol_visibility(xmlNodePtr node, elf_symbol::visibility& v)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "visibility"))
    {
      string str;
      xml::xml_char_sptr_to_string(s, str);
      if (!string_to_elf_symbol_visibility(str, v))
	return false;
      return true;
    }
  return false;
}
/// Read the value of the 'id' attribute from a given XML node.
///
/// @param node the XML node to consider.
///
/// @param type_id the string to set the 'id' to.
///
/// @return true iff @p type_id was successfully set.
static bool
read_type_id_string(xmlNodePtr node, string& type_id)
{
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    {
      type_id = CHAR_STR(s);
      return true;
    }
  return false;
}

#ifdef WITH_DEBUG_SELF_COMPARISON
/// Associate a type-id string with the type that was constructed from
/// it.
///
/// Note that if we are not in "self comparison debugging" mode or if
/// the type we are looking at is not canonicalized, then this
/// function does nothing.
///
/// @param t the type built from the a type XML node that has a
/// particular type-id.
///
/// @param type_id the type-id of type @p t.
///
/// @return true if the association was performed.
static bool
maybe_map_type_with_type_id(const type_base_sptr& t,
			    const string& type_id)
{
  if (!t)
    return false;

  const environment& env = t->get_environment();
  if (!env.self_comparison_debug_is_on()
      || is_non_canonicalized_type(t.get()))
    return false;

  const_cast<environment&>(env).
    get_pointer_type_id_map()[reinterpret_cast<uintptr_t>(t.get())] = type_id;

  return true;
}

/// Associate a type-id string with the type that was constructed from
/// it.
///
/// Note that if we are not in "self comparison debugging" mode or if
/// the type we are looking at is not canonicalized, then this
/// function does nothing.
///
/// @param t the type built from the a type XML node that has a
/// particular type-id.
///
/// @param type_id the type-id of type @p t.
///
/// @return true if the association was performed.
static bool
maybe_map_type_with_type_id(const type_base_sptr& t,
			    xmlNodePtr node)
{
  if (!t)
    return false;

  const environment&env = t->get_environment();
  if (!env.self_comparison_debug_is_on()
      || is_non_canonicalized_type(t.get()))
    return false;

  string type_id;
  if (!read_type_id_string(node, type_id) || type_id.empty())
    return false;

  return maybe_map_type_with_type_id(t, type_id);
}

#endif

/// Set the naming typedef to a given decl depending on the content of
/// the "naming-typedef-id" property of its descriptive XML element.
///
/// @param rdr the current ABIXML reader.
///
/// @param node the XML node to read from.
///
/// @param decl the decl to set the naming typedef to.
static void
maybe_set_naming_typedef(reader&		rdr,
			 xmlNodePtr		node,
			 const decl_base_sptr&	decl)
{
  string naming_typedef_id;
  read_naming_typedef_id_string(node, naming_typedef_id);
  if (!naming_typedef_id.empty())
    {
      typedef_decl_sptr naming_typedef =
	is_typedef(rdr.build_or_get_type_decl(naming_typedef_id, true));
      ABG_ASSERT(naming_typedef);
      decl->set_naming_typedef(naming_typedef);
    }
}

/// Build a @ref namespace_decl from an XML element node which name is
/// "namespace-decl".  Note that this function recursively reads the
/// content of the namespace and builds the proper IR nodes
/// accordingly.
///
/// @param rdr the ABIXML reader to use.
///
/// @param node the XML node to consider.  It must constain the
/// content of the namespace, that is, children XML nodes representing
/// what is inside the namespace, unless the namespace is empty.
///
/// @param add_to_current_scope if set to yes, the resulting
/// namespace_decl is added to the IR being currently built.
///
/// @return a pointer to the the resulting @ref namespace_decl.
static namespace_decl_sptr
build_namespace_decl(reader&	rdr,
		     const xmlNodePtr	node,
		     bool		add_to_current_scope)
{
  namespace_decl_sptr nil;
  if (!node || !xmlStrEqual(node->name, BAD_CAST("namespace-decl")))
    return nil;

  if (decl_base_sptr d = rdr.get_decl_for_xml_node(node))
    {
      namespace_decl_sptr result = dynamic_pointer_cast<namespace_decl>(d);
      ABG_ASSERT(result);
      return result;
    }

  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    name = xml::unescape_xml_string(CHAR_STR(s));

  location loc;
  read_location(rdr, node, loc);

  const environment& env = rdr.get_environment();
  namespace_decl_sptr decl(new namespace_decl(env, name, loc));
  maybe_set_artificial_location(rdr, node, decl);
  rdr.push_decl_to_scope(decl,
			 add_to_current_scope
			 ? rdr.get_scope_ptr_for_node(node)
			 : nullptr);
  rdr.map_xml_node_to_decl(node, decl);

  for (xmlNodePtr n = xmlFirstElementChild(node);
       n;
       n = xmlNextElementSibling(n))
    handle_element_node(rdr, n, /*add_to_current_scope=*/true);

  rdr.pop_scope_or_abort(decl);

  return decl;
}

/// Build an instance of @ref elf_symbol from an XML element node
/// which name is 'elf-symbol'.
///
/// @param rdr the context used for reading the XML input.
///
/// @param node the XML node to read.
///
/// @param drop_if_suppressed if the elf symbol was suppressed by a
/// suppression specification then do not build it.
///
/// @return the @ref elf_symbol built, or nil if it couldn't be built.
static elf_symbol_sptr
build_elf_symbol(reader& rdr, const xmlNodePtr node,
		 bool drop_if_suppressed)
{
  elf_symbol_sptr nil;

  if (!node
      || node->type != XML_ELEMENT_NODE
      || !xmlStrEqual(node->name, BAD_CAST("elf-symbol")))
    return nil;

  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    xml::xml_char_sptr_to_string(s, name);

  size_t size = 0;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "size"))
    size = strtol(CHAR_STR(s), NULL, 0);

  bool is_defined = true;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "is-defined"))
    {
      string value;
      xml::xml_char_sptr_to_string(s, value);
      if (value == "true" || value == "yes")
	is_defined = true;
      else
	is_defined = false;
    }

  bool is_common = false;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "is-common"))
    {
      string value;
      xml::xml_char_sptr_to_string(s, value);
      if (value == "true" || value == "yes")
	is_common = true;
      else
	is_common = false;
    }

  string version_string;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "version"))
    xml::xml_char_sptr_to_string(s, version_string);

  bool is_default_version = false;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "is-default-version"))
    {
      string value;
      xml::xml_char_sptr_to_string(s, value);
      if (value == "true" || value == "yes")
	is_default_version = true;
    }

  elf_symbol::type type = elf_symbol::NOTYPE_TYPE;
  read_elf_symbol_type(node, type);

  elf_symbol::binding binding = elf_symbol::GLOBAL_BINDING;
  read_elf_symbol_binding(node, binding);

  elf_symbol::visibility visibility = elf_symbol::DEFAULT_VISIBILITY;
  read_elf_symbol_visibility(node, visibility);

  elf_symbol::version version(version_string, is_default_version);

  const bool is_suppressed = suppr::is_elf_symbol_suppressed(rdr, name, type);
  if (drop_if_suppressed && is_suppressed)
    return elf_symbol_sptr();

  const environment& env = rdr.get_environment();
  elf_symbol_sptr e = elf_symbol::create(env, /*index=*/0,
					 size, name, type, binding,
					 is_defined, is_common,
					 version, visibility);

  e->set_is_suppressed(is_suppressed);

  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "crc"))
    e->set_crc(strtoull(CHAR_STR(s), NULL, 0));

  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "namespace"))
    {
      std::string ns;
      xml::xml_char_sptr_to_string(s, ns);
      e->set_namespace(ns);
    }

  return e;
}

/// Build and instance of elf_symbol from an XML attribute named
/// 'elf-symbol-id' which value is the ID of a symbol that should
/// present in the symbol db of the corpus associated to the current
/// context.
///
/// @param rdr the current context to consider.
///
/// @param node the xml element node to consider.
///
/// @param function_symbol is true if we should look for a function
/// symbol, is false if we should look for a variable symbol.
///
/// @return a shared pointer the resutling elf_symbol.
static elf_symbol_sptr
build_elf_symbol_from_reference(reader& rdr, const xmlNodePtr node)
{
  elf_symbol_sptr nil;

  if (!node)
    return nil;

  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "elf-symbol-id"))
    {
      string sym_id;
      xml::xml_char_sptr_to_string(s, sym_id);
      if (sym_id.empty())
	return nil;

      string name, ver;
      elf_symbol::get_name_and_version_from_id(sym_id, name, ver);
      if (name.empty())
	return nil;

      if (rdr.corpus()->get_symtab())
	{
	  const elf_symbols& symbols =
	    rdr.corpus()->get_symtab()->lookup_symbol(name);

	  for (const auto& symbol : symbols)
	    if (symbol->get_id_string() == sym_id)
	      return symbol;
	}
    }

  return nil;
}

/// Build an instance of string_elf_symbols_map_type from an XML
/// element representing either a function symbols data base, or a
/// variable symbols database.
///
/// @param rdr the context to take in account.
///
/// @param node the XML node to consider.
///
/// @param function_syms true if we should look for a function symbols
/// data base, false if we should look for a variable symbols data
/// base.
static string_elf_symbols_map_sptr
build_elf_symbol_db(reader& rdr,
		    const xmlNodePtr node,
		    bool function_syms)
{
  string_elf_symbols_map_sptr map, nil;
  string_elf_symbol_sptr_map_type id_sym_map;

  if (!node)
    return nil;

  if (function_syms
      && !xmlStrEqual(node->name, BAD_CAST("elf-function-symbols")))
    return nil;

  if (!function_syms
      && !xmlStrEqual(node->name, BAD_CAST("elf-variable-symbols")))
    return nil;

  rdr.set_corpus_node(node);

  typedef std::unordered_map<xmlNodePtr, elf_symbol_sptr>
    xml_node_ptr_elf_symbol_sptr_map_type;
  xml_node_ptr_elf_symbol_sptr_map_type xml_node_ptr_elf_symbol_map;

  elf_symbol_sptr sym;
  for (xmlNodePtr n = xmlFirstElementChild(node);
       n;
       n = xmlNextElementSibling(n))
    if ((sym = build_elf_symbol(rdr, n, /*drop_if_suppress=*/false)))
      {
	id_sym_map[sym->get_id_string()] = sym;
	xml_node_ptr_elf_symbol_map[n] = sym;
      }

  if (id_sym_map.empty())
    return nil;

  map.reset(new string_elf_symbols_map_type);
  string_elf_symbols_map_type::iterator it;
  for (string_elf_symbol_sptr_map_type::const_iterator i = id_sym_map.begin();
       i != id_sym_map.end();
       ++i)
    (*map)[i->second->get_name()].push_back(i->second);

  // Now build the alias relations
  for (xml_node_ptr_elf_symbol_sptr_map_type::const_iterator x =
	 xml_node_ptr_elf_symbol_map.begin();
       x != xml_node_ptr_elf_symbol_map.end();
       ++x)
    {
      if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(x->first, "alias"))
	{
	  string alias_id = CHAR_STR(s);

	  // Symbol aliases can be multiple separated by comma(,), split them
	  std::vector<std::string> elems;
	  std::stringstream aliases(alias_id);
	  std::string item;
	  while (std::getline(aliases, item, ','))
	    elems.push_back(item);
	  for (std::vector<string>::iterator alias = elems.begin();
	       alias != elems.end(); ++alias)
	    {
	      string_elf_symbol_sptr_map_type::const_iterator i =
	      id_sym_map.find(*alias);
	      ABG_ASSERT(i != id_sym_map.end());
	      ABG_ASSERT(i->second->is_main_symbol());

	      x->second->get_main_symbol()->add_alias(i->second);
	    }
	}
    }

  return map;
}

/// Build a function parameter from a 'parameter' xml element node.
///
/// @param rdr the contexte of the xml parsing.
///
/// @param node the xml 'parameter' element node to de-serialize from.
static shared_ptr<function_decl::parameter>
build_function_parameter(reader& rdr, const xmlNodePtr node)
{
  shared_ptr<function_decl::parameter> nil;

  if (!node || !xmlStrEqual(node->name, BAD_CAST("parameter")))
    return nil;

  bool is_variadic = false;
  string is_variadic_str;
  if (xml_char_sptr s =
      xml::build_sptr(xmlGetProp(node, BAD_CAST("is-variadic"))))
    {
      is_variadic_str = CHAR_STR(s) ? CHAR_STR(s) : "";
      is_variadic = is_variadic_str == "yes";
    }

  bool is_artificial = false;
  read_is_artificial(node, is_artificial);

  string type_id;
  if (xml_char_sptr a = xml::build_sptr(xmlGetProp(node, BAD_CAST("type-id"))))
    type_id = CHAR_STR(a);

  type_base_sptr type;
  if (is_variadic)
    type = rdr.get_environment().get_variadic_parameter_type();
  else
    {
      ABG_ASSERT(!type_id.empty());
      type = rdr.build_or_get_type_decl(type_id, true);
    }
  ABG_ASSERT(type);

  string name;
  if (xml_char_sptr a = xml::build_sptr(xmlGetProp(node, BAD_CAST("name"))))
    name = CHAR_STR(a);

  location loc;
  read_location(rdr, node, loc);

  function_decl::parameter_sptr p
    (new function_decl::parameter(type, name, loc,
				  is_variadic, is_artificial));

  return p;
}

/// Build a function_decl from a 'function-decl' xml node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the function_decl from.
///
/// @param as_method_decl if this is set to a class_decl pointer, it
/// means that the 'function-decl' xml node should be parsed as a
/// method_decl.  The class_decl pointer is the class decl to which
/// the resulting method_decl is a member function of.  The resulting
/// shared_ptr<function_decl> that is returned is then really a
/// shared_ptr<method_decl>.
///
/// @param add_to_current_scope if set to yes, the result of
/// this function is added to its current scope.
///
/// @param add_to_exported_decls if set to yes, the resulting of this
/// function is added to the set of decls exported by the current
/// corpus being built.
///
/// @return a pointer to a newly created function_decl upon successful
/// completion, a null pointer otherwise.
static function_decl_sptr
build_function_decl(reader&		rdr,
		    const xmlNodePtr	node,
		    class_or_union_sptr as_method_decl,
		    bool		add_to_current_scope,
		    bool		add_to_exported_decls)
{
  function_decl_sptr nil;

  if (!xmlStrEqual(node->name, BAD_CAST("function-decl")))
    return nil;

  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    name = xml::unescape_xml_string(CHAR_STR(s));

  string mangled_name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "mangled-name"))
    mangled_name = xml::unescape_xml_string(CHAR_STR(s));

  if (as_method_decl
      && !mangled_name.empty()
      && as_method_decl->find_member_function_sptr(mangled_name))
    {
      function_decl_sptr result =
	as_method_decl->find_member_function_sptr(mangled_name);
      if (result)
	return result;
    }

  string inline_prop;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "declared-inline"))
    inline_prop = CHAR_STR(s);
  bool declared_inline = inline_prop == "yes";

  decl_base::visibility vis = decl_base::VISIBILITY_NONE;
  read_visibility(node, vis);

  decl_base::binding bind = decl_base::BINDING_NONE;
  read_binding(node, bind);

  size_t size = rdr.get_translation_unit()->get_address_size(), align = 0;
  read_size_and_alignment(node, size, align);

  location loc;
  read_location(rdr, node, loc);

  const environment& env = rdr.get_environment();

  std::vector<function_decl::parameter_sptr> parms;
  type_base_sptr return_type = env.get_void_type();

  for (xmlNodePtr n = xmlFirstElementChild(node);
       n ;
       n = xmlNextElementSibling(n))
    {
      if (xmlStrEqual(n->name, BAD_CAST("parameter")))
	{
	  if (function_decl::parameter_sptr p =
	      build_function_parameter(rdr, n))
	    parms.push_back(p);
	}
      else if (xmlStrEqual(n->name, BAD_CAST("return")))
	{
	  string type_id;
	  if (xml_char_sptr s =
	      xml::build_sptr(xmlGetProp(n, BAD_CAST("type-id"))))
	    type_id = CHAR_STR(s);
	  if (!type_id.empty())
	    return_type = rdr.build_or_get_type_decl(type_id, true);
	}
    }

  function_type_sptr fn_type(as_method_decl
			     ? new method_type(return_type, as_method_decl,
					       parms, /*is_const=*/false,
					       size, align)
			     : new function_type(return_type,
						 parms, size, align));

  ABG_ASSERT(fn_type);

  fn_type->set_is_artificial(true);

  function_decl_sptr fn_decl(as_method_decl
			     ? new method_decl (name, fn_type,
						declared_inline, loc,
						mangled_name, vis, bind)
			     : new function_decl(name, fn_type,
						 declared_inline, loc,
						 mangled_name, vis,
						 bind));

  maybe_set_artificial_location(rdr, node, fn_decl);
  rdr.push_decl_to_scope(fn_decl,
			 add_to_current_scope
			 ? rdr.get_scope_ptr_for_node(node)
			 : nullptr);
  RECORD_ARTIFACTS_AS_USED_IN_FN_DECL(rdr, fn_decl);

  elf_symbol_sptr sym = build_elf_symbol_from_reference(rdr, node);
  if (sym)
    fn_decl->set_symbol(sym);

  if (fn_decl->get_symbol() && fn_decl->get_symbol()->is_public())
    fn_decl->set_is_in_public_symbol_table(true);

  rdr.get_translation_unit()->bind_function_type_life_time(fn_type);

  rdr.maybe_canonicalize_type(fn_type, !add_to_current_scope);

  if (add_to_exported_decls)
    rdr.maybe_add_fn_to_exported_decls(fn_decl.get());

  return fn_decl;
}

/// Build a function_decl from a 'function-decl' xml node if it's not
/// been suppressed by a suppression specification that is in the
/// context.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the function_decl from.
///
/// @param as_method_decl if this is set to a class_or_union pointer,
/// it means that the 'function-decl' xml node should be parsed as a
/// method_decl.  The class_or_union pointer is the class or union the
/// resulting method_decl is a member function of.  The resulting @ref
/// function_decl_sptr that is returned is then really a @ref
/// method_decl_sptr.
///
/// @param add_to_current_scope if set to yes, the resulting of
/// this function is added to its current scope.
///
/// @param add_to_exported_decls if set to yes, the resulting of this
/// function is added to the set of decls exported by the current
/// corpus being built.
///
/// @return a pointer to a newly created function_decl upon successful
/// completion.  If the function was suppressed by a suppression
/// specification then returns nil.
static function_decl_sptr
build_function_decl_if_not_suppressed(reader&			rdr,
				      const xmlNodePtr		node,
				      class_or_union_sptr	as_method_decl,
				      bool			add_to_current_scope,
				      bool			add_to_exported_decls)
{
  function_decl_sptr fn;

  if (function_is_suppressed(rdr, node))
    // The function was suppressed by at least one suppression
    // specification associated to the current ABIXML reader.  So
    // don't build any IR for it.
    ;
  else
    fn = build_function_decl(rdr, node, as_method_decl,
			     add_to_current_scope,
			     add_to_exported_decls);
  return fn;
}

/// Test if a given function denoted by its name and linkage name is
/// suppressed by any of the suppression specifications associated to
/// a given context of native xml reading.
///
/// @param rdr the native xml reading context of interest.
///
/// @param note the XML node that represents the fucntion.
/// match.
///
/// @return true iff at least one function specification matches the
/// function denoted by the node @p node.
static bool
function_is_suppressed(const reader& rdr, xmlNodePtr node)
{
  string fname;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    fname = xml::unescape_xml_string(CHAR_STR(s));

  string flinkage_name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "mangled-name"))
    flinkage_name = xml::unescape_xml_string(CHAR_STR(s));

  scope_decl* scope = rdr.get_cur_scope();

  string qualified_name = build_qualified_name(scope, fname);

  return suppr::is_function_suppressed(rdr, qualified_name, flinkage_name);
}

/// Test if a type denoted by its name, context and location is
/// suppressed by the suppression specifications that are associated
/// to a given ABIXML reader.
///
/// @param rdr the ABIXML reader to consider.
///
/// @param note the XML node that represents the type.
///
/// @return true iff the type designated by @p node is suppressed by
///  at least of suppression specifications associated to the current
///  ABIXML reader.
static bool
type_is_suppressed(const reader& rdr, xmlNodePtr node)
{
  string type_name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    type_name = xml::unescape_xml_string(CHAR_STR(s));

  location type_location;
  read_location(rdr, node, type_location);

  scope_decl* scope = rdr.get_cur_scope();

  string qualified_name = build_qualified_name(scope, type_name);

  bool type_is_private = false;
  return suppr::is_type_suppressed(rdr, qualified_name, type_location,
				   type_is_private,
				   /*require_drop_property=*/true);
}

/// Build a @ref var_decl out of a an XML node that describes it iff
/// the variable denoted by the XML node is not suppressed by a
/// suppression specification associated to the current ABIXML reader.
///
/// @param rdr the ABIXML reader to use.
///
/// @param node the XML node for the variable to consider.
///
/// @parm add_to_current_scope whether to add the built @ref var_decl
/// to the current scope or not.
///
/// @return true iff the @ref var_decl was built.
static var_decl_sptr
build_var_decl_if_not_suppressed(reader&		rdr,
				 const xmlNodePtr	node,
				 bool			add_to_current_scope)
{
  var_decl_sptr var;
  if (!variable_is_suppressed(rdr, node))
    var = build_var_decl(rdr, node, add_to_current_scope);
  return var;
}

/// Test if a variable denoted by its XML node is suppressed by a
/// suppression specification that is present in a given ABIXML reader.
///
/// @param rdr the ABIXML reader to consider.
///
/// @param node the XML node of the variable to consider.
///
/// @return true iff the variable denoted by @p node is suppressed.
static bool
variable_is_suppressed(const reader& rdr, xmlNodePtr node)
{
  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    name = xml::unescape_xml_string(CHAR_STR(s));

  string linkage_name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "mangled-name"))
    linkage_name = xml::unescape_xml_string(CHAR_STR(s));

  scope_decl* scope = rdr.get_cur_scope();

  string qualified_name = build_qualified_name(scope, name);

  return suppr::is_variable_suppressed(rdr, qualified_name, linkage_name);
}

/// Test if a variable in a particular scope is suppressed by a
/// suppression specification that is present in a given ABIXML reader.
///
/// @parm rdr the ABIXML reader to consider.
///
/// @param scope the scope of the variable to consider.
///
/// @param v the variable to consider.
///
/// @return true iff the variable @p v is suppressed.
static bool
variable_is_suppressed(const reader& rdr,
		       const scope_decl* scope,
		       const var_decl& v)
{
  string qualified_name = build_qualified_name(scope, v.get_name());
  return suppr::is_variable_suppressed(rdr, qualified_name,
				       v.get_linkage_name());
}

/// Build pointer to var_decl from a 'var-decl' xml Node
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the var_decl from.
///
/// @return a pointer to a newly built var_decl upon successful
/// completion, a null pointer otherwise.
static shared_ptr<var_decl>
build_var_decl(reader&	rdr,
	       const xmlNodePtr node,
	       bool		add_to_current_scope)
{
  shared_ptr<var_decl> nil;

  if (!xmlStrEqual(node->name, BAD_CAST("var-decl")))
    return nil;

  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    name = xml::unescape_xml_string(CHAR_STR(s));

  string type_id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "type-id"))
    type_id = CHAR_STR(s);
  type_base_sptr underlying_type = rdr.build_or_get_type_decl(type_id,
							       true);
  ABG_ASSERT(underlying_type);

  string mangled_name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "mangled-name"))
    mangled_name = xml::unescape_xml_string(CHAR_STR(s));

  decl_base::visibility vis = decl_base::VISIBILITY_NONE;
  read_visibility(node, vis);

  decl_base::binding bind = decl_base::BINDING_NONE;
  read_binding(node, bind);

  location locus;
  read_location(rdr, node, locus);

  var_decl_sptr decl(new var_decl(name, underlying_type,
				  locus, mangled_name,
				  vis, bind));
  maybe_set_artificial_location(rdr, node, decl);

  elf_symbol_sptr sym = build_elf_symbol_from_reference(rdr, node);
  if (sym)
    decl->set_symbol(sym);

  rdr.push_decl_to_scope(decl,
			 add_to_current_scope
			 ? rdr.get_scope_ptr_for_node(node)
			 : nullptr);
  if (add_to_current_scope)
    {
      // This variable is really being kept in the IR, so let's record
      // that it's using its type.
      RECORD_ARTIFACT_AS_USED_BY(rdr, underlying_type, decl);
    }

  if (decl->get_symbol() && decl->get_symbol()->is_public())
    decl->set_is_in_public_symbol_table(true);

  return decl;
}

///  Build the IR node for a void type.
///
///  @param rdr the ABIXML reader to use.
///
///  @return the void type node.
static decl_base_sptr
build_ir_node_for_void_type(reader& rdr)
{
  const environment& env = rdr.get_environment();

  type_base_sptr t = env.get_void_type();
  add_decl_to_scope(is_decl(t), rdr.get_translation_unit()->get_global_scope());
  decl_base_sptr type_declaration = get_type_declaration(t);
  canonicalize(t);
  return type_declaration;
}

/// Build the IR node for a "pointer to void type".
///
/// That IR node is shared across the ABI corpus.
///
/// Note that this function just gets that IR node from the
/// environment and, if it's not added to any scope yet, adds it to
/// the global scope associated to the current translation unit.
///
/// @param rdr the DWARF reader to consider.
///
/// @return the IR node.
static decl_base_sptr
build_ir_node_for_void_pointer_type(reader& rdr)
{
    const environment& env = rdr.get_environment();

  type_base_sptr t = env.get_void_pointer_type();
  add_decl_to_scope(is_decl(t), rdr.get_translation_unit()->get_global_scope());
  decl_base_sptr type_declaration = get_type_declaration(t);
  canonicalize(t);
  return type_declaration;
}

/// Build a type_decl from a "type-decl" XML Node.
///
/// @param rdr the context of the parsing.
///
/// @param node the XML node to build the type_decl from.
///
/// @param add_to_current_scope if set to yes, the resulting of
/// this function is added to its current scope.
///
/// @return a pointer to type_decl upon successful completion, a null
/// pointer otherwise.
static type_decl_sptr
build_type_decl(reader&		rdr,
		const xmlNodePtr	node,
		bool			add_to_current_scope)
{
  shared_ptr<type_decl> nil;

  if (!xmlStrEqual(node->name, BAD_CAST("type-decl")))
    return nil;

  if (decl_base_sptr d = rdr.get_decl_for_xml_node(node))
    {
      type_decl_sptr result = dynamic_pointer_cast<type_decl>(d);
      ABG_ASSERT(result);
      return result;
    }

  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    name = xml::unescape_xml_string(CHAR_STR(s));

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);
  ABG_ASSERT(!id.empty());

  size_t size_in_bits= 0;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "size-in-bits"))
    size_in_bits = atoi(CHAR_STR(s));

  size_t alignment_in_bits = 0;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "alignment-in-bits"))
    alignment_in_bits = atoi(CHAR_STR(s));

  bool is_decl_only = false;
  read_is_declaration_only(node, is_decl_only);

  location loc;
  read_location(rdr, node, loc);

  bool is_anonymous = false;
  read_is_anonymous(node, is_anonymous);

  if (type_base_sptr d = rdr.get_type_decl(id))
    {
      // I've seen instances of DSOs where a type_decl would appear
      // several times.  Hugh.
      type_decl_sptr ty = dynamic_pointer_cast<type_decl>(d);
      ABG_ASSERT(ty);
      ABG_ASSERT(!name.empty());
      ABG_ASSERT(!ty->get_name().empty());
      ABG_ASSERT(ty->get_size_in_bits() == size_in_bits);
      ABG_ASSERT(ty->get_alignment_in_bits() == alignment_in_bits);
      return ty;
    }

  const environment& env = rdr.get_environment();
  type_decl_sptr decl;
  if (name == env.get_variadic_parameter_type_name())
    decl = is_type_decl(env.get_variadic_parameter_type());
  else if (name == "void")
    decl = is_type_decl(build_ir_node_for_void_type(rdr));
  else
    decl.reset(new type_decl(env, name, size_in_bits,
			     alignment_in_bits, loc));
  maybe_set_artificial_location(rdr, node, decl);
  decl->set_is_anonymous(is_anonymous);
  decl->set_is_declaration_only(is_decl_only);
  if (rdr.push_and_key_type_decl(decl, node, add_to_current_scope))
    {
      rdr.map_xml_node_to_decl(node, decl);
      return decl;
    }

  return nil;
}

/// Build a qualified_type_def from a 'qualified-type-def' xml node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the qualified_type_def from.
///
/// @param add_to_current_scope if set to yes, the resulting of this
/// function is added to its current scope.
///
/// @return a pointer to a newly built qualified_type_def upon
/// successful completion, a null pointer otherwise.
static qualified_type_def_sptr
build_qualified_type_decl(reader&	rdr,
			  const xmlNodePtr	node,
			  bool			add_to_current_scope)
{
  qualified_type_def_sptr nil;
  if (!xmlStrEqual(node->name, BAD_CAST("qualified-type-def")))
    return nil;

  if (decl_base_sptr d = rdr.get_decl_for_xml_node(node))
    {
      qualified_type_def_sptr result =
	dynamic_pointer_cast<qualified_type_def>(d);
      ABG_ASSERT(result);
      return result;
    }

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE (node, "id"))
    id = CHAR_STR(s);

  ABG_ASSERT(!id.empty());

  location loc;
  read_location(rdr, node, loc);

  qualified_type_def::CV cv = qualified_type_def::CV_NONE;
    string const_str;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "const"))
    const_str = CHAR_STR(s);
  bool const_cv = const_str == "yes";

  string volatile_str;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "volatile"))
    volatile_str = CHAR_STR(s);
  bool volatile_cv = volatile_str == "yes";

  string restrict_str;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "restrict"))
    restrict_str = CHAR_STR(s);
  bool restrict_cv = restrict_str == "yes";

  if (const_cv)
    cv = cv | qualified_type_def::CV_CONST;
  if (volatile_cv)
    cv = cv | qualified_type_def::CV_VOLATILE;
  if (restrict_cv)
    cv = cv | qualified_type_def::CV_RESTRICT;

  string type_id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "type-id"))
    type_id = CHAR_STR(s);
  ABG_ASSERT(!type_id.empty());

  shared_ptr<type_base> underlying_type =
    rdr.build_or_get_type_decl(type_id, true);
  ABG_ASSERT(underlying_type);

  qualified_type_def_sptr decl;
  if (type_base_sptr t = rdr.get_type_decl(id))
    {
      decl = is_qualified_type(t);
      ABG_ASSERT(decl);
    }
  else
    {
      decl.reset(new qualified_type_def(underlying_type, cv, loc));
      maybe_set_artificial_location(rdr, node, decl);
      rdr.push_and_key_type_decl(decl, node, add_to_current_scope);
      RECORD_ARTIFACT_AS_USED_BY(rdr, underlying_type, decl);
    }

  rdr.map_xml_node_to_decl(node, decl);

  return decl;
}

/// Build a pointer_type_def from a 'pointer-type-def' xml node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the pointer_type_def from.
///
/// @param add_to_current_scope if set to yes, the resulting of
/// this function is added to its current scope.
///
/// @return a pointer to a newly built pointer_type_def upon
/// successful completion, a null pointer otherwise.
static pointer_type_def_sptr
build_pointer_type_def(reader&	rdr,
		       const xmlNodePtr node,
		       bool		add_to_current_scope)
{

  shared_ptr<pointer_type_def> nil;

  if (!xmlStrEqual(node->name, BAD_CAST("pointer-type-def")))
    return nil;

  if (decl_base_sptr d = rdr.get_decl_for_xml_node(node))
    {
      pointer_type_def_sptr result =
	dynamic_pointer_cast<pointer_type_def>(d);
      ABG_ASSERT(result);
      return result;
    }

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);
  ABG_ASSERT(!id.empty());

  if (type_base_sptr t = rdr.get_type_decl(id))
    {
      pointer_type_def_sptr result = is_pointer_type(t);
      ABG_ASSERT(result);
      return result;
    }

  string type_id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "type-id"))
    type_id = CHAR_STR(s);

  size_t size_in_bits = rdr.get_translation_unit()->get_address_size();
  size_t alignment_in_bits = 0;
  read_size_and_alignment(node, size_in_bits, alignment_in_bits);
  location loc;
  read_location(rdr, node, loc);

  type_base_sptr pointed_to_type =
    rdr.build_or_get_type_decl(type_id, true);
  ABG_ASSERT(pointed_to_type);

  pointer_type_def_sptr t;
  if (rdr.get_environment().is_void_type(pointed_to_type))
    t = is_pointer_type(build_ir_node_for_void_pointer_type(rdr));
  else
    // Create the pointer type /before/ the pointed-to type.  After the
    // creation, the type is 'keyed' using rdr.push_and_key_type_decl.
    // This means that the type can be retrieved from its type ID.  This
    // is so that if the pointed-to type indirectly uses this pointer
    // type (via recursion) then that is made possible.
    t.reset(new pointer_type_def(pointed_to_type,
				 size_in_bits,
				 alignment_in_bits,
				 loc));

  maybe_set_artificial_location(rdr, node, t);

  if (rdr.push_and_key_type_decl(t, node, add_to_current_scope))
    rdr.map_xml_node_to_decl(node, t);

  RECORD_ARTIFACT_AS_USED_BY(rdr, pointed_to_type, t);
  return t;
}

/// Build a reference_type_def from a pointer to 'reference-type-def'
/// xml node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the reference_type_def from.
///
/// @param add_to_current_scope if set to yes, the resulting of
/// this function is added to its current scope.
///
/// @return a pointer to a newly built reference_type_def upon
/// successful completio, a null pointer otherwise.
static shared_ptr<reference_type_def>
build_reference_type_def(reader&		rdr,
			 const xmlNodePtr	node,
			 bool			add_to_current_scope)
{
  shared_ptr<reference_type_def> nil;

  if (!xmlStrEqual(node->name, BAD_CAST("reference-type-def")))
    return nil;

  if (decl_base_sptr d = rdr.get_decl_for_xml_node(node))
    {
      reference_type_def_sptr result =
	dynamic_pointer_cast<reference_type_def>(d);
      ABG_ASSERT(result);
      return result;
    }

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);
  ABG_ASSERT(!id.empty());

  if (type_base_sptr d = rdr.get_type_decl(id))
    {
      reference_type_def_sptr ty = is_reference_type(d);
      ABG_ASSERT(ty);
      return ty;
    }

  location loc;
  read_location(rdr, node, loc);
  string kind;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "kind"))
    kind = CHAR_STR(s); // this should be either "lvalue" or "rvalue".
  bool is_lvalue = kind == "lvalue";

  size_t size_in_bits = rdr.get_translation_unit()->get_address_size();
  size_t alignment_in_bits = 0;
  read_size_and_alignment(node, size_in_bits, alignment_in_bits);

  string type_id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "type-id"))
    type_id = CHAR_STR(s);
  ABG_ASSERT(!type_id.empty());

  // Create the reference type /before/ the pointed-to type.  After
  // the creation, the type is 'keyed' using
  // rdr.push_and_key_type_decl.  This means that the type can be
  // retrieved from its type ID.  This is so that if the pointed-to
  // type indirectly uses this reference type (via recursion) then
  // that is made possible.
  reference_type_def_sptr t(new reference_type_def(rdr.get_environment(),
						   is_lvalue, size_in_bits,
						   alignment_in_bits, loc));
  maybe_set_artificial_location(rdr, node, t);
  if (rdr.push_and_key_type_decl(t, node, add_to_current_scope))
    rdr.map_xml_node_to_decl(node, t);

  type_base_sptr pointed_to_type =
    rdr.build_or_get_type_decl(type_id,/*add_to_current_scope=*/ true);
  ABG_ASSERT(pointed_to_type);
  t->set_pointed_to_type(pointed_to_type);
  RECORD_ARTIFACT_AS_USED_BY(rdr, pointed_to_type, t);

  return t;
}

/// Build a function_type from a pointer to 'function-type'
/// xml node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the function_type from.
///
/// @param add_to_current_scope if set to yes, the result of
/// this function is added to its current scope.
///
/// @return a pointer to a newly built function_type upon
/// successful completion, a null pointer otherwise.
static function_type_sptr
build_function_type(reader&	rdr,
		    const xmlNodePtr	node,
		    bool /*add_to_current_scope*/)
{
  function_type_sptr nil;

  if (!xmlStrEqual(node->name, BAD_CAST("function-type")))
    return nil;

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);
  ABG_ASSERT(!id.empty());

  string method_class_id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "method-class-id"))
    method_class_id = CHAR_STR(s);

  bool is_method_t = !method_class_id.empty();

  size_t size = rdr.get_translation_unit()->get_address_size(), align = 0;
  read_size_and_alignment(node, size, align);

  const environment& env = rdr.get_environment();
  std::vector<shared_ptr<function_decl::parameter> > parms;
  type_base_sptr return_type = env.get_void_type();

  class_or_union_sptr method_class_type;
  if (is_method_t)
    {
      method_class_type =
	is_class_or_union_type(rdr.build_or_get_type_decl(method_class_id,
							  /*add_decl_to_scope=*/true));
      ABG_ASSERT(method_class_type);
    }

  function_type_sptr fn_type(is_method_t
			     ? new method_type(method_class_type,
					       /*is_const=*/false,
					       size, align)
			     : new function_type(return_type,
						 parms, size, align));

  rdr.get_translation_unit()->bind_function_type_life_time(fn_type);
  rdr.key_type_decl(fn_type, id);
  RECORD_ARTIFACTS_AS_USED_IN_FN_TYPE(rdr, fn_type);

  for (xmlNodePtr n = xmlFirstElementChild(node);
       n;
       n = xmlNextElementSibling(n))
    {
      if (xmlStrEqual(n->name, BAD_CAST("parameter")))
	{
	  if (function_decl::parameter_sptr p =
	      build_function_parameter(rdr, n))
	    parms.push_back(p);
	}
      else if (xmlStrEqual(n->name, BAD_CAST("return")))
	{
	  string type_id;
	  if (xml_char_sptr s =
	      xml::build_sptr(xmlGetProp(n, BAD_CAST("type-id"))))
	    type_id = CHAR_STR(s);
	  if (!type_id.empty())
	    fn_type->set_return_type(rdr.build_or_get_type_decl
				     (type_id, true));
	}
    }

  fn_type->set_parameters(parms);

  return fn_type;
}

/// Build a array_type_def::subrange_type from a 'subrange' xml node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the
/// array_type_def::subrange_type from.
///
///
/// @return a pointer to a newly built array_type_def::subrange_type
/// upon successful completion, a null pointer otherwise.
static array_type_def::subrange_sptr
build_subrange_type(reader&		rdr,
		    const xmlNodePtr	node,
		    bool		add_to_current_scope)
{
  array_type_def::subrange_sptr nil;

  if (!node || !xmlStrEqual(node->name, BAD_CAST("subrange")))
    return nil;

  if (decl_base_sptr d = rdr.get_decl_for_xml_node(node))
    {
      array_type_def::subrange_sptr result =
	dynamic_pointer_cast<array_type_def::subrange_type>(d);
      ABG_ASSERT(result);
      return result;
    }

  string id;
  // Note that in early implementations, the subrange didn't carry its
  // own ID as the subrange was just a detail of an array.  So we
  // still need to support the abixml emitted by those early
  // implementations.
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);

  if (!id.empty())
    if (type_base_sptr d = rdr.get_type_decl(id))
      {
	array_type_def::subrange_sptr ty = is_subrange_type(d);
	ABG_ASSERT(ty);
	return ty;
      }

  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    name = CHAR_STR(s);

  uint64_t length = 0;
  string length_str;
  bool is_infinite = false;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "length"))
    {
      if (string(CHAR_STR(s)) == "infinite" || string(CHAR_STR(s)) == "unknown")
	is_infinite = true;
      else
	length = strtoull(CHAR_STR(s), NULL, 0);
    }

  int64_t lower_bound = 0, upper_bound = 0;
  bool bounds_present = false;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "lower-bound"))
    {
      lower_bound = strtoll(CHAR_STR(s), NULL, 0);
      s = XML_NODE_GET_ATTRIBUTE(node, "upper-bound");
      if (!string(CHAR_STR(s)).empty())
	upper_bound = strtoll(CHAR_STR(s), NULL, 0);
      bounds_present = true;
      ABG_ASSERT(is_infinite
		 || (length == (uint64_t) upper_bound - lower_bound + 1));
    }

  string underlying_type_id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "type-id"))
    underlying_type_id = CHAR_STR(s);

  type_base_sptr underlying_type;
  if (!underlying_type_id.empty())
    {
      underlying_type = rdr.build_or_get_type_decl(underlying_type_id, true);
      ABG_ASSERT(underlying_type);
    }

  location loc;
  read_location(rdr, node, loc);

  // Note that DWARF would actually have a lower_bound of -1 for an
  // array of length 0.
  array_type_def::subrange_type::bound_value max_bound;
  array_type_def::subrange_type::bound_value min_bound;
  if (!is_infinite)
    if (length > 0)
      // By default, if no 'lower-bound/upper-bound' attributes are
      // set, we assume that the lower bound is 0 and the upper bound
      // is length - 1.
      max_bound.set_signed(length - 1);

  if (bounds_present)
    {
      // So lower_bound/upper_bound are set.  Let's set them rather
      // than assume that mind_bound is zero.
      min_bound.set_signed(lower_bound);
      max_bound.set_signed(upper_bound);
    }

  array_type_def::subrange_sptr p
    (new array_type_def::subrange_type(rdr.get_environment(),
				       name, min_bound, max_bound,
				       underlying_type, loc));
  maybe_set_artificial_location(rdr, node, p);
  p->is_infinite(is_infinite);

  if (rdr.push_and_key_type_decl(p, node, add_to_current_scope))
    rdr.map_xml_node_to_decl(node, p);

  return p;
}

/// Build a array_type_def from a 'array-type-def' xml node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the array_type_def from.
///
/// @param add_to_current_scope if set to yes, the resulting of
/// this function is added to its current scope.
///
/// @return a pointer to a newly built array_type_def upon
/// successful completion, a null pointer otherwise.
static array_type_def_sptr
build_array_type_def(reader&	rdr,
		     const		xmlNodePtr node,
		     bool		add_to_current_scope)
{

  array_type_def_sptr nil;

  if (!xmlStrEqual(node->name, BAD_CAST("array-type-def")))
    return nil;

  if (decl_base_sptr d = rdr.get_decl_for_xml_node(node))
    {
      array_type_def_sptr result =
	dynamic_pointer_cast<array_type_def>(d);
      ABG_ASSERT(result);
      return result;
    }

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);
  ABG_ASSERT(!id.empty());

  if (type_base_sptr d = rdr.get_type_decl(id))
    {
      array_type_def_sptr ty = is_array_type(d);
      ABG_ASSERT(ty);
      return ty;
    }

  int dimensions = 0;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "dimensions"))
    dimensions = atoi(CHAR_STR(s));

  string type_id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "type-id"))
    type_id = CHAR_STR(s);

  // maybe building the type of array elements triggered building this
  // one in the mean time ...
  if (decl_base_sptr d = rdr.get_decl_for_xml_node(node))
    {
      array_type_def_sptr result =
	dynamic_pointer_cast<array_type_def>(d);
      ABG_ASSERT(result);
      return result;
    }

  size_t size_in_bits = 0, alignment_in_bits = 0;
  bool has_size_in_bits = false;
  char *endptr;

  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "size-in-bits"))
    {
      size_in_bits = strtoull(CHAR_STR(s), &endptr, 0);
      if (*endptr != '\0')
	{
	  if (!strcmp(CHAR_STR(s), "infinite")
	      ||!strcmp(CHAR_STR(s), "unknown"))
	    size_in_bits = (size_t) -1;
	  else
	    return nil;
	}
      has_size_in_bits = true;
    }

  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "alignment-in-bits"))
    {
      alignment_in_bits = strtoull(CHAR_STR(s), &endptr, 0);
      if (*endptr != '\0')
	return nil;
    }

  location loc;
  read_location(rdr, node, loc);
  array_type_def::subranges_type subranges;

  for (xmlNodePtr n = xmlFirstElementChild(node);
       n;
       n = xmlNextElementSibling(n))
    if (xmlStrEqual(n->name, BAD_CAST("subrange")))
      {
	if (array_type_def::subrange_sptr s =
	    build_subrange_type(rdr, n, /*add_to_current_scope=*/true))
	  {
	    MAYBE_MAP_TYPE_WITH_TYPE_ID(s, n);
	    if (add_to_current_scope)
	      {
		add_decl_to_scope(s, rdr.get_cur_scope());
		rdr.maybe_canonicalize_type(s);
	      }
	    subranges.push_back(s);
	  }
      }

  // The type of array elements.
  type_base_sptr type =
    rdr.build_or_get_type_decl(type_id, true);
  ABG_ASSERT(type);

  array_type_def_sptr ar_type(new array_type_def(type, subranges, loc));
  maybe_set_artificial_location(rdr, node, ar_type);
  if (rdr.push_and_key_type_decl(ar_type, node, add_to_current_scope))
    rdr.map_xml_node_to_decl(node, ar_type);
  RECORD_ARTIFACT_AS_USED_BY(rdr, type, ar_type);

  if (dimensions != ar_type->get_dimension_count()
      || (alignment_in_bits
	  != ar_type->get_element_type()->get_alignment_in_bits()))
    return nil;

  if (has_size_in_bits && size_in_bits != (size_t) -1
      && size_in_bits != ar_type->get_size_in_bits())
    {
      // We have a potential discrepancy between calculated and recorded sizes.
      size_t element_size = ar_type->get_element_type()->get_size_in_bits();
      if (element_size && element_size != (size_t)-1)
	{
	  // Older versions miscalculated multidimensional array sizes.
	  size_t bad_count = 0;
	  for (vector<array_type_def::subrange_sptr>::const_iterator i =
		 subranges.begin();
	       i != subranges.end();
	       ++i)
	    bad_count += (*i)->get_length();
	  if (size_in_bits == bad_count * element_size)
	    {
	      static bool reported = false;
	      if (!reported)
		{
		  std::cerr << "notice: Found incorrectly calculated array "
			    << "sizes in XML - this is benign.\nOlder versions "
			    << "of libabigail miscalculated multidimensional "
			    << "array sizes." << std::endl;
		  reported = true;
		}
	    }
	  else
	    {
	      std::cerr << "error: Found incorrectly calculated array size in "
			<< "XML (id=\"" << id <<  "\")." << std::endl;
	      ABG_ASSERT_NOT_REACHED;
	    }
	}
    }

  return ar_type;
}

/// Build an @ref enum_type_decl from the XML node that represents it,
/// if it was not suppressed by a supression specification present in
/// the current reader.
///
/// @param rdr the reader to take into account.
///
/// @param node the XML node representing the @ref enum_type_decl to
/// build.
///
/// @param add_to_current_scope whether to add the built @ref
/// enum_type_decl to the current scope.
///
/// @return the newly built @ref enum_type_decl iff it was effectively
/// built.
static enum_type_decl_sptr
build_enum_type_decl_if_not_suppressed(reader&	rdr,
				       const xmlNodePtr node,
				       bool		add_to_current_scope)
{
  enum_type_decl_sptr enum_type;
  if (!type_is_suppressed(rdr, node))
    enum_type = build_enum_type_decl(rdr, node, add_to_current_scope);
  return enum_type;
}

/// Build an enum_type_decl from an 'enum-type-decl' xml node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the enum_type_decl from.
///
/// param add_to_current_scope if set to yes, the resulting of this
/// function is added to its current scope.
///
/// @return a pointer to a newly built enum_type_decl upon successful
/// completion, a null pointer otherwise.
static enum_type_decl_sptr
build_enum_type_decl(reader&	rdr,
		     const xmlNodePtr	node,
		     bool		add_to_current_scope)
{
  enum_type_decl_sptr nil;

  if (!xmlStrEqual(node->name, BAD_CAST("enum-decl")))
    return nil;

  if (decl_base_sptr d = rdr.get_decl_for_xml_node(node))
    {
      enum_type_decl_sptr result =
	dynamic_pointer_cast<enum_type_decl>(d);
      ABG_ASSERT(result);
      return result;
    }

  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    name = xml::unescape_xml_string(CHAR_STR(s));

  string linkage_name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "linkage-name"))
    linkage_name = xml::unescape_xml_string(CHAR_STR(s));

  location loc;
  read_location(rdr, node, loc);

  bool is_decl_only = false;
  read_is_declaration_only(node, is_decl_only);

  bool is_anonymous = false;
  read_is_anonymous(node, is_anonymous);

  bool is_artificial = false;
  read_is_artificial(node, is_artificial);

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);

  ABG_ASSERT(!id.empty());

  string base_type_id;
  enum_type_decl::enumerators enums;
  for (xmlNodePtr n = xmlFirstElementChild(node);
       n;
       n = xmlNextElementSibling(n))
    {
      if (xmlStrEqual(n->name, BAD_CAST("underlying-type")))
	{
	  xml_char_sptr a = xml::build_sptr(xmlGetProp(n, BAD_CAST("type-id")));
	  if (a)
	    base_type_id = CHAR_STR(a);
	  continue;
	}
      else if (xmlStrEqual(n->name, BAD_CAST("enumerator")))
	{
	  string name;
	  int64_t value = 0;

	  xml_char_sptr a = xml::build_sptr(xmlGetProp(n, BAD_CAST("name")));
	  if (a)
	    name = xml::unescape_xml_string(CHAR_STR(a));

	  a = xml::build_sptr(xmlGetProp(n, BAD_CAST("value")));
	  if (a)
	    {
	      value = strtoll(CHAR_STR(a), NULL, 0);
	      // when strtoll encounters overflow or underflow, errno
	      // is set to ERANGE and the returned value is either
	      // LLONG_MIN or LLONG_MAX.
	      if ((errno == ERANGE)
		  && (value == LLONG_MIN || value == LLONG_MAX))
		return nil;
	    }

	  enums.push_back(enum_type_decl::enumerator(name, value));
	}
    }

  type_base_sptr underlying_type =
    rdr.build_or_get_type_decl(base_type_id, true);
  ABG_ASSERT(underlying_type);

  enum_type_decl_sptr t(new enum_type_decl(name, loc,
					   underlying_type,
					   enums, linkage_name));
  maybe_set_artificial_location(rdr, node, t);
  t->set_is_anonymous(is_anonymous);
  t->set_is_artificial(is_artificial);
  t->set_is_declaration_only(is_decl_only);
  if (rdr.push_and_key_type_decl(t, node, add_to_current_scope))
    {
      maybe_set_naming_typedef(rdr, node, t);
      rdr.map_xml_node_to_decl(node, t);
      RECORD_ARTIFACT_AS_USED_BY(rdr, underlying_type, t);
      return t;
    }

  return nil;
}

/// Build a typedef_decl from a 'typedef-decl' xml node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the typedef_decl from.
///
/// @return a pointer to a newly built typedef_decl upon successful
/// completion, a null pointer otherwise.
static shared_ptr<typedef_decl>
build_typedef_decl(reader&	rdr,
		   const xmlNodePtr	node,
		   bool		add_to_current_scope)
{
  shared_ptr<typedef_decl> nil;

  if (!xmlStrEqual(node->name, BAD_CAST("typedef-decl")))
    return nil;

  if (decl_base_sptr d = rdr.get_decl_for_xml_node(node))
    {
      typedef_decl_sptr result = is_typedef(d);
      ABG_ASSERT(result);
      return result;
    }

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);
  ABG_ASSERT(!id.empty());

  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    name = xml::unescape_xml_string(CHAR_STR(s));

  location loc;
  read_location(rdr, node, loc);

  string type_id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "type-id"))
    type_id = CHAR_STR(s);
  ABG_ASSERT(!type_id.empty());

  type_base_sptr underlying_type(rdr.build_or_get_type_decl(type_id, true));
  ABG_ASSERT(underlying_type);

  typedef_decl_sptr t(new typedef_decl(name, underlying_type, loc));
  maybe_set_artificial_location(rdr, node, t);
  rdr.push_and_key_type_decl(t, node, add_to_current_scope);
  rdr.map_xml_node_to_decl(node, t);
  RECORD_ARTIFACT_AS_USED_BY(rdr, underlying_type, t);

  return t;
}

/// Build a class from its XML node if it is not suppressed by a
/// suppression specification that is present in the ABIXML reader.
///
/// @param rdr the ABIXML reader to consider.
///
/// @param node the XML node to consider.
///
/// @param add_to_current_scope whether to add the built class to the
/// current context or not.
///
/// @return true iff the class was built.
static class_decl_sptr
build_class_decl_if_not_suppressed(reader&	rdr,
				   const xmlNodePtr	node,
				   bool		add_to_current_scope)
{
  class_decl_sptr class_type;
  if (!type_is_suppressed(rdr, node))
    class_type = build_class_decl(rdr, node, add_to_current_scope);
  return class_type;
}

/// Build a @ref union_decl from its XML node if it is not suppressed
/// by a suppression specification that is present in the read
/// context.
///
/// @param rdr the ABIXML reader to consider.
///
/// @param node the XML node to consider.
///
/// @param add_to_current_scope whether to add the built @ref
/// union_decl to the current context or not.
///
/// @return true iff the @ref union_decl was built.
static union_decl_sptr
build_union_decl_if_not_suppressed(reader&	rdr,
				   const xmlNodePtr	node,
				   bool		add_to_current_scope)
{
  union_decl_sptr union_type;
  if (!type_is_suppressed(rdr, node))
    union_type = build_union_decl(rdr, node, add_to_current_scope);
  return union_type;
}

/// Build a class_decl from a 'class-decl' xml node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the class_decl from.
///
/// @param add_to_current_scope if yes, the resulting class node
/// hasn't triggered voluntarily the adding of the resulting
/// class_decl_sptr to the current scope.
///
/// @return a pointer to class_decl upon successful completion, a null
/// pointer otherwise.
static class_decl_sptr
build_class_decl(reader&		rdr,
		 const xmlNodePtr	node,
		 bool			add_to_current_scope)
{
  class_decl_sptr nil;

  if (!xmlStrEqual(node->name, BAD_CAST("class-decl")))
    return nil;

  if (decl_base_sptr d = rdr.get_decl_for_xml_node(node))
    {
      class_decl_sptr result = dynamic_pointer_cast<class_decl>(d);
      ABG_ASSERT(result);
      return result;
    }

  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    name = xml::unescape_xml_string(CHAR_STR(s));

  size_t size_in_bits = 0, alignment_in_bits = 0;
  read_size_and_alignment(node, size_in_bits, alignment_in_bits);

  decl_base::visibility vis = decl_base::VISIBILITY_NONE;
  read_visibility(node, vis);

  bool is_artificial = false;
  read_is_artificial(node, is_artificial);

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);

  location loc;
  read_location(rdr, node, loc);

  class_decl::member_types mbrs;
  class_decl::data_members data_mbrs;
  class_decl::member_functions mbr_functions;
  class_decl::base_specs  bases;

  class_decl_sptr decl;

  bool is_decl_only = false;
  read_is_declaration_only(node, is_decl_only);

  bool is_struct = false;
  read_is_struct(node, is_struct);

  bool is_anonymous = false;
  read_is_anonymous(node, is_anonymous);

  ABG_ASSERT(!id.empty());

  class_decl_sptr previous_definition, previous_declaration;
  if (!is_anonymous)
    if (type_base_sptr t = rdr.get_type_decl(id))
      {
	previous_definition  = is_class_type(t);
	ABG_ASSERT(previous_definition);
      }

  const vector<type_base_sptr> *types_ptr = 0;
  if (!is_anonymous && !previous_definition)
    types_ptr = rdr.get_all_type_decls(id);
  if (types_ptr)
    {
      // Lets look at the previous declarations and the first previous
      // definition of this type that we've already seen while parsing
      // this corpus.
      for (vector<type_base_sptr>::const_iterator i = types_ptr->begin();
	   i != types_ptr->end();
	   ++i)
	{
	  class_decl_sptr klass = is_class_type(*i);
	  ABG_ASSERT(klass);
	  if (klass->get_is_declaration_only()
	      && !klass->get_definition_of_declaration())
	    previous_declaration = klass;
	  else if (!klass->get_is_declaration_only()
		   && !previous_definition)
	    previous_definition = klass;
	  if (previous_definition && previous_declaration)
	    break;
	}

      if (previous_declaration)
	ABG_ASSERT(previous_declaration->get_name() == name);

      if (previous_definition)
	ABG_ASSERT(previous_definition->get_name() == name);

      if (is_decl_only && previous_declaration)
	return previous_declaration;
    }

  const environment& env = rdr.get_environment();

  if (!is_decl_only && previous_definition)
    // We are in the case where we've read this class definition
    // before, but we might need to update it to add some new stuff to
    // it; we might thus find the new stuff to add in the current
    // (new) incarnation of that definition that we are currently
    // reading.
    decl = previous_definition;
  else
    {
      if (is_decl_only)
	{
	  decl.reset(new class_decl(env, name, is_struct));
	  if (size_in_bits)
	    decl->set_size_in_bits(size_in_bits);
	  if (is_anonymous)
	    decl->set_is_anonymous(is_anonymous);
	  decl->set_location(loc);
	}
      else
	decl.reset(new class_decl(env, name, size_in_bits, alignment_in_bits,
				  is_struct, loc, vis, bases, mbrs,
				  data_mbrs, mbr_functions, is_anonymous));
    }

  maybe_set_artificial_location(rdr, node, decl);
  decl->set_is_artificial(is_artificial);

  string def_id;
  bool is_def_of_decl = false;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "def-of-decl-id"))
    def_id = CHAR_STR(s);

  if (!def_id.empty())
    {
      decl_base_sptr d = is_decl(rdr.get_type_decl(def_id));
      if (d && d->get_is_declaration_only())
	{
	  is_def_of_decl = true;
	  decl->set_earlier_declaration(d);
	  d->set_definition_of_declaration(decl);
	}
    }

  if (!is_decl_only
      && decl
      && !decl->get_is_declaration_only()
      && previous_declaration)
    {
      // decl is the definition of the previous declaration
      // previous_declaration.
      //
      // Let's link them.
      decl->set_earlier_declaration(is_decl(previous_declaration));
      for (vector<type_base_sptr>::const_iterator i = types_ptr->begin();
	   i != types_ptr->end();
	   ++i)
	{
	  class_decl_sptr d = is_class_type(*i);
	  ABG_ASSERT(d);
	  if (d->get_is_declaration_only()
	      && !d->get_definition_of_declaration())
	    {
	      previous_declaration->set_definition_of_declaration(decl);
	      is_def_of_decl = true;
	    }
	}
    }

  if (is_decl_only && previous_definition)
    {
      // decl is a declaration of the previous definition
      // previous_definition.  Let's link them.
      ABG_ASSERT(decl->get_is_declaration_only()
	     && !decl->get_definition_of_declaration());
      decl->set_definition_of_declaration(previous_definition);
    }

  ABG_ASSERT(!is_decl_only || !is_def_of_decl);

  rdr.push_decl_to_scope(decl,
			 add_to_current_scope
			 ? rdr.get_scope_ptr_for_node(node)
			 : nullptr);

  rdr.map_xml_node_to_decl(node, decl);
  rdr.key_type_decl(decl, id);

  // If this class has a naming typedef, get it and refer to it.
  maybe_set_naming_typedef(rdr, node, decl);

  for (xmlNodePtr n = xmlFirstElementChild(node);
       n;
       n = xmlNextElementSibling(n))
    {
      if (xmlStrEqual(n->name, BAD_CAST("base-class")))
	{
	  access_specifier access =
	    is_struct
	    ? public_access
	    : private_access;
	  read_access(n, access);

	  string type_id;
	  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(n, "type-id"))
	    type_id = CHAR_STR(s);
	  shared_ptr<class_decl> b =
	    dynamic_pointer_cast<class_decl>
	    (rdr.build_or_get_type_decl(type_id, true));
	  ABG_ASSERT(b);

	  if (decl->find_base_class(b->get_qualified_name()))
	    // We are in updating mode for this class.  The version of
	    // the class we have already has this base class, so we
	    // are not going to add it again.
	    continue;

	  size_t offset_in_bits = 0;
	  bool offset_present = read_offset_in_bits (n, offset_in_bits);

	  bool is_virtual = false;
	  read_is_virtual (n, is_virtual);

	  shared_ptr<class_decl::base_spec> base (new class_decl::base_spec
						  (b, access,
						   offset_present
						   ? (long) offset_in_bits
						   : -1,
						   is_virtual));
	  decl->add_base_specifier(base);
	}
      else if (xmlStrEqual(n->name, BAD_CAST("member-type")))
	{
	  access_specifier access =
	    is_struct
	    ? public_access
	    : private_access;
	  read_access(n, access);

	  rdr.map_xml_node_to_decl(n, decl);

	  for (xmlNodePtr p = xmlFirstElementChild(n);
	       p;
	       p = xmlNextElementSibling(p))
	    {
	      if (type_base_sptr t =
		  build_type(rdr, p, /*add_to_current_scope=*/true))
		{
		  decl_base_sptr td = get_type_declaration(t);
		  ABG_ASSERT(td);
		  set_member_access_specifier(td, access);
		  rdr.maybe_canonicalize_type(t, !add_to_current_scope);
		  xml_char_sptr i= XML_NODE_GET_ATTRIBUTE(p, "id");
		  string id = CHAR_STR(i);
		  ABG_ASSERT(!id.empty());
		  rdr.key_type_decl(t, id);
		  rdr.map_xml_node_to_decl(p, td);
		}
	    }
	}
      else if (xmlStrEqual(n->name, BAD_CAST("data-member")))
	{
	  rdr.map_xml_node_to_decl(n, decl);

	  access_specifier access =
	    is_struct
	    ? public_access
	    : private_access;
	  read_access(n, access);

	  bool is_laid_out = false;
	  size_t offset_in_bits = 0;
	  if (read_offset_in_bits(n, offset_in_bits))
	    is_laid_out = true;

	  bool is_static = false;
	  read_static(n, is_static);

	  for (xmlNodePtr p = xmlFirstElementChild(n);
	       p;
	       p = xmlNextElementSibling(p))
	    {
	      if (var_decl_sptr v =
		  build_var_decl(rdr, p, /*add_to_cur_scope=*/false))
		{
		  if (decl->find_data_member(v))
		    {
		      // We are in updating mode and the current
		      // version of this class already has this data
		      // member, so we are not going to add it again.
		      // So we need to discard the data member we have
		      // built (and that was pushed to the current
		      // stack of decls built) and move on.
		      decl_base_sptr d = rdr.pop_decl();
		      ABG_ASSERT(is_var_decl(d));
		      continue;
		    }

		  if (!variable_is_suppressed(rdr, decl.get(), *v))
		    {
		      decl->add_data_member(v, access,
					    is_laid_out,
					    is_static,
					    offset_in_bits);
		      if (is_static)
			rdr.maybe_add_var_to_exported_decls(v.get());
		      // Now let's record the fact that the data
		      // member uses its type and that the class being
		      // built uses the data member.
		      if (is_anonymous_data_member(v))
			// This data member is anonymous so recording
			// that it uses its type is useless because we
			// can't name it.  Rather, let's record that
			// the class being built uses the type of the
			// (anonymous) data member.
			RECORD_ARTIFACT_AS_USED_BY(rdr, v->get_type(), decl);
		      else
			{
			  RECORD_ARTIFACT_AS_USED_BY(rdr, v->get_type(), v);
			  RECORD_ARTIFACT_AS_USED_BY(rdr, v, decl);
			}
		    }
		}
	    }
	}
      else if (xmlStrEqual(n->name, BAD_CAST("member-function")))
	{
	  access_specifier access =
	    is_struct
	    ? public_access
	    : private_access;
	  read_access(n, access);

	  bool is_virtual = false;
	  ssize_t vtable_offset = -1;
	  if (xml_char_sptr s =
	      XML_NODE_GET_ATTRIBUTE(n, "vtable-offset"))
	    {
	      is_virtual = true;
	      vtable_offset = atoi(CHAR_STR(s));
	    }

	  bool is_static = false;
	  read_static(n, is_static);

	  bool is_ctor = false, is_dtor = false, is_const = false;
	  read_cdtor_const(n, is_ctor, is_dtor, is_const);

	  for (xmlNodePtr p = xmlFirstElementChild(n);
	       p;
	       p = xmlNextElementSibling(p))
	    {
	      if (function_decl_sptr f =
		  build_function_decl_if_not_suppressed(rdr, p, decl,
							/*add_to_cur_sc=*/true,
							/*add_to_exported_decls=*/false))
		{
		  method_decl_sptr m = is_method_decl(f);
		  ABG_ASSERT(m);
		  set_member_access_specifier(m, access);
		  set_member_is_static(m, is_static);
		  if (vtable_offset != -1)
		    set_member_function_vtable_offset(m, vtable_offset);
		  set_member_function_is_virtual(m, is_virtual);
		  set_member_function_is_ctor(m, is_ctor);
		  set_member_function_is_dtor(m, is_dtor);
		  set_member_function_is_const(m, is_const);
		  rdr.map_xml_node_to_decl(p, m);
		  rdr.maybe_add_fn_to_exported_decls(f.get());
		  break;
		}
	    }
	}
      else if (xmlStrEqual(n->name, BAD_CAST("member-template")))
	{
	  rdr.map_xml_node_to_decl(n, decl);

	  access_specifier access =
	    is_struct
	    ? public_access
	    : private_access;
	  read_access(n, access);

	  bool is_static = false;
	  read_static(n, is_static);

	  bool is_ctor = false, is_dtor = false, is_const = false;
	  read_cdtor_const(n, is_ctor, is_dtor, is_const);

	  for (xmlNodePtr p = xmlFirstElementChild(n);
	       p;
	       p = xmlNextElementSibling(p))
	    {
	      if (shared_ptr<function_tdecl> f =
		  build_function_tdecl(rdr, p,
				       /*add_to_current_scope=*/true))
		{
		  shared_ptr<member_function_template> m
		    (new member_function_template(f, access, is_static,
						  is_ctor, is_const));
		  ABG_ASSERT(f->get_scope());
		  decl->add_member_function_template(m);
		}
	      else if (shared_ptr<class_tdecl> c =
		       build_class_tdecl(rdr, p,
					 /*add_to_current_scope=*/true))
		{
		  member_class_template_sptr m(new member_class_template(c,
									 access,
									 is_static));
		  ABG_ASSERT(c->get_scope());
		  decl->add_member_class_template(m);
		}
	    }
	}
    }

  rdr.pop_scope_or_abort(decl);

  return decl;
}

/// Build a union_decl from a 'union-decl' xml node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the union_decl from.
///
/// @param add_to_current_scope if yes, the resulting union node
/// hasn't triggered voluntarily the adding of the resulting
/// union_decl_sptr to the current scope.
///
/// @return a pointer to union_decl upon successful completion, a null
/// pointer otherwise.
static union_decl_sptr
build_union_decl(reader& rdr,
		 const xmlNodePtr node,
		 bool add_to_current_scope)
{
  union_decl_sptr nil;

  if (!xmlStrEqual(node->name, BAD_CAST("union-decl")))
    return nil;

  if (decl_base_sptr d = rdr.get_decl_for_xml_node(node))
    {
      union_decl_sptr result = dynamic_pointer_cast<union_decl>(d);
      ABG_ASSERT(result);
      return result;
    }

  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    name = xml::unescape_xml_string(CHAR_STR(s));

  size_t size_in_bits = 0, alignment_in_bits = 0;
  read_size_and_alignment(node, size_in_bits, alignment_in_bits);

  decl_base::visibility vis = decl_base::VISIBILITY_NONE;
  read_visibility(node, vis);

  bool is_artificial = false;
  read_is_artificial(node, is_artificial);

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);

  location loc;
  read_location(rdr, node, loc);

  union_decl::member_types mbrs;
  union_decl::data_members data_mbrs;
  union_decl::member_functions mbr_functions;

  union_decl_sptr decl;

  bool is_decl_only = false;
  read_is_declaration_only(node, is_decl_only);

  bool is_anonymous = false;
  read_is_anonymous(node, is_anonymous);

  ABG_ASSERT(!id.empty());
  union_decl_sptr previous_definition, previous_declaration;
  const vector<type_base_sptr> *types_ptr = 0;
  if (!is_anonymous)
    types_ptr = rdr.get_all_type_decls(id);
  if (types_ptr)
    {
      // Lets look at the previous declarations and the first previous
      // definition of this type that we've already seen while parsing
      // this corpus.
      for (vector<type_base_sptr>::const_iterator i = types_ptr->begin();
	   i != types_ptr->end();
	   ++i)
	{
	  union_decl_sptr onion = is_union_type(*i);
	  ABG_ASSERT(onion);
	  if (onion->get_is_declaration_only()
	      && !onion->get_definition_of_declaration())
	    previous_declaration = onion;
	  else if (!onion->get_is_declaration_only()
		   && !previous_definition)
	    previous_definition = onion;
	  if (previous_definition && previous_declaration)
	    break;
	}

      if (previous_declaration)
	ABG_ASSERT(previous_declaration->get_name() == name);

      if (previous_definition)
	ABG_ASSERT(previous_definition->get_name() == name);

      if (is_decl_only && previous_declaration)
	return previous_declaration;
    }

  const environment& env = rdr.get_environment();

  if (!is_decl_only && previous_definition)
    // We are in the case where we've read this class definition
    // before, but we might need to update it to add some new stuff to
    // it; we might thus find the new stuff to add in the current
    // (new) incarnation of that definition that we are currently
    // reading.
    decl = previous_definition;
  else
    {
      if (is_decl_only)
	decl.reset(new union_decl(env, name));
      else
	decl.reset(new union_decl(env, name,
				  size_in_bits,
				  loc, vis, mbrs,
				  data_mbrs,
				  mbr_functions,
				  is_anonymous));
    }

  maybe_set_artificial_location(rdr, node, decl);
  decl->set_is_artificial(is_artificial);

  string def_id;
  bool is_def_of_decl = false;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "def-of-decl-id"))
    def_id = CHAR_STR(s);

  if (!def_id.empty())
    {
      class_decl_sptr d =
	dynamic_pointer_cast<class_decl>(rdr.get_type_decl(def_id));
      if (d && d->get_is_declaration_only())
	{
	  is_def_of_decl = true;
	  decl->set_earlier_declaration(d);
	  d->set_definition_of_declaration(decl);
	}
    }

  if (!is_decl_only
      && decl
      && !decl->get_is_declaration_only()
      && previous_declaration)
    {
      // decl is the definition of the previous declaration
      // previous_declaration.
      //
      // Let's link them.
      decl->set_earlier_declaration(previous_declaration);
      for (vector<type_base_sptr>::const_iterator i = types_ptr->begin();
	   i != types_ptr->end();
	   ++i)
	{
	  union_decl_sptr d = is_union_type(*i);
	  ABG_ASSERT(d);
	  if (d->get_is_declaration_only()
	      && !d->get_definition_of_declaration())
	    {
	      previous_declaration->set_definition_of_declaration(decl);
	      is_def_of_decl = true;
	    }
	}
    }

  if (is_decl_only && previous_definition)
    {
      // decl is a declaration of the previous definition
      // previous_definition.  Let's link them.
      ABG_ASSERT(decl->get_is_declaration_only()
	     && !decl->get_definition_of_declaration());
      decl->set_definition_of_declaration(previous_definition);
    }

  ABG_ASSERT(!is_decl_only || !is_def_of_decl);

  rdr.push_decl_to_scope(decl,
			 add_to_current_scope
			 ? rdr.get_scope_ptr_for_node(node)
			 : nullptr);

  rdr.map_xml_node_to_decl(node, decl);
  rdr.key_type_decl(decl, id);

  maybe_set_naming_typedef(rdr, node, decl);

  for (xmlNodePtr n = xmlFirstElementChild(node);
       !is_decl_only && n;
       n = xmlNextElementSibling(n))
    {
      if (xmlStrEqual(n->name, BAD_CAST("member-type")))
	{
	  access_specifier access = private_access;
	  read_access(n, access);

	  rdr.map_xml_node_to_decl(n, decl);

	  for (xmlNodePtr p = xmlFirstElementChild(n);
	       p;
	       p = xmlNextElementSibling(p))
	    {
	      if (type_base_sptr t =
		  build_type(rdr, p, /*add_to_current_scope=*/true))
		{
		  decl_base_sptr td = get_type_declaration(t);
		  ABG_ASSERT(td);
		  set_member_access_specifier(td, access);
		  rdr.maybe_canonicalize_type(t, !add_to_current_scope);
		  xml_char_sptr i= XML_NODE_GET_ATTRIBUTE(p, "id");
		  string id = CHAR_STR(i);
		  ABG_ASSERT(!id.empty());
		  rdr.key_type_decl(t, id);
		  rdr.map_xml_node_to_decl(p, td);
		}
	    }
	}
      else if (xmlStrEqual(n->name, BAD_CAST("data-member")))
	{
	  rdr.map_xml_node_to_decl(n, decl);

	  access_specifier access = private_access;
	  read_access(n, access);

	  bool is_laid_out = true;
	  size_t offset_in_bits = 0;
	  bool is_static = false;
	  read_static(n, is_static);

	  for (xmlNodePtr p = xmlFirstElementChild(n);
	       p;
	       p = xmlNextElementSibling(p))
	    {
	      if (var_decl_sptr v =
		  build_var_decl(rdr, p, /*add_to_cur_scope=*/false))
		{
		  if (decl->find_data_member(v))
		    {
		      // We are in updating mode and the current
		      // version of this class already has this data
		      // member, so we are not going to add it again.
		      // So we need to discard the data member we have
		      // built (and that was pushed to the current
		      // stack of decls built) and move on.
		      decl_base_sptr d = rdr.pop_decl();
		      ABG_ASSERT(is_var_decl(d));
		      continue;
		    }
		  if (!is_static
		      || !variable_is_suppressed(rdr, decl.get(), *v))
		    {
		      decl->add_data_member(v, access,
					    is_laid_out,
					    is_static,
					    offset_in_bits);
		      // Now let's record the fact that the data
		      // member uses its type and that the union being
		      // built uses the data member.
		      if (is_anonymous_data_member(v))
			// This data member is anonymous so recording
			// that it uses its type is useless because we
			// can't name it.  Rather, let's record that
			// the class being built uses the type of the
			// (anonymous) data member.
			RECORD_ARTIFACT_AS_USED_BY(rdr, v->get_type(), decl);
		      else
			{
			  RECORD_ARTIFACT_AS_USED_BY(rdr, v->get_type(), v);
			  RECORD_ARTIFACT_AS_USED_BY(rdr, v, decl);
			}
		    }
		}
	    }
	}
      else if (xmlStrEqual(n->name, BAD_CAST("member-function")))
	{
	  rdr.map_xml_node_to_decl(n, decl);

	  access_specifier access = private_access;
	  read_access(n, access);

	  bool is_static = false;
	  read_static(n, is_static);

	  bool is_ctor = false, is_dtor = false, is_const = false;
	  read_cdtor_const(n, is_ctor, is_dtor, is_const);

	  for (xmlNodePtr p = xmlFirstElementChild(n);
	       p;
	       p = xmlNextElementSibling(p))
	    {
	      if (function_decl_sptr f =
		  build_function_decl_if_not_suppressed(rdr, p, decl,
							/*add_to_cur_sc=*/true,
							/*add_to_exported_decls=*/false))
		{
		  method_decl_sptr m = is_method_decl(f);
		  ABG_ASSERT(m);
		  set_member_access_specifier(m, access);
		  set_member_is_static(m, is_static);
		  set_member_function_is_ctor(m, is_ctor);
		  set_member_function_is_dtor(m, is_dtor);
		  set_member_function_is_const(m, is_const);
		  rdr.maybe_add_fn_to_exported_decls(f.get());
		  break;
		}
	    }
	}
      else if (xmlStrEqual(n->name, BAD_CAST("member-template")))
	{
	  rdr.map_xml_node_to_decl(n, decl);

	  access_specifier access = private_access;
	  read_access(n, access);

	  bool is_static = false;
	  read_static(n, is_static);

	  bool is_ctor = false, is_dtor = false, is_const = false;
	  read_cdtor_const(n, is_ctor, is_dtor, is_const);

	  for (xmlNodePtr p = xmlFirstElementChild(n);
	       p;
	       p = xmlNextElementSibling(p))
	    {
	      if (function_tdecl_sptr f =
		  build_function_tdecl(rdr, p,
				       /*add_to_current_scope=*/true))
		{
		  member_function_template_sptr m
		    (new member_function_template(f, access, is_static,
						  is_ctor, is_const));
		  ABG_ASSERT(f->get_scope());
		  decl->add_member_function_template(m);
		}
	      else if (class_tdecl_sptr c =
		       build_class_tdecl(rdr, p,
					 /*add_to_current_scope=*/true))
		{
		  member_class_template_sptr m(new member_class_template(c,
									 access,
									 is_static));
		  ABG_ASSERT(c->get_scope());
		  decl->add_member_class_template(m);
		}
	    }
	}
    }

  rdr.pop_scope_or_abort(decl);

  return decl;
}

/// Build an intance of function_tdecl, from an
/// 'function-template-decl' xml element node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to parse from.
///
/// @param add_to_current_scope if set to yes, the resulting of
/// this function is added to its current scope.
///
/// @return the newly built function_tdecl upon successful
/// completion, a null pointer otherwise.
static shared_ptr<function_tdecl>
build_function_tdecl(reader& rdr,
		     const xmlNodePtr node,
		     bool add_to_current_scope)
{
  shared_ptr<function_tdecl> nil, result;

  if (!xmlStrEqual(node->name, BAD_CAST("function-template-decl")))
    return nil;

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);
  if (id.empty() || rdr.get_fn_tmpl_decl(id))
    return nil;

  location loc;
  read_location(rdr, node, loc);

  decl_base::visibility vis = decl_base::VISIBILITY_NONE;
  read_visibility(node, vis);

  decl_base::binding bind = decl_base::BINDING_NONE;
  read_binding(node, bind);

  const environment& env = rdr.get_environment();

  function_tdecl_sptr fn_tmpl_decl(new function_tdecl(env, loc, vis, bind));
  maybe_set_artificial_location(rdr, node, fn_tmpl_decl);

  rdr.push_decl_to_scope(fn_tmpl_decl,
			 add_to_current_scope
			 ? rdr.get_scope_ptr_for_node(node)
			 : nullptr);
  rdr.key_fn_tmpl_decl(fn_tmpl_decl, id);
  rdr.map_xml_node_to_decl(node, fn_tmpl_decl);

  unsigned parm_index = 0;
  for (xmlNodePtr n = xmlFirstElementChild(node);
       n;
       n = xmlNextElementSibling(n))
    {
      if (template_parameter_sptr parm =
	  build_template_parameter(rdr, n, parm_index, fn_tmpl_decl))
	{
	  fn_tmpl_decl->add_template_parameter(parm);
	  ++parm_index;
	}
      else if (function_decl_sptr f =
	       build_function_decl_if_not_suppressed(rdr, n, class_decl_sptr(),
						     /*add_to_current_scope=*/true,
						     /*add_to_exported_decls=*/true))
	fn_tmpl_decl->set_pattern(f);
    }

  rdr.key_fn_tmpl_decl(fn_tmpl_decl, id);

  return fn_tmpl_decl;
}

/// Build an intance of class_tdecl, from a
/// 'class-template-decl' xml element node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to parse from.
///
/// @param add_to_current_scope if set to yes, the resulting of this
/// function is added to its current scope.
///
/// @return the newly built function_tdecl upon successful
/// completion, a null pointer otherwise.
static class_tdecl_sptr
build_class_tdecl(reader&		rdr,
		  const xmlNodePtr	node,
		  bool			add_to_current_scope)
{
  class_tdecl_sptr nil, result;

  if (!xmlStrEqual(node->name, BAD_CAST("class-template-decl")))
    return nil;

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);
  if (id.empty() || rdr.get_class_tmpl_decl(id))
    return nil;

  location loc;
  read_location(rdr, node, loc);

  decl_base::visibility vis = decl_base::VISIBILITY_NONE;
  read_visibility(node, vis);

  const environment& env = rdr.get_environment();

  class_tdecl_sptr class_tmpl (new class_tdecl(env, loc, vis));
  maybe_set_artificial_location(rdr, node, class_tmpl);

  if (add_to_current_scope)
    rdr.push_decl_to_scope(class_tmpl, node);
  rdr.key_class_tmpl_decl(class_tmpl, id);
  rdr.map_xml_node_to_decl(node, class_tmpl);

  unsigned parm_index = 0;
  for (xmlNodePtr n = xmlFirstElementChild(node);
       n;
       n = xmlNextElementSibling(n))
    {
      if (template_parameter_sptr parm=
	  build_template_parameter(rdr, n, parm_index, class_tmpl))
	{
	  class_tmpl->add_template_parameter(parm);
	  ++parm_index;
	}
      else if (class_decl_sptr c =
	       build_class_decl_if_not_suppressed(rdr, n,
						  add_to_current_scope))
	{
	  if (c->get_scope())
	    rdr.maybe_canonicalize_type(c, /*force_delay=*/false);
	  class_tmpl->set_pattern(c);
	}
    }

  rdr.key_class_tmpl_decl(class_tmpl, id);

  return class_tmpl;
}

/// Build a type_tparameter from a 'template-type-parameter'
/// xml element node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to parse from.
///
/// @param index the index (occurrence index, starting from 0) of the
/// template parameter.
///
/// @param tdecl the enclosing template declaration that holds the
/// template type parameter.
///
/// @return a pointer to a newly created instance of
/// type_tparameter, a null pointer otherwise.
static type_tparameter_sptr
build_type_tparameter(reader&		rdr,
		      const xmlNodePtr		node,
		      unsigned			index,
		      template_decl_sptr	tdecl)
{
  type_tparameter_sptr nil, result;

  if (!xmlStrEqual(node->name, BAD_CAST("template-type-parameter")))
    return nil;

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);
  if (!id.empty())
    ABG_ASSERT(!rdr.get_type_decl(id));

  string type_id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "type-id"))
    type_id = CHAR_STR(s);
  if (!type_id.empty()
      && !(result = dynamic_pointer_cast<type_tparameter>
	   (rdr.build_or_get_type_decl(type_id, true))))
    abort();

  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    name = xml::unescape_xml_string(CHAR_STR(s));

  location loc;
  read_location(rdr, node,loc);

  result.reset(new type_tparameter(index, tdecl, name, loc));
  maybe_set_artificial_location(rdr, node, result);

  if (id.empty())
    rdr.push_decl_to_scope(is_decl(result), node);
  else
    rdr.push_and_key_type_decl(result, node, /*add_to_current_scope=*/true);

  rdr.maybe_canonicalize_type(result, /*force_delay=*/false);

  return result;
}

/// Build a tmpl_parm_type_composition from a
/// "template-parameter-type-composition" xml element node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to parse from.
///
/// @param index the index of the previous normal template parameter.
///
/// @param tdecl the enclosing template declaration that holds this
/// template parameter type composition.
///
/// @return a pointer to a new instance of tmpl_parm_type_composition
/// upon successful completion, a null pointer otherwise.
static type_composition_sptr
build_type_composition(reader&		rdr,
		       const xmlNodePtr	node,
		       unsigned		index,
		       template_decl_sptr	tdecl)
{
  type_composition_sptr nil, result;

  if (!xmlStrEqual(node->name, BAD_CAST("template-parameter-type-composition")))
    return nil;

  type_base_sptr composed_type;
  result.reset(new type_composition(index, tdecl, composed_type));
  rdr.push_decl_to_scope(is_decl(result), node);

  for (xmlNodePtr n = xmlFirstElementChild(node);
       n;
       n = xmlNextElementSibling(n))
    {
      if ((composed_type =
	   build_pointer_type_def(rdr, n,
				  /*add_to_current_scope=*/true))
	  ||(composed_type =
	     build_reference_type_def(rdr, n,
				      /*add_to_current_scope=*/true))
	  ||(composed_type =
	     build_array_type_def(rdr, n,
				  /*add_to_current_scope=*/true))
	  || (composed_type =
	      build_qualified_type_decl(rdr, n,
					/*add_to_current_scope=*/true)))
	{
	  rdr.maybe_canonicalize_type(composed_type,
				       /*force_delay=*/true);
	  result->set_composed_type(composed_type);
	  break;
	}
    }

  return result;
}

/// Build an instance of non_type_tparameter from a
/// 'template-non-type-parameter' xml element node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to parse from.
///
/// @param index the index of the parameter.
///
/// @param tdecl the enclosing template declaration that holds this
/// non type template parameter.
///
/// @return a pointer to a newly created instance of
/// non_type_tparameter upon successful completion, a null
/// pointer code otherwise.
static non_type_tparameter_sptr
build_non_type_tparameter(reader&	rdr,
			  const xmlNodePtr	node,
			  unsigned		index,
			  template_decl_sptr	tdecl)
{
  non_type_tparameter_sptr r;

  if (!xmlStrEqual(node->name, BAD_CAST("template-non-type-parameter")))
    return r;

  string type_id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "type-id"))
    type_id = CHAR_STR(s);
  type_base_sptr type;
  if (type_id.empty()
      || !(type = rdr.build_or_get_type_decl(type_id, true)))
    abort();

  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    name = xml::unescape_xml_string(CHAR_STR(s));

  location loc;
  read_location(rdr, node,loc);

  r.reset(new non_type_tparameter(index, tdecl, name, type, loc));
  maybe_set_artificial_location(rdr, node, r);
  rdr.push_decl_to_scope(is_decl(r), node);

  return r;
}

/// Build an intance of template_tparameter from a
/// 'template-template-parameter' xml element node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to parse from.
///
/// @param index the index of the template parameter.
///
/// @param tdecl the enclosing template declaration that holds this
/// template template parameter.
///
/// @return a pointer to a new instance of template_tparameter
/// upon successful completion, a null pointer otherwise.
static template_tparameter_sptr
build_template_tparameter(reader&	rdr,
			  const xmlNodePtr	node,
			  unsigned		index,
			  template_decl_sptr	tdecl)
{
  template_tparameter_sptr nil;

  if (!xmlStrEqual(node->name, BAD_CAST("template-template-parameter")))
    return nil;

  string id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "id"))
    id = CHAR_STR(s);
  // Bail out if a type with the same ID already exists.
  ABG_ASSERT(!id.empty());

  string type_id;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "type-id"))
    type_id = CHAR_STR(s);
  // Bail out if no type with this ID exists.
  if (!type_id.empty()
      && !(dynamic_pointer_cast<template_tparameter>
	   (rdr.build_or_get_type_decl(type_id, true))))
    abort();

  string name;
  if (xml_char_sptr s = XML_NODE_GET_ATTRIBUTE(node, "name"))
    name = xml::unescape_xml_string(CHAR_STR(s));

  location loc;
  read_location(rdr, node, loc);

  template_tparameter_sptr result(new template_tparameter(index, tdecl,
							  name, loc));
  maybe_set_artificial_location(rdr, node, result);
  rdr.push_decl_to_scope(result, node);

  // Go parse template parameters that are children nodes
  int parm_index = 0;
  for (xmlNodePtr n = xmlFirstElementChild(node);
       n;
       n = xmlNextElementSibling(n))
    if (shared_ptr<template_parameter> p =
	build_template_parameter(rdr, n, parm_index, result))
      {
	result->add_template_parameter(p);
	++parm_index;
      }

  if (result)
    {
      rdr.key_type_decl(result, id);
      rdr.maybe_canonicalize_type(result, /*force_delay=*/false);
    }

  return result;
}

/// Build a template parameter type from several possible xml elment
/// nodes representing a serialized form a template parameter.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml element node to parse from.
///
/// @param index the index of the template parameter we are parsing.
///
/// @param tdecl the enclosing template declaration that holds this
/// template parameter.
///
/// @return a pointer to a newly created instance of
/// template_parameter upon successful completion, a null pointer
/// otherwise.
static template_parameter_sptr
build_template_parameter(reader&		rdr,
			 const xmlNodePtr	node,
			 unsigned		index,
			 template_decl_sptr	tdecl)
{
  shared_ptr<template_parameter> r;
  ((r = build_type_tparameter(rdr, node, index, tdecl))
   || (r = build_non_type_tparameter(rdr, node, index, tdecl))
   || (r = build_template_tparameter(rdr, node, index, tdecl))
   || (r = build_type_composition(rdr, node, index, tdecl)));

  return r;
}

/// Build a type from an xml node.
///
/// @param rdr the context of the parsing.
///
/// @param node the xml node to build the type_base from.
///
/// @return a pointer to the newly built type_base upon successful
/// completion, a null pointer otherwise.
static type_base_sptr
build_type(reader&	rdr,
	   const xmlNodePtr	node,
	   bool		add_to_current_scope)
{
  type_base_sptr t;

  ((t = build_type_decl(rdr, node, add_to_current_scope))
   || (t = build_qualified_type_decl(rdr, node, add_to_current_scope))
   || (t = build_pointer_type_def(rdr, node, add_to_current_scope))
   || (t = build_reference_type_def(rdr, node , add_to_current_scope))
   || (t = build_function_type(rdr, node, add_to_current_scope))
   || (t = build_array_type_def(rdr, node, add_to_current_scope))
   || (t = build_subrange_type(rdr, node, add_to_current_scope))
   || (t = build_enum_type_decl_if_not_suppressed(rdr, node,
						  add_to_current_scope))
   || (t = build_typedef_decl(rdr, node, add_to_current_scope))
   || (t = build_class_decl_if_not_suppressed(rdr, node,
					      add_to_current_scope))
   || (t = build_union_decl_if_not_suppressed(rdr, node,
					      add_to_current_scope)));

  if (rdr.tracking_non_reachable_types() && t)
    {
      corpus_sptr abi = rdr.corpus();
      ABG_ASSERT(abi);
      bool is_non_reachable_type = false;
      read_is_non_reachable_type(node, is_non_reachable_type);
      if (!is_non_reachable_type)
	abi->record_type_as_reachable_from_public_interfaces(*t);
    }

  MAYBE_MAP_TYPE_WITH_TYPE_ID(t, node);

  if (t)
    rdr.maybe_canonicalize_type(t,/*force_delay=*/false );
  return t;
}

/// Parses 'type-decl' xml element.
///
/// @param rdr the parsing context.
///
/// @return true upon successful parsing, false otherwise.
static decl_base_sptr
handle_type_decl(reader&	rdr,
		 xmlNodePtr	node,
		 bool		add_to_current_scope)
{
  type_decl_sptr decl = build_type_decl(rdr, node, add_to_current_scope);
  MAYBE_MAP_TYPE_WITH_TYPE_ID(decl, node);
  if (decl && decl->get_scope())
    rdr.maybe_canonicalize_type(decl, /*force_delay=*/false);
  return decl;
}

/// Parses 'namespace-decl' xml element.
///
/// @param rdr the parsing context.
///
/// @return true upon successful parsing, false otherwise.
static decl_base_sptr
handle_namespace_decl(reader&	rdr,
		      xmlNodePtr	node,
		      bool		add_to_current_scope)
{
  namespace_decl_sptr d = build_namespace_decl(rdr, node,
					       add_to_current_scope);
  return d;
}

/// Parse a qualified-type-def xml element.
///
/// @param rdr the parsing context.
///
/// @return true upon successful parsing, false otherwise.
static decl_base_sptr
handle_qualified_type_decl(reader&	rdr,
			   xmlNodePtr		node,
			   bool		add_to_current_scope)
{
  qualified_type_def_sptr decl =
    build_qualified_type_decl(rdr, node,
			      add_to_current_scope);
  MAYBE_MAP_TYPE_WITH_TYPE_ID(decl, node);
  if (decl && decl->get_scope())
    rdr.maybe_canonicalize_type(decl, /*force_delay=*/false);
  return decl;
}

/// Parse a pointer-type-decl element.
///
/// @param rdr the context of the parsing.
///
/// @return true upon successful completion, false otherwise.
static decl_base_sptr
handle_pointer_type_def(reader&	rdr,
			xmlNodePtr	node,
			bool		add_to_current_scope)
{
  pointer_type_def_sptr decl = build_pointer_type_def(rdr, node,
						      add_to_current_scope);
  MAYBE_MAP_TYPE_WITH_TYPE_ID(decl, node);
  if (decl && decl->get_scope())
    rdr.maybe_canonicalize_type(decl, /*force_delay=*/false);
  return decl;
}

/// Parse a reference-type-def element.
///
/// @param rdr the context of the parsing.
///
/// reference_type_def is added to.
static decl_base_sptr
handle_reference_type_def(reader& rdr,
			  xmlNodePtr	node,
			  bool		add_to_current_scope)
{
  reference_type_def_sptr decl = build_reference_type_def(rdr, node,
							  add_to_current_scope);
  MAYBE_MAP_TYPE_WITH_TYPE_ID(decl, node);
  if (decl && decl->get_scope())
    rdr.maybe_canonicalize_type(decl, /*force_delay=*/false);
  return decl;
}

/// Parse a function-type element.
///
/// @param rdr the context of the parsing.
///
/// function_type is added to.
static type_base_sptr
handle_function_type(reader&	rdr,
		     xmlNodePtr	node,
		     bool		add_to_current_scope)
{
  function_type_sptr type = build_function_type(rdr, node,
						  add_to_current_scope);
  MAYBE_MAP_TYPE_WITH_TYPE_ID(type, node);
  rdr.maybe_canonicalize_type(type, /*force_delay=*/true);
  return type;
}

/// Parse a array-type-def element.
///
/// @param rdr the context of the parsing.
///
/// array_type_def is added to.
static decl_base_sptr
handle_array_type_def(reader&	rdr,
		      xmlNodePtr	node,
		      bool		add_to_current_scope)
{
  array_type_def_sptr decl = build_array_type_def(rdr, node,
						  add_to_current_scope);
  MAYBE_MAP_TYPE_WITH_TYPE_ID(decl, node);
  rdr.maybe_canonicalize_type(decl, /*force_delay=*/false);
  return decl;
}

/// Parse an enum-decl element.
///
/// @param rdr the context of the parsing.
static decl_base_sptr
handle_enum_type_decl(reader&	rdr,
		      xmlNodePtr	node,
		      bool		add_to_current_scope)
{
  enum_type_decl_sptr decl =
    build_enum_type_decl_if_not_suppressed(rdr, node,
					   add_to_current_scope);
  MAYBE_MAP_TYPE_WITH_TYPE_ID(decl, node);
  if (decl && decl->get_scope())
    rdr.maybe_canonicalize_type(decl, /*force_delay=*/false);
  return decl;
}

/// Parse a typedef-decl element.
///
/// @param rdr the context of the parsing.
static decl_base_sptr
handle_typedef_decl(reader&	rdr,
		    xmlNodePtr		node,
		    bool		add_to_current_scope)
{
  typedef_decl_sptr decl = build_typedef_decl(rdr, node,
					      add_to_current_scope);
  MAYBE_MAP_TYPE_WITH_TYPE_ID(decl, node);
  if (decl && decl->get_scope())
    rdr.maybe_canonicalize_type(decl, /*force_delay=*/false);
  return decl;
}

/// Parse a var-decl element.
///
/// @param rdr the context of the parsing.
///
/// @param node the node to read & parse from.
///
/// @param add_to_current_scope if set to yes, the resulting of this
/// function is added to its current scope.
static decl_base_sptr
handle_var_decl(reader&	rdr,
		xmlNodePtr	node,
		bool		add_to_current_scope)
{
  decl_base_sptr decl = build_var_decl_if_not_suppressed(rdr, node,
							 add_to_current_scope);
  rdr.maybe_add_var_to_exported_decls(is_var_decl(decl).get());
  return decl;
}

/// Parse a function-decl element.
///
/// @param rdr the context of the parsing
///
/// @return true upon successful completion of the parsing, false
/// otherwise.
static decl_base_sptr
handle_function_decl(reader&	rdr,
		     xmlNodePtr	node,
		     bool		add_to_current_scope)
{
  return build_function_decl_if_not_suppressed(rdr, node, class_decl_sptr(),
					       add_to_current_scope,
					       /*add_to_exported_decls=*/true);
}

/// Parse a 'class-decl' xml element.
///
/// @param rdr the context of the parsing.
///
/// @return the resulting @ref class_decl built from the XML element
/// upon successful completion of the parsing, nil otherwise.
static decl_base_sptr
handle_class_decl(reader& rdr,
		  xmlNodePtr	node,
		  bool		add_to_current_scope)
{
  class_decl_sptr decl =
    build_class_decl_if_not_suppressed(rdr, node, add_to_current_scope);
  MAYBE_MAP_TYPE_WITH_TYPE_ID(is_type(decl), node);
  if (decl && decl->get_scope())
    rdr.maybe_canonicalize_type(decl, /*force_delay=*/false);
  return decl;
}

/// Parse a 'union-decl' xml element.
///
/// @param rdr the context of the parsing.
///
/// @return the resulting @ref union_decl built from the XML element
/// upon successful completion of the parsing, nil otherwise.
static decl_base_sptr
handle_union_decl(reader& rdr,
		  xmlNodePtr	node,
		  bool		add_to_current_scope)
{
  union_decl_sptr decl =
    build_union_decl_if_not_suppressed(rdr, node, add_to_current_scope);
  MAYBE_MAP_TYPE_WITH_TYPE_ID(is_type(decl), node);
  if (decl && decl->get_scope())
    rdr.maybe_canonicalize_type(decl, /*force_delay=*/false);
  return decl;
}

/// Parse a 'function-template-decl' xml element.
///
/// @param rdr the parsing context.
///
/// @return true upon successful completion of the parsing, false
/// otherwise.
static decl_base_sptr
handle_function_tdecl(reader&	rdr,
		      xmlNodePtr	node,
		      bool		add_to_current_scope)
{
  function_tdecl_sptr d = build_function_tdecl(rdr, node,
					       add_to_current_scope);
  return d;
}

/// Parse a 'class-template-decl' xml element.
///
/// @param rdr the context of the parsing.
///
/// @return true upon successful completion, false otherwise.
static decl_base_sptr
handle_class_tdecl(reader&	rdr,
		   xmlNodePtr		node,
		   bool		add_to_current_scope)
{
  class_tdecl_sptr decl = build_class_tdecl(rdr, node,
					    add_to_current_scope);
  return decl;
}

/// De-serialize a translation unit from an ABI Instrumentation xml
/// file coming from an input stream.
///
/// @param in a pointer to the input stream.
///
/// @param env the environment to use.
///
/// @return the translation unit resulting from the parsing upon
/// successful completion, or nil.
translation_unit_sptr
read_translation_unit_from_istream(istream* in, environment& env)
{
  reader read_rdr(xml::new_reader_from_istream(in), env);
  return read_translation_unit_from_input(read_rdr);
}
template<typename T>
struct array_deleter
{
  void
  operator()(T* a)
  {
    delete [] a;
  }
};//end array_deleter


/// Create an xml_reader::reader to read a native XML ABI file.
///
/// @param path the path to the native XML file to read.
///
/// @param env the environment to use.
///
/// @return the created context.
fe_iface_sptr
create_reader(const string& path, environment& env)
{
  reader_sptr result(new reader(xml::new_reader_from_file(path),
				env));
  corpus_sptr corp = result->corpus();
  corp->set_origin(corpus::NATIVE_XML_ORIGIN);
#ifdef WITH_DEBUG_SELF_COMPARISON
  if (env.self_comparison_debug_is_on())
    env.set_self_comparison_debug_input(result->corpus());
#endif
  result->set_path(path);
  return result;
}

/// Create an xml_reader::reader to read a native XML ABI from
/// an input stream..
///
/// @param in the input stream that contains the native XML file to read.
///
/// @param env the environment to use.
///
/// @return the created context.
fe_iface_sptr
create_reader(std::istream* in, environment& env)
{
  reader_sptr result(new reader(xml::new_reader_from_istream(in),
				env));
  corpus_sptr corp = result->corpus();
  corp->set_origin(corpus::NATIVE_XML_ORIGIN);
#ifdef WITH_DEBUG_SELF_COMPARISON
  if (env.self_comparison_debug_is_on())
    env.set_self_comparison_debug_input(result->corpus());
#endif
  return result;
}

/// De-serialize an ABI corpus from an input XML document which root
/// node is 'abi-corpus'.
///
/// @param in the input stream to read the XML document from.
///
/// @param env the environment to use.  Note that the life time of
/// this environment must be greater than the lifetime of the
/// resulting corpus as the corpus uses resources that are allocated
/// in the environment.
///
/// @return the resulting corpus de-serialized from the parsing.  This
/// is non-null iff the parsing resulted in a valid corpus.
corpus_sptr
read_corpus_from_abixml(std::istream* in,
			environment& env)
{
  fe_iface_sptr rdr = create_reader(in, env);
  fe_iface::status sts;
  return rdr->read_corpus(sts);
}

/// De-serialize an ABI corpus from an XML document file which root
/// node is 'abi-corpus'.
///
/// @param path the path to the input file to read the XML document
/// from.
///
/// @param env the environment to use.  Note that the life time of
/// this environment must be greater than the lifetime of the
/// resulting corpus as the corpus uses resources that are allocated
/// in the environment.
///
/// @return the resulting corpus de-serialized from the parsing.  This
/// is non-null if the parsing successfully resulted in a corpus.
corpus_sptr
read_corpus_from_abixml_file(const string& path,
			     environment& env)
{
  fe_iface_sptr rdr = create_reader(path, env);
  fe_iface::status sts;
  corpus_sptr corp = rdr->read_corpus(sts);
  return corp;
}

}//end namespace xml_reader

#ifdef WITH_DEBUG_SELF_COMPARISON
/// Load the map that is stored at
/// environment::get_type_id_canonical_type_map().
///
/// That map associates type-ids to the pointer value of the canonical
/// types they correspond to.  The map is loaded from a file that was
/// stored on disk by some debugging primitive that is activated when
/// the command "abidw --debug-abidiff <binary>' is used."
///
/// The function that stored the map in that file is
/// write_canonical_type_ids.
///
/// @param rdr the ABIXML reader to use.
///
/// @param file_path the path to the file containing the type-ids <->
/// canonical type mapping.
///
/// @return true iff the loading was successful.
bool
load_canonical_type_ids(fe_iface& iface, const string &file_path)
{
  abixml::reader& rdr = dynamic_cast<abixml::reader&>(iface);

  xmlDocPtr doc = xmlReadFile(file_path.c_str(), NULL, XML_PARSE_NOERROR);
  if (!doc)
    return false;

  xmlNodePtr node = xmlDocGetRootElement(doc);
  if (!node)
    return false;

  // We expect a file which content looks like:
  //
  // <abixml-types-check>
  //     <type>
  //       <id>type-id-573</id>
  //       <c>0x262ee28</c>
  //     </type>
  //     <type>
  //       <id>type-id-569</id>
  //       <c>0x2628298</c>
  //     </type>
  //     <type>
  //       <id>type-id-575</id>
  //       <c>0x25f9ba8</c>
  //     </type>
  // <abixml-types-check>
  //
  // So let's parse it!

  if (xmlStrcmp(node->name, (xmlChar*) "abixml-types-check"))
    return false;

  for (node = xmlFirstElementChild(node);
       node;
       node = xmlNextElementSibling(node))
    {
      if (xmlStrcmp(node->name, (xmlChar*) "type"))
	continue;

      string id, canonical_address;
      xmlNodePtr data = xmlFirstElementChild(node);
      if (data && !xmlStrcmp(data->name, (xmlChar*) "id")
	  && data->children && xmlNodeIsText(data->children))
	id = (char*) XML_GET_CONTENT(data->children);

      data = xmlNextElementSibling(data);
      if (data && !xmlStrcmp(data->name, (xmlChar*) "c")
	  && data->children && xmlNodeIsText(data->children))
	{
	  canonical_address = (char*) XML_GET_CONTENT(data->children);
	  std::stringstream s;
	  s << canonical_address;
	  uintptr_t v = 0;
	  s >>  std::hex >> v;
	  if (!id.empty()
	      // 0xdeadbabe is the special value the hash of types
	      // that are not canonicalized.  Look into function
	      // hash_as_canonical_type_or_constant for the details.
	      && v != 0xdeadbabe)
	    rdr.get_environment().get_type_id_canonical_type_map()[id] = v;
	}
    }
  return true;
}
#endif

}//end namespace abigail
