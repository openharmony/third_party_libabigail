// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- Mode: C++ -*-
//
// Copyright (C) 2014-2025 Red Hat, Inc.
//
// Author: Dodji Seketeli

/// @file
///
/// This program reads a program A, one library L in version V which A
/// links against, and the same library L in a different version, V+P.
/// The program then checks that A is still ABI compatible with L in
/// version V+P.
///
/// The program also comes with a "weak mode" in which just the
/// application and the library in version V+P need to be provided by
/// the user.  In that case, the types of functions and variables of
/// the library that are consumed by the application are compared to
/// the types of the functions and variables expected by the
/// application.  If they match exactly, then the types of functions
/// and variables that the application expects from the library are
/// honoured by the library.  Otherwise, the library might provide
/// functions and variables that mean something different from what
/// the application expects and that might signal an ABI
/// incompatibility between what the application expects and what the
/// library provides.

#include <unistd.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include "config.h"
#include "abg-config.h"
#include "abg-tools-utils.h"
#include "abg-corpus.h"
#include "abg-reader.h"
#include "abg-dwarf-reader.h"
#include "abg-comparison.h"
#include "abg-suppression.h"
#ifdef WITH_CTF
#include "abg-ctf-reader.h"
#endif
#ifdef WITH_BTF
#include "abg-btf-reader.h"
#endif

using std::string;
using std::cerr;
using std::cout;
using std::ostream;
using std::ofstream;
using std::vector;
using std::shared_ptr;

using namespace abigail;

using abigail::tools_utils::abidiff_status;
using abigail::tools_utils::base_name;
using abigail::tools_utils::check_file;
using abigail::tools_utils::create_best_elf_based_reader;
using abigail::tools_utils::emit_prefix;
using abigail::ir::environment;
using abigail::ir::environment_sptr;
using abigail::corpus;
using abigail::corpus_sptr;
using abigail::ir::elf_symbols;
using abigail::ir::demangle_cplus_mangled_name;
using abigail::ir::type_base_sptr;
using abigail::ir::function_type_sptr;
using abigail::ir::function_decl;
using abigail::ir::var_decl;
using abigail::comparison::diff_context_sptr;
using abigail::comparison::diff_context;
using abigail::comparison::diff_sptr;
using abigail::comparison::corpus_diff;
using abigail::comparison::corpus_diff_sptr;
using abigail::comparison::function_type_diff_sptr;
using abigail::comparison::compute_diff;
using abigail::comparison::get_default_harmless_categories_bitmap;
using abigail::comparison::apply_filters_and_categorize_diff_node_tree;
using abigail::suppr::suppression_sptr;
using abigail::suppr::suppressions_type;
using abigail::suppr::read_suppressions;

class options
{
  options();

public:
  string		prog_name;
  string		unknow_option;
  string		app_path;
  string		lib1_path;
  string		lib2_path;
  string		app_di_root_path;
  string		lib1_di_root_path;
  string		lib2_di_root_path;
  vector<string>	suppression_paths;
  bool			display_help;
  bool			display_version;
  bool			weak_mode;
  bool			list_undefined_symbols_only;
  bool			show_base_names;
  bool			show_redundant;
  bool			redundant_opt_set;
  bool			no_redundant_opt_set;
  bool			show_locs;
  bool			fail_no_debug_info;
  bool			ignore_soname;
#ifdef WITH_CTF
  bool			use_ctf;
#endif
#ifdef WITH_BTF
  bool			use_btf;
#endif

  options(const char* program_name)
    :prog_name(program_name),
     display_help(),
     display_version(),
     weak_mode(),
     list_undefined_symbols_only(),
     show_base_names(),
     show_redundant(true),
     redundant_opt_set(),
     no_redundant_opt_set(),
     show_locs(true),
     fail_no_debug_info(),
     ignore_soname(false)
#ifdef WITH_CTF
    ,
      use_ctf()
#endif
#ifdef WITH_BTF
    ,
      use_btf()
#endif
  {}
}; // end struct options

/// A description of a change of the type of a function.  It contains
/// the declaration of the function we are interested in, as well as
/// the differences found in the type of that function.
struct fn_change
{
  const function_decl* decl = nullptr;
  function_type_diff_sptr diff;
  bool reverse_direction = false;

  fn_change(const function_decl* decl,
	    function_type_diff_sptr difference,
	    bool reverse_dir = false)
    : decl(decl),
      diff(difference),
      reverse_direction(reverse_dir)
  {}
}; // end struct fn_change

/// An description of a change of the type of a variable.  It contains
/// the declaration of the variable we are interested in, as well as
/// the differences found in the type of that variable.
struct var_change
{
  var_decl_sptr decl = nullptr;
  diff_sptr diff;
  bool reverse_direction = false;

  var_change(const var_decl_sptr& var,
	     diff_sptr difference,
	     bool reverse_dir)
    : decl(var),
      diff(difference),
      reverse_direction(reverse_dir)
  {}
}; // end struct var_change

class options;
struct fn_changes;
struct var_changes;

static void
report_function_changes(const options&			opts,
			const vector<fn_change>&	fn_changes);

static void
report_variable_changes(const options&			opts,
			const vector<var_change>&	var_changes);

static abidiff_status
compare_expected_against_provided_functions(diff_context_sptr&		ctxt,
					    corpus_sptr		app_corpus,
					    corpus_sptr		lib_corpus,
					    vector<fn_change>&		fn_changes,
					    bool			reverse_direction = false);

static abidiff_status
compare_expected_against_provided_variables(diff_context_sptr&		ctxt,
					    corpus_sptr		app_corpus,
					    corpus_sptr		lib_corpus,
					    vector<var_change>&	var_changes,
					    bool			reverse_direction = false);

static abidiff_status
perform_compat_check_in_normal_mode(options& opts,
				    diff_context_sptr& ctxt,
				    corpus_sptr app_corpus,
				    corpus_sptr lib1_corpus,
				    corpus_sptr lib2_corpus);

static abidiff_status
perform_compat_check_in_weak_mode(options& opts,
				  diff_context_sptr& ctxt,
				  corpus_sptr app_corpus,
				  corpus_sptr lib_corpus);

static void
display_usage(const string& prog_name, ostream& out)
{
  emit_prefix(prog_name, out)
    << "usage: " << prog_name
    << " [options] [application-path] [lib-v1-path] [lib-v2-path]"
    << "\n"
    << " where options can be: \n"
    << "  --help|-h  display this help message\n"
    << "  --version|-v  show program version information and exit\n"
    << "  --list-undefined-symbols|-u  display the list of "
    "undefined symbols of the application\n"
    << "  --show-base-names|b  in the report, only show the base names "
    " of the files; not the full paths\n"
    << "  --app-debug-info-dir|--appd <path-to-app-debug-info>  set the path "
    "to the debug information directory for the application\n"
    << "  --lib-debug-info-dir1|--libd1 <path-to-lib-debug-info1>  set the path "
    "to the debug information directory for the first library\n"
    << "  --lib-debug-info-dir2|--libd2 <path-to-lib-debug-info2>  set the path "
    "to the debug information directory for the second library\n"
    << "  --suppressions|--suppr <path> specify a suppression file\n"
    << "  --no-redundant  do not display redundant changes\n"
    << "  --no-show-locs  do now show location information\n"
    << "  --ignore-soname  do not take the SONAMEs into account\n"
    << "  --fail-no-debug-info  bail out if no debug info was found\n"
    << "  --redundant  display redundant changes (this is the default)\n"
    << "  --weak-mode  check compatibility between the application and "
    "just one version of the library.\n"
#ifdef WITH_CTF
    << "  --ctf use CTF instead of DWARF in ELF files\n"
#endif
#ifdef WITH_BTF
    << "  --btf use BTF instead of DWARF in ELF files\n"
#endif
    ;
}

static bool
parse_command_line(int argc, char* argv[], options& opts)
{
  if (argc < 2)
    return false;

  for (int i = 1; i < argc; ++i)
    {
      if (argv[i][0] != '-')
	{
	  if (opts.app_path.empty())
	    opts.app_path = argv[i];
	  else if (opts.lib1_path.empty())
	    opts.lib1_path = argv[i];
	  else if (opts.lib2_path.empty())
	    opts.lib2_path = argv[i];
	  else
	    return false;
	}
      else if (!strcmp(argv[i], "--version")
	       || !strcmp(argv[i], "-v"))
	{
	  opts.display_version = true;
	  return true;
	}
      else if (!strcmp(argv[i], "--list-undefined-symbols")
	       || !strcmp(argv[i], "-u"))
	opts.list_undefined_symbols_only = true;
      else if (!strcmp(argv[i], "--show-base-names")
	       || !strcmp(argv[i], "-b"))
	opts.show_base_names = true;
      else if (!strcmp(argv[i], "--app-debug-info-dir")
	       || !strcmp(argv[i], "--appd"))
	{
	  if (argc <= i + 1
	      || argv[i + 1][0] == '-')
	    return false;
	  // elfutils wants the root path to the debug info to be
	  // absolute.
	  opts.app_di_root_path =
	    abigail::tools_utils::make_path_absolute(string(argv[i + 1]));
	  ++i;
	}
      else if (!strcmp(argv[i], "--lib-debug-info-dir1")
	       || !strcmp(argv[i], "--libd1"))
	{
	  if (argc <= i + 1
	      || argv[i + 1][0] == '-')
	    return false;
	  // elfutils wants the root path to the debug info to be
	  // absolute.
	  opts.lib1_di_root_path =
	    abigail::tools_utils::make_path_absolute(string(argv[i + 1]));
	  ++i;
	}
      else if (!strcmp(argv[i], "--lib-debug-info-dir2")
	       || !strcmp(argv[i], "--libd2"))
	{
	  if (argc <= i + 1
	      || argv[i + 1][0] == '-')
	    return false;
	  // elfutils wants the root path to the debug info to be
	  // absolute.
	  opts.lib2_di_root_path =
	    abigail::tools_utils::make_path_absolute(string(argv[i + 1]));
	  ++i;
	}
      else if (!strcmp(argv[i], "--suppressions")
	       || !strcmp(argv[i], "--suppr"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    return false;
	  opts.suppression_paths.push_back(argv[j]);
	  ++i;
	}
      else if (!strcmp(argv[i], "--redundant"))
        {
	  opts.show_redundant = true;
	  opts.redundant_opt_set = true;
	}
      else if (!strcmp(argv[i], "--no-redundant"))
        {
  	  opts.show_redundant = false;
	  opts.no_redundant_opt_set = true;
	}
      else if (!strcmp(argv[i], "--no-show-locs"))
	opts.show_locs = false;
      else if (!strcmp(argv[i], "--ignore-soname"))
	opts.ignore_soname=true;
      else if (!strcmp(argv[i], "--fail-no-debug-info"))
	opts.fail_no_debug_info = true;
      else if (!strcmp(argv[i], "--help")
	       || !strcmp(argv[i], "-h"))
	{
	  opts.display_help = true;
	  return true;
	}
      else if (!strcmp(argv[i], "--weak-mode"))
	opts.weak_mode = true;
#ifdef WITH_CTF
      else if (!strcmp(argv[i], "--ctf"))
        opts.use_ctf = true;
#endif
#ifdef WITH_BTF
      else if (!strcmp(argv[i], "--btf"))
        opts.use_btf = true;
#endif
      else
	{
	  opts.unknow_option = argv[i];
	  return false;
	}
    }

  if (!opts.list_undefined_symbols_only)
    {
      if (opts.app_path.empty()
	  || opts.lib1_path.empty())
	return false;
      if (!opts.weak_mode && opts.lib2_path.empty())
	opts.weak_mode = true;
    }

  return true;
}

/// Create the context of a diff.
///
/// Create the diff context, initialize it and return a smart pointer
/// to it.
///
/// @param opts the options of the program.
///
/// @return a smart pointer to the newly created diff context.
static diff_context_sptr
create_diff_context(const options& opts)
{
  diff_context_sptr ctxt(new diff_context());
  ctxt->show_added_fns(false);
  ctxt->show_added_vars(false);
  ctxt->show_added_symbols_unreferenced_by_debug_info(false);
  ctxt->show_linkage_names(true);
  ctxt->show_redundant_changes(opts.show_redundant);
  ctxt->show_locs(opts.show_locs);
  // Intentional logic flip of ignore_soname
  ctxt->show_soname_change(!opts.ignore_soname);
  ctxt->switch_categories_off(get_default_harmless_categories_bitmap());

  // Load suppression specifications, if there are any.
  suppressions_type supprs;
  for (vector<string>::const_iterator i = opts.suppression_paths.begin();
       i != opts.suppression_paths.end();
       ++i)
    if (check_file(*i, cerr, opts.prog_name))
      read_suppressions(*i, supprs);

  if (!supprs.empty())
    ctxt->add_suppressions(supprs);

  return ctxt;
}

/// Compare the functions expected by an application against the
/// functions provides by a library.
///
/// The result of the comparison is a vector of @ref fn_change.
///
/// The app & libraries are represented by their ABI corpora.
///
/// The comparison can also be done in the "reverse direction",
/// meaning, it compares the functions expected by library (or plugin)
/// against the functions provided by the application.
///
/// @param ctxt the context use to perform the comparison.
///
/// @param app_corpus the ABI corpus of the application to consider.
///
/// @param lib_corpus the ABI corpus of the library (or plugin) to
/// consider.
///
/// @param fn_changes output parameter.  This is a vector of @ref
/// fn_change that is populated by this function if it finds changes
/// between what the application expects and what the library
/// provides.
///
/// @param reverse_direction if this is true, then @lib_corpus is
/// considered as a plugin and in that case, the functions it expects
/// are compared against the functions provided by the application.
///
/// @return the status of the comparison.
static abidiff_status
compare_expected_against_provided_functions(diff_context_sptr&		ctxt,
					    corpus_sptr		app_corpus,
					    corpus_sptr		lib_corpus,
					    vector<fn_change>&		fn_changes,
					    bool			reverse_direction)
{
  abidiff_status status = abigail::tools_utils::ABIDIFF_OK;
  for (auto expected_fn :
	 reverse_direction
	 ? lib_corpus->get_sorted_undefined_functions()
	 : app_corpus->get_sorted_undefined_functions())
    {
      interned_string fn_id = expected_fn->get_id();
      // ... against the functions exported by the library!
      const std::unordered_set<function_decl*> *exported_fns =
	reverse_direction
	? app_corpus->lookup_functions(fn_id)
	: lib_corpus->lookup_functions(fn_id);
      if (exported_fns)
	{
	  for (auto exported_fn : *exported_fns)
	    {
	      // OK here is where we compare the function expected
	      // by the application against the function exported by
	      // the library.
	      function_type_diff_sptr fn_type_diff =
		compute_diff(expected_fn->get_type(),
			     exported_fn->get_type(),
			     ctxt);
	      diff_sptr diff_tree = is_diff(fn_type_diff);
	      apply_filters_and_categorize_diff_node_tree(diff_tree);
	      if (fn_type_diff && fn_type_diff->to_be_reported())
		{
		  // So there is a type change between the function
		  // expected by the application and the function
		  // exported by the library.  Let's record that
		  // change so that we can report about it later.
		  fn_changes.push_back(fn_change(expected_fn, fn_type_diff, reverse_direction));
		  status |= abigail::tools_utils::ABIDIFF_ABI_CHANGE;
		}
	    }
	}
    }

  return status;
}

/// Compare the variables expected by an application against the
/// variables provides by a library.
///
/// The result of the comparison is a vector of @ref fn_change.
///
/// The app & libraries are represented by their ABI corpora.
///
/// The comparison can also be done in the "reverse direction",
/// meaning, it compares the variables expected by library (or plugin)
/// against the variables provided by the application.
///
/// @param ctxt the context use to perform the comparison.
///
/// @param app_corpus the ABI corpus of the application to consider.
///
/// @param lib_corpus the ABI corpus of the library (or plugin) to
/// consider.
///
/// @param fn_changes output parameter.  This is a vector of @ref
/// fn_change that is populated by this function if it finds changes
/// between what the application expects and what the library
/// provides.
///
/// @param reverse_direction if this is true, then @lib_corpus is
/// considered as a plugin and in that case, the variables it expects
/// are compared against the variables provided by the application.
///
/// @return the status of the comparison.
static abidiff_status
compare_expected_against_provided_variables(diff_context_sptr&		ctxt,
					    corpus_sptr		app_corpus,
					    corpus_sptr		lib_corpus,
					    vector<var_change>&	var_changes,
					    bool			reverse_direction)
{
  abidiff_status status = abigail::tools_utils::ABIDIFF_OK;
  for (auto expected_var :
	 reverse_direction
	 ? lib_corpus->get_sorted_undefined_variables()
	 : app_corpus->get_sorted_undefined_variables())
    {
      interned_string var_id = expected_var->get_id();
      // ... against the variables exported by the library!
      const std::unordered_set<var_decl_sptr>* exported_vars =
	reverse_direction
	? app_corpus->lookup_variables(var_id)
	: lib_corpus->lookup_variables(var_id);
      if (exported_vars)
	{
	  for (auto exported_var : *exported_vars)
	    {
	      // OK here is where we compare the variable expected by
	      // the application against the variable exported by the
	      // library.
	      diff_sptr type_diff =
		compute_diff(expected_var->get_type(),
			     exported_var->get_type(),
			     ctxt);
	      apply_filters_and_categorize_diff_node_tree(type_diff);
	      if (type_diff && type_diff->to_be_reported())
		{
		  // So there is a type change between the variable
		  // expected by the application and the variable
		  // exported by the library.  Let's record that
		  // change so that we can report about it later.
		  var_changes.push_back(var_change(expected_var, type_diff, reverse_direction));
		  status |= abigail::tools_utils::ABIDIFF_ABI_CHANGE;
		}
	    }
	}
    }

  return status;
}

/// Report about the changes between functions expected by a binary
/// and functions provided by another one.
///
/// @param opts the command line options received by the current
/// program.
///
/// @param fn_changes the vector of @ref fn_change to report about.
static void
report_function_changes(const options&			opts,
			const vector<fn_change>&	fn_changes)
{
  string lib1_path = opts.lib1_path, app_path = opts.app_path;


  // If some function changes were detected, then report them.
  if (!fn_changes.empty())
    {
      if (opts.show_base_names)
	{
	  base_name(opts.lib1_path, lib1_path);
	  base_name(opts.app_path, app_path);
	}

      if (fn_changes.front().reverse_direction)
	cout << "functions expected by library or plugin "
	     << "'" << lib1_path << "'\n"
	     << "have sub-types that are different from what application "
	     << "'" << app_path << "' "
	     << "provides:\n\n";
      else
	cout << "functions defined in library "
	     << "'" << lib1_path << "'\n"
	     << "have sub-types that are different from what application "
	     << "'" << app_path << "' "
	     << "expects:\n\n";

      for (auto& change : fn_changes)
	{
	  cout << "  "
	       << change.decl->get_pretty_representation()
	       << ":\n";
	  change.diff->report(cout, "    ");
	  cout << "\n";
	}
    }
}

/// Report about the changes between variables expected by a binary
/// and variables provided by another one.
///
/// @param opts the command line options received by the current
/// program.
///
/// @param var_changes the vector of @ref var_change to report about.
static void
report_variable_changes(const options&			opts,
			const vector<var_change>&	var_changes)
{
  string lib1_path = opts.lib1_path, app_path = opts.app_path;

  if (!var_changes.empty())
    {
      if (opts.show_base_names)
	{
	  base_name(opts.lib1_path, lib1_path);
	  base_name(opts.app_path, app_path);
	}

      if (var_changes.front().reverse_direction)
	cout << "variables defined in library or plugin "
	     << "'" << lib1_path << "'\n"
	     << "have sub-types that are different from what application "
	     << "'" << app_path << "' "
	     << "expects:\n\n";
      else
	cout << "variables defined in library "
	     << "'" << lib1_path << "'\n"
	     << "have sub-types that are different from what application "
	     << "'" << app_path << "' "
	     << "expects:\n\n";

      for (vector<var_change>::const_iterator i = var_changes.begin();
	   i != var_changes.end();
	   ++i)
	{
	  cout << "  "
	       << i->decl->get_pretty_representation()
	       << ":\n";
	  i->diff->report(cout, "    ");
	  cout << "\n";
	}
    }
}

/// Perform a compatibility check of an application corpus linked
/// against a first version of library corpus, with a second version
/// of the same library.
///
/// @param opts the options the tool got invoked with.
///
/// @param ctxt the context of the diff to be performed.
///
/// @param app_corpus the application corpus to consider.
///
/// @param lib1_corpus the library corpus that got linked with the
/// application which corpus is @p app_corpus.
///
/// @param lib2_corpus the second version of the library corpus @p
/// lib1_corpus.  This function checks that the functions and
/// variables that @p app_corpus expects from lib1_corpus are still
/// present in @p lib2_corpus and that their types mean the same
/// thing.
///
/// @return a status bitfield.
static abidiff_status
perform_compat_check_in_normal_mode(options& opts,
				    diff_context_sptr& ctxt,
				    corpus_sptr app_corpus,
				    corpus_sptr lib1_corpus,
				    corpus_sptr lib2_corpus)
{
  ABG_ASSERT(lib1_corpus);
  ABG_ASSERT(lib2_corpus);
  ABG_ASSERT(app_corpus);

  abidiff_status status = abigail::tools_utils::ABIDIFF_OK;

  // compare lib1 and lib2 only by looking at the functions and
  // variables which symbols are those undefined in the app.

  for (elf_symbols::const_iterator i =
	 app_corpus->get_sorted_undefined_fun_symbols().begin();
       i != app_corpus->get_sorted_undefined_fun_symbols().end();
       ++i)
    {
      string id = (*i)->get_id_string();
      lib1_corpus->get_sym_ids_of_fns_to_keep().push_back(id);
      lib2_corpus->get_sym_ids_of_fns_to_keep().push_back(id);
    }
  for (elf_symbols::const_iterator i =
	 app_corpus->get_sorted_undefined_var_symbols().begin();
       i != app_corpus->get_sorted_undefined_var_symbols().end();
       ++i)
    {
      string id = (*i)->get_id_string();
      lib1_corpus->get_sym_ids_of_vars_to_keep().push_back(id);
      lib2_corpus->get_sym_ids_of_vars_to_keep().push_back(id);
    }

  if (!app_corpus->get_sorted_undefined_var_symbols().empty()
      || !app_corpus->get_sorted_undefined_fun_symbols().empty())
    {
      lib1_corpus->maybe_drop_some_exported_decls();
      lib2_corpus->maybe_drop_some_exported_decls();
    }

  // Now really do the diffing.
  corpus_diff_sptr changes = compute_diff(lib1_corpus, lib2_corpus, ctxt);

  if (changes->has_net_changes())
    {
      string app_path = opts.app_path,
	lib1_path = opts.lib1_path,
	lib2_path = opts.lib2_path;

      if (opts.show_base_names)
	{
	  base_name(opts.app_path, app_path);
	  base_name(opts.lib1_path, lib1_path);
	  base_name(opts.lib2_path, lib2_path);
	}

      status |= abigail::tools_utils::ABIDIFF_ABI_CHANGE;

      bool abi_broke_for_sure = changes->has_incompatible_changes();

      cout << "ELF file '" << app_path << "'";
      if (abi_broke_for_sure)
	{
	  cout << " is not ";
	  status |= abigail::tools_utils::ABIDIFF_ABI_INCOMPATIBLE_CHANGE;
	}
      else
	  cout << " might not be ";

      cout << "ABI compatible with '" << lib2_path
	   << "' due to differences with '" << lib1_path
	   << "' below:\n";
      changes->report(cout);
    }

  return status;
}

/// Perform a compatibility check of an application corpus and a
/// library corpus.
///
/// The types of the variables and functions exported by the library
/// and consumed by the application are compared with the types
/// expected by the application.  This function checks that the types
/// mean the same thing; otherwise it emits on standard output type
/// layout differences found.
///
/// @param opts the options the tool got invoked with.
///
/// @param app_corpus the application corpus to consider.
///
/// @param lib_corpus the library corpus to consider.
///
/// @return a status bitfield.
static abidiff_status
perform_compat_check_in_weak_mode(options& opts,
				  diff_context_sptr& ctxt,
				  corpus_sptr app_corpus,
				  corpus_sptr lib_corpus)
{
  ABG_ASSERT(lib_corpus);
  ABG_ASSERT(app_corpus);

  abidiff_status status = abigail::tools_utils::ABIDIFF_OK;

  // We are now going to compare the functions that are exported by
  // lib_corpus against those that app_corpus expects.
  //
  // In other words, the functions which symbols are defined by
  // lib_corpus are going to be compared to the functions and
  // variables which are undefined in app_corpus.

  {
    vector<fn_change> fn_changes;
    status = compare_expected_against_provided_functions(ctxt, app_corpus, lib_corpus,
							 fn_changes, /*reverse_direction=*/false);
    report_function_changes(opts, fn_changes);
  }

  {
    vector<fn_change> fn_changes;
    status |= compare_expected_against_provided_functions(ctxt, app_corpus, lib_corpus,
							  fn_changes, /*reverse_direction=*/true);
    report_function_changes(opts, fn_changes);
  }

  // Similarly, we are now going to compare the variables that are
  // exported by lib_corpus against those that app_corpus expects.
  {
    vector<var_change> var_changes;
    status |= compare_expected_against_provided_variables(ctxt, app_corpus, lib_corpus,
							  var_changes, /*reverse_direction=*/false);
    report_variable_changes(opts, var_changes);
  }

  {
    vector<var_change> var_changes;
    status |= compare_expected_against_provided_variables(ctxt, app_corpus, lib_corpus,
							  var_changes, /*reverse_direction=*/true);
    report_variable_changes(opts, var_changes);
  }

  return status;
}

/// Read an ABI corpus, be it from ELF or abixml.
///
/// @param opts the options passed from the user to the program.
///
/// @param status the resulting fe_iface::status to send back to the
/// caller.
///
/// @param di_roots the directories from where to look for debug info.
///
/// @param env the environment used for libabigail.
///
/// @param path the path to the ABI corpus to read from.
static corpus_sptr
read_corpus(options			opts,
	    abigail::fe_iface::status&	status,
	    const vector<string>	di_roots,
	    environment		&env,
	    const string		&path)
{
  corpus_sptr retval = NULL;
  abigail::tools_utils::file_type type =
    abigail::tools_utils::guess_file_type(path);
  abigail::fe_iface_sptr rdr;

  switch (type)
    {
    case abigail::tools_utils::FILE_TYPE_UNKNOWN:
      emit_prefix(opts.prog_name, cerr)
	<< "Unknown content type for file " << path << "\n";
      break;
    case abigail::tools_utils::FILE_TYPE_ELF:
      {
	corpus::origin requested_fe_kind = corpus::DWARF_ORIGIN;
#ifdef WITH_CTF
	if (opts.use_ctf)
	  requested_fe_kind = corpus::CTF_ORIGIN;
#endif
#ifdef WITH_BTF
	if (opts.use_btf)
	  requested_fe_kind = corpus::BTF_ORIGIN;
#endif

	rdr = create_best_elf_based_reader (path, di_roots, env, requested_fe_kind,
					    /*load_all_types=*/opts.weak_mode,
					    status);
	ABG_ASSERT(rdr);
	rdr->options().load_undefined_interfaces = true;
	retval = rdr->read_corpus(status);
      }
      break;
    case abigail::tools_utils::FILE_TYPE_XML_CORPUS:
      {
	rdr = abixml::create_reader(path, env);
	assert(rdr);
	retval = rdr->read_corpus(status);
      }
      break;
    case abigail::tools_utils::FILE_TYPE_AR:
    case abigail::tools_utils::FILE_TYPE_XML_CORPUS_GROUP:
    case abigail::tools_utils::FILE_TYPE_RPM:
    case abigail::tools_utils::FILE_TYPE_SRPM:
    case abigail::tools_utils::FILE_TYPE_DEB:
    case abigail::tools_utils::FILE_TYPE_DIR:
    case abigail::tools_utils::FILE_TYPE_TAR:
    case abigail::tools_utils::FILE_TYPE_NATIVE_BI:
    case abigail::tools_utils::FILE_TYPE_XZ:
      break;
    }

  return retval;
}

int
main(int argc, char* argv[])
{
  options opts(argv[0]);

  abigail::tools_utils::initialize();

  if (!parse_command_line(argc, argv, opts))
    {
      if (!opts.unknow_option.empty())
	{
	  emit_prefix(argv[0], cerr)
	    << "unrecognized option: " << opts.unknow_option << "\n"
	    << "try the --help option for more information\n";
	  return (abigail::tools_utils::ABIDIFF_USAGE_ERROR
		  | abigail::tools_utils::ABIDIFF_ERROR);
	}

      emit_prefix(argv[0], cerr)
	<< "wrong invocation\n"
	<< "try the --help option for more information\n";
      return (abigail::tools_utils::ABIDIFF_USAGE_ERROR
	      | abigail::tools_utils::ABIDIFF_ERROR);
    }

  if (opts.display_help)
    {
      display_usage(argv[0], cout);
      return (abigail::tools_utils::ABIDIFF_USAGE_ERROR
		  | abigail::tools_utils::ABIDIFF_ERROR);
    }

  if (opts.display_version)
    {
      emit_prefix(argv[0], cout)
	<< abigail::tools_utils::get_library_version_string()
	<< "\n";
      return 0;
    }

  if (opts.weak_mode && !opts.lib2_path.empty())
    {
      emit_prefix(argv[0], cout)
        << "WARNING: The \'--weak-mode\' option is used. The "
	<< opts.lib2_path << " will be ignored automatically\n";
    }

  if (opts.redundant_opt_set && opts.no_redundant_opt_set)
    {
      emit_prefix(argv[0], cerr)
        << "ERROR: The \'--redundant\' and '--no-redundant' option are in conflict. "
	<< "Please select only one option to use.\n";
      return 1;
    }

  ABG_ASSERT(!opts.app_path.empty());
  if (!abigail::tools_utils::check_file(opts.app_path, cerr, opts.prog_name))
    return abigail::tools_utils::ABIDIFF_ERROR;

  // Create the context of the diff
  diff_context_sptr ctxt = create_diff_context(opts);

  // Check if any suppression specification prevents us from
  // performing the compatibility checking.
  suppressions_type& supprs = ctxt->suppressions();
  bool files_suppressed = (file_is_suppressed(opts.app_path, supprs)
			   || file_is_suppressed(opts.lib1_path, supprs)
			   || file_is_suppressed(opts.lib2_path, supprs));

  if (files_suppressed)
    // We don't have to compare anything because a user
    // suppression specification file instructs us to avoid
    // loading either one of the input files.
    return abigail::tools_utils::ABIDIFF_OK;

  // Read the application ELF file.
  string& app_di_root = opts.app_di_root_path;
  vector<string> app_di_roots;
  if (!app_di_root.empty())
    app_di_roots.push_back(app_di_root);
  abigail::fe_iface::status status = abigail::fe_iface::STATUS_UNKNOWN;
  environment env;

  corpus_sptr app_corpus = read_corpus(opts, status,
				       app_di_roots, env,
				       opts.app_path);
  if (!app_corpus)
    {
      emit_prefix(argv[0], cerr) << opts.app_path
				 << " is not a supported file\n";
      return abigail::tools_utils::ABIDIFF_ERROR;
    }

  if (opts.fail_no_debug_info
      && (status & abigail::fe_iface::STATUS_ALT_DEBUG_INFO_NOT_FOUND)
      && (status & abigail::fe_iface::STATUS_DEBUG_INFO_NOT_FOUND))
    {
      emit_prefix(argv[0], cerr) << opts.app_path
				 << " does not have debug symbols\n";
      return abigail::tools_utils::ABIDIFF_ERROR;
    }
  if (status & abigail::fe_iface::STATUS_NO_SYMBOLS_FOUND)
    {
      emit_prefix(argv[0], cerr)
	<< "could not read symbols from " << opts.app_path << "\n";
      return abigail::tools_utils::ABIDIFF_ERROR;
    }
  if (!(status & abigail::fe_iface::STATUS_OK))
    {
      emit_prefix(argv[0], cerr)
	<< "could not read file " << opts.app_path << "\n";
      return abigail::tools_utils::ABIDIFF_ERROR;
    }

  if (opts.list_undefined_symbols_only)
    {
      for (elf_symbols::const_iterator i =
	     app_corpus->get_sorted_undefined_fun_symbols().begin();
	   i != app_corpus->get_sorted_undefined_fun_symbols().end();
	   ++i)
	{
	  string id = (*i)->get_id_string();
	  string sym_name = (*i)->get_name();
	  string demangled_name = demangle_cplus_mangled_name(sym_name);
	  if (demangled_name != sym_name)
	    cout << demangled_name << "  {" << id << "}\n";
	  else
	    cout << id << "\n";
	}
      return abigail::tools_utils::ABIDIFF_OK;
    }

  // Read the first version of the library.
  ABG_ASSERT(!opts.lib1_path.empty());
  if (!abigail::tools_utils::check_file(opts.lib1_path, cerr, opts.prog_name))
    return abigail::tools_utils::ABIDIFF_ERROR;

  string& lib1_di_root = opts.lib1_di_root_path;
  vector<string> lib1_di_roots;
  if (!lib1_di_root.empty())
    lib1_di_roots.push_back(lib1_di_root);
  corpus_sptr lib1_corpus = read_corpus(opts, status,
					lib1_di_roots,
					env, opts.lib1_path);
  if (!lib1_corpus)
    {
      emit_prefix(argv[0], cerr) << opts.lib1_path
				 << " is not a supported file\n";
      return abigail::tools_utils::ABIDIFF_ERROR;
    }
  if (opts.fail_no_debug_info
      && (status & abigail::fe_iface::STATUS_ALT_DEBUG_INFO_NOT_FOUND)
      && (status & abigail::fe_iface::STATUS_DEBUG_INFO_NOT_FOUND))
    emit_prefix(argv[0], cerr)
      << "could not read debug info for " << opts.lib1_path << "\n";
  if (status & abigail::fe_iface::STATUS_NO_SYMBOLS_FOUND)
    {
      emit_prefix(argv[0], cerr) << "could not read symbols from "
				 << opts.lib1_path << "\n";
      return abigail::tools_utils::ABIDIFF_ERROR;
    }
  if (!(status & abigail::fe_iface::STATUS_OK))
    {
      emit_prefix(argv[0], cerr)
	<< "could not read file " << opts.lib1_path << "\n";
      return abigail::tools_utils::ABIDIFF_ERROR;
    }

  // Read the second version of the library.
  corpus_sptr lib2_corpus;
  if (!opts.weak_mode)
    {
      ABG_ASSERT(!opts.lib2_path.empty());
      string& lib2_di_root = opts.lib2_di_root_path;
      vector<string> lib2_di_roots;
      if (!lib2_di_root.empty())
	lib2_di_roots.push_back(lib2_di_root);
      lib2_corpus = read_corpus(opts, status,
				lib2_di_roots, env,
				opts.lib2_path);
      if (!lib2_corpus)
	{
	  emit_prefix(argv[0], cerr) << opts.lib2_path
				     << " is not a supported file\n";
	  return abigail::tools_utils::ABIDIFF_ERROR;
	}

      if (opts.fail_no_debug_info
	  && (status & abigail::fe_iface::STATUS_ALT_DEBUG_INFO_NOT_FOUND)
	  && (status & abigail::fe_iface::STATUS_DEBUG_INFO_NOT_FOUND))
	{
	  emit_prefix(argv[0], cerr)
	    << "could not read debug info for " << opts.lib2_path << "\n";
	  return abigail::tools_utils::ABIDIFF_ERROR;
	}
      if (status & abigail::fe_iface::STATUS_NO_SYMBOLS_FOUND)
	{
	  emit_prefix(argv[0], cerr)
	    << "could not read symbols from " << opts.lib2_path << "\n";
	  return abigail::tools_utils::ABIDIFF_ERROR;
	}
      if (!(status & abigail::fe_iface::STATUS_OK))
	{
	  emit_prefix(argv[0], cerr)
	    << "could not read file " << opts.lib2_path << "\n";
	  return abigail::tools_utils::ABIDIFF_ERROR;
	}
    }

  abidiff_status s = abigail::tools_utils::ABIDIFF_OK;

  if (opts.weak_mode)
    s = perform_compat_check_in_weak_mode(opts, ctxt,
					  app_corpus,
					  lib1_corpus);
  else
    s = perform_compat_check_in_normal_mode(opts, ctxt,
					    app_corpus,
					    lib1_corpus,
					    lib2_corpus);

  return s;
}
