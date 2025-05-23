// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- Mode: C++ -*-
//
// Copyright (C) 2013-2023 Red Hat, Inc.
//
// Author: Dodji Seketeli

/// @file

#include "config.h"
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <set>
#include "abg-config.h"
#include "abg-comp-filter.h"
#include "abg-suppression.h"
#include "abg-tools-utils.h"
#include "abg-reader.h"
#include "abg-dwarf-reader.h"
#ifdef WITH_CTF
#include "abg-ctf-reader.h"
#endif

#ifdef WITH_BTF
#include "abg-btf-reader.h"
#endif

using std::vector;
using std::set;
using std::string;
using std::ostream;
using std::cout;
using std::cerr;
using std::shared_ptr;
using abg_compat::optional;
using namespace abigail;
using abigail::ir::environment;
using abigail::ir::environment_sptr;
using abigail::translation_unit;
using abigail::translation_unit_sptr;
using abigail::corpus_sptr;
using abigail::corpus_group_sptr;
using abigail::comparison::translation_unit_diff_sptr;
using abigail::comparison::corpus_diff;
using abigail::comparison::corpus_diff_sptr;
using abigail::comparison::compute_diff;
using abigail::comparison::get_default_harmless_categories_bitmap;
using abigail::comparison::get_default_harmful_categories_bitmap;
using abigail::suppr::suppression_sptr;
using abigail::suppr::suppressions_type;
using abigail::suppr::read_suppressions;

using abigail::tools_utils::emit_prefix;
using abigail::tools_utils::check_file;
using abigail::tools_utils::guess_file_type;
using abigail::tools_utils::gen_suppr_spec_from_headers;
using abigail::tools_utils::gen_suppr_spec_from_kernel_abi_whitelists;
using abigail::tools_utils::load_default_system_suppressions;
using abigail::tools_utils::load_default_user_suppressions;
using abigail::tools_utils::abidiff_status;
using abigail::tools_utils::create_best_elf_based_reader;
using abigail::tools_utils::stick_corpus_and_dependencies_into_corpus_group;
using abigail::tools_utils::stick_corpus_and_binaries_into_corpus_group;
using abigail::tools_utils::add_dependencies_into_corpus_group;
using abigail::tools_utils::get_dependencies;

using namespace abigail;

struct options
{
  bool display_usage;
  bool display_version;
  bool missing_operand;
  string		wrong_option;
  string		file1;
  string		file2;
  vector<string>	suppression_paths;
  vector<string>	kernel_abi_whitelist_paths;
  vector<string>	drop_fn_regex_patterns;
  vector<string>	drop_var_regex_patterns;
  vector<string>	keep_fn_regex_patterns;
  vector<string>	keep_var_regex_patterns;
  vector<string>	headers_dirs1;
  vector<string>        header_files1;
  vector<string>	headers_dirs2;
  vector<string>        header_files2;
  bool			drop_private_types;
  optional<bool>	exported_interfaces_only;
  bool			linux_kernel_mode;
  bool			no_default_supprs;
  bool			no_arch;
  bool			no_corpus;
  bool			ignore_soname;
  bool			leaf_changes_only;
  bool			fail_no_debug_info;
  bool			show_hexadecimal_values;
  bool			show_offsets_sizes_in_bits;
  bool			show_relative_offset_changes;
  bool			show_stats_only;
  bool			show_symtabs;
  bool			show_deleted_fns;
  bool			show_changed_fns;
  bool			show_added_fns;
  bool			show_added_syms;
  bool			show_all_fns;
  bool			show_deleted_vars;
  bool			show_changed_vars;
  bool			show_added_vars;
  bool			show_all_vars;
  bool			show_all_types;
  bool			show_linkage_names;
  bool			show_locs;
  bool			show_harmful_changes;
  bool			show_harmless_changes;
  bool			show_redundant_changes;
  bool			show_symbols_not_referenced_by_debug_info;
  bool			show_impacted_interfaces;
  bool			assume_odr_for_cplusplus;
  bool			leverage_dwarf_factorization;
  bool			perform_change_categorization;
  bool			follow_dependencies;
  bool			list_dependencies;
  bool			dump_diff_tree;
  bool			show_stats;
  bool			do_log;
#ifdef WITH_DEBUG_SELF_COMPARISON
  bool			do_debug_self_comparison;
#endif
#ifdef WITH_DEBUG_TYPE_CANONICALIZATION
  bool			do_debug_type_canonicalization;
#endif
#ifdef WITH_CTF
  bool			use_ctf;
#endif
#ifdef WITH_BTF
  bool			use_btf;
#endif
  vector<char*> di_root_paths1;
  vector<char*> di_root_paths2;
  vector<char**> prepared_di_root_paths1;
  vector<char**> prepared_di_root_paths2;
  vector<string> added_bins_dirs1;
  vector<string> added_bins_dirs2;
  vector<string> added_bins1;
  vector<string> added_bins2;

  options()
    : display_usage(),
      display_version(),
      missing_operand(),
      drop_private_types(false),
      linux_kernel_mode(true),
      no_default_supprs(),
      no_arch(),
      no_corpus(),
      ignore_soname(false),
      leaf_changes_only(),
      fail_no_debug_info(),
      show_hexadecimal_values(),
      show_offsets_sizes_in_bits(true),
      show_relative_offset_changes(true),
      show_stats_only(),
      show_symtabs(),
      show_deleted_fns(),
      show_changed_fns(),
      show_added_fns(),
      show_added_syms(true),
      show_all_fns(true),
      show_deleted_vars(),
      show_changed_vars(),
      show_added_vars(),
      show_all_vars(true),
      show_all_types(false),
      show_linkage_names(true),
      show_locs(true),
      show_harmful_changes(true),
      show_harmless_changes(),
      show_redundant_changes(),
      show_symbols_not_referenced_by_debug_info(true),
      show_impacted_interfaces(),
      assume_odr_for_cplusplus(true),
      leverage_dwarf_factorization(true),
      perform_change_categorization(true),
      follow_dependencies(),
      list_dependencies(),
      dump_diff_tree(),
      show_stats(),
      do_log()
#ifdef WITH_DEBUG_SELF_COMPARISON
    ,
      do_debug_self_comparison()
#endif
#ifdef WITH_DEBUG_TYPE_CANONICALIZATION
    ,
      do_debug_type_canonicalization()
#endif
#ifdef WITH_CTF
    ,
      use_ctf()
#endif
#ifdef WITH_BTF
    ,
      use_btf()
#endif
  {}

  ~options()
  {
    for (vector<char*>::iterator i = di_root_paths1.begin();
	 i != di_root_paths1.end();
	 ++i)
      free(*i);

    for (vector<char*>::iterator i = di_root_paths2.begin();
	 i != di_root_paths2.end();
	 ++i)
      free(*i);

    prepared_di_root_paths1.clear();
    prepared_di_root_paths2.clear();
  }
};//end struct options;

static void
display_usage(const string& prog_name, ostream& out)
{
  emit_prefix(prog_name, out)
    << "usage: " << prog_name << " [options] [<file1> <file2>]\n"
    << " where options can be:\n"
    << " --help|-h  display this message\n "
    << " --version|-v  display program version information and exit\n"
    << " --debug-info-dir1|--d1 <path> the root for the debug info of file1\n"
    << " --debug-info-dir2|--d2 <path> the root for the debug info of file2\n"
    << " --headers-dir1|--hd1 <path>  the path to headers of file1\n"
    << " --header-file1|--hf1 <path>  the path to one header of file1\n"
    << " --headers-dir2|--hd2 <path>  the path to headers of file2\n"
    << " --header-file2|--hf2 <path>  the path to one header of file2\n"
    << " --added-binaries-dir1  the path to the dependencies of file1\n"
    << " --added-binaries-dir2  the path to the dependencies of file2\n"
    << " --add-binaries1 <bin1,bin2,.>. build corpus groups with "
    "extra binaries added to the first one and compare them\n"
    << " --add-binaries2 <bin1,bin2,..> build corpus groups with "
    "extra binaries added to the second one and compare them\n"
    << " --follow-dependencies|--fdeps build corpus groups with the "
    "dependencies of the input files\n"
    << " --list-dependencies|--ldeps show the dependencies of the input files\n"
    << " --drop-private-types  drop private types from "
    "internal representation\n"
    << "  --exported-interfaces-only  analyze exported interfaces only\n"
    << "  --allow-non-exported-interfaces  analyze interfaces that "
    "might not be exported\n"
    << " --no-linux-kernel-mode  don't consider the input binaries as "
       "linux kernel binaries\n"
    << " --kmi-whitelist|-w  path to a "
       "linux kernel abi whitelist\n"
    << " --stat  only display the diff stats\n"
    << " --symtabs  only display the symbol tables of the corpora\n"
    << " --no-default-suppression  don't load any "
       "default suppression specification\n"
    << " --no-architecture  do not take architecture in account\n"
    << " --no-corpus-path  do not take the path to the corpora into account\n"
    << " --ignore-soname  do not take the SONAMEs into account\n"
    << " --fail-no-debug-info  bail out if no debug info was found\n"
    << " --leaf-changes-only|-l  only show leaf changes, "
    "so no change impact analysis (implies --redundant)\n"
    << " --deleted-fns  display deleted public functions\n"
    << " --changed-fns  display changed public functions\n"
    << " --added-fns  display added public functions\n"
    << " --deleted-vars  display deleted global public variables\n"
    << " --changed-vars  display changed global public variables\n"
    << " --added-vars  display added global public variables\n"
    << " --non-reachable-types|-t  consider types non reachable"
    " from public interfaces\n"
    << " --no-added-syms  do not display added functions or variables\n"
    << " --no-linkage-name  do not display linkage names of "
    "added/removed/changed\n"
    << " --no-unreferenced-symbols  do not display changes "
    "about symbols not referenced by debug info\n"
    << " --no-show-locs  do now show location information\n"
    << " --show-bytes  show size and offsets in bytes\n"
    << " --show-bits  show size and offsets in bits\n"
    << " --show-hex  show size and offset in hexadecimal\n"
    << " --show-dec  show size and offset in decimal\n"
    << " --no-show-relative-offset-changes  do not show relative"
    " offset changes\n"
    << " --suppressions|--suppr <path> specify a suppression file\n"
    << " --drop <regex>  drop functions and variables matching a regexp\n"
    << " --drop-fn <regex> drop functions matching a regexp\n"
    << " --drop-var <regex> drop variables matching a regexp\n"
    << " --keep <regex>  keep only functions and variables matching a regex\n"
    << " --keep-fn <regex>  keep only functions matching a regex\n"
    << " --keep-var  <regex>  keep only variables matching a regex\n"
    << " --harmless  display the harmless changes\n"
    << " --no-harmful  do not display the harmful changes\n"
    << " --redundant  display redundant changes\n"
    << " --no-redundant  do not display redundant changes "
    "(this is the default)\n"
    << " --impacted-interfaces  display interfaces impacted by leaf changes\n"
    << " --no-leverage-dwarf-factorization  do not use DWZ optimisations to "
    "speed-up the analysis of the binary\n"
    << " --no-change-categorization | -x don't perform categorization "
    "of changes, for speed purposes\n"
    << " --no-assume-odr-for-cplusplus  do not assume the ODR to speed-up the "
    "analysis of the binary\n"
    << " --dump-diff-tree  emit a debug dump of the internal diff tree to "
    "the error output stream\n"
    <<  " --stats  show statistics about various internal stuff\n"
#ifdef WITH_CTF
    << " --ctf use CTF instead of DWARF in ELF files\n"
#endif
#ifdef WITH_BTF
    << " --btf use BTF instead of DWARF in ELF files\n"
#endif
#ifdef WITH_DEBUG_SELF_COMPARISON
    << " --debug-self-comparison debug the process of comparing "
    "an ABI corpus against itself"
#endif
#ifdef WITH_DEBUG_TYPE_CANONICALIZATION
    << " --debug-tc debug the type canonicalization process"
#endif
    << " --verbose show verbose messages about internal stuff\n";
}

/// Parse the command line and set the options accordingly.
///
/// @param argc the number of words on the command line
///
/// @param argv the command line, which is an array of words.
///
/// @param opts the options data structure.  This is set by the
/// function iff it returns true.
///
/// @return true if the command line could be parsed and opts filed,
/// false otherwise.
bool
parse_command_line(int argc, char* argv[], options& opts)
{
  if (argc < 2)
    return false;

  for (int i = 1; i < argc; ++i)
    {
      if (argv[i][0] != '-')
	{
	  if (opts.file1.empty())
	    opts.file1 = argv[i];
	  else if (opts.file2.empty())
	    opts.file2 = argv[i];
	  else
	    return false;
	}
      else if (!strcmp(argv[i], "--version")
	       || !strcmp(argv[i], "-v"))
	{
	  opts.display_version = true;
	  return true;
	}
      else if (!strcmp(argv[i], "--debug-info-dir1")
	       || !strcmp(argv[i], "--d1"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  // elfutils wants the root path to the debug info to be
	  // absolute.
	  opts.di_root_paths1.push_back
	    (abigail::tools_utils::make_path_absolute_to_be_freed(argv[j]));
	  ++i;
	}
      else if (!strcmp(argv[i], "--debug-info-dir2")
	       || !strcmp(argv[i], "--d2"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  // elfutils wants the root path to the debug info to be
	  // absolute.
	  opts.di_root_paths2.push_back
	    (abigail::tools_utils::make_path_absolute_to_be_freed(argv[j]));
	  ++i;
	}
      else if (!strcmp(argv[i], "--headers-dir1")
	       || !strcmp(argv[i], "--hd1"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  // The user can specify several header files directories for
	  // the first binary.
	  opts.headers_dirs1.push_back(argv[j]);
	  ++i;
	}
      else if (!strcmp(argv[i], "--header-file1")
	       || !strcmp(argv[i], "--hf1"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  opts.header_files1.push_back(argv[j]);
	  ++i;
	}
      else if (!strcmp(argv[i], "--headers-dir2")
	       || !strcmp(argv[i], "--hd2"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  // The user can specify several header files directories for
	  // the first binary.
	  opts.headers_dirs2.push_back(argv[j]);
	  ++i;
	}
      else if (!strcmp(argv[i], "--header-file2")
	       || !strcmp(argv[i], "--hf2"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  opts.header_files2.push_back(argv[j]);
	  ++i;
	}
      else if (!strcmp(argv[i], "--follow-dependencies")
	       || !strcmp(argv[i], "--fdeps"))
	opts.follow_dependencies = true;
      else if (!strcmp(argv[i], "--list-dependencies")
	       || !strcmp(argv[i], "--ldeps"))
	opts.list_dependencies = true;
      else if (!strcmp(argv[i], "--added-binaries-dir1")
	       || !strcmp(argv[i], "--abd1"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  opts.added_bins_dirs1.push_back(argv[j]);
	  ++i;
	}
      else if (!strcmp(argv[i], "--added-binaries-dir2")
	       || !strcmp(argv[i], "--abd2"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  opts.added_bins_dirs2.push_back(argv[j]);
	  ++i;
	}
      else if (!strncmp(argv[i], "--add-binaries1=",
			strlen("--add-binaries1=")))
	tools_utils::get_comma_separated_args_of_option(argv[i],
							"--add-binaries1=",
							opts.added_bins1);
      else if (!strcmp(argv[i], "--add-binaries1"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  string s = argv[j];
	  if (s.find(','))
	    tools_utils::split_string(s, ",", opts.added_bins1);
	  else
	    opts.added_bins1.push_back(s);
	  ++i;
	}
      else if (!strncmp(argv[i], "--add-binaries2=",
			strlen("--add-binaries2=")))
	tools_utils::get_comma_separated_args_of_option(argv[i],
							"--add-binaries2=",
							opts.added_bins2);
      else if (!strcmp(argv[i], "--add-binaries2"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  string s = argv[j];
	  if (s.find(','))
	    tools_utils::split_string(s, ",", opts.added_bins2);
	  else
	    opts.added_bins2.push_back(s);
	  ++i;
	}
      else if (!strcmp(argv[i], "--kmi-whitelist")
	       || !strcmp(argv[i], "-w"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  opts.kernel_abi_whitelist_paths.push_back(argv[j]);
	  ++i;
	}
      else if (!strcmp(argv[i], "--stat"))
	opts.show_stats_only = true;
      else if (!strcmp(argv[i], "--symtabs"))
	opts.show_symtabs = true;
      else if (!strcmp(argv[i], "--help")
	       || !strcmp(argv[i], "-h"))
	{
	  opts.display_usage = true;
	  return true;
	}
      else if (!strcmp(argv[i], "--drop-private-types"))
	opts.drop_private_types = true;
      else if (!strcmp(argv[i], "--exported-interfaces-only"))
	opts.exported_interfaces_only = true;
      else if (!strcmp(argv[i], "--allow-non-exported-interfaces"))
	opts.exported_interfaces_only = false;
      else if (!strcmp(argv[i], "--no-linux-kernel-mode"))
	opts.linux_kernel_mode = false;
      else if (!strcmp(argv[i], "--no-default-suppression"))
	opts.no_default_supprs = true;
      else if (!strcmp(argv[i], "--no-architecture"))
	opts.no_arch = true;
      else if (!strcmp(argv[i], "--no-corpus-path"))
	opts.no_corpus = true;
      else if (!strcmp(argv[i], "--ignore-soname"))
	opts.ignore_soname = true;
      else if (!strcmp(argv[i], "--fail-no-debug-info"))
	opts.fail_no_debug_info = true;
      else if (!strcmp(argv[i], "--leaf-changes-only")
	       ||!strcmp(argv[i], "-l"))
	opts.leaf_changes_only = true;
      else if (!strcmp(argv[i], "--deleted-fns"))
	{
	  opts.show_deleted_fns = true;
	  opts.show_all_fns = false;
	  opts.show_all_vars = false;
	}
      else if (!strcmp(argv[i], "--changed-fns"))
	{
	  opts.show_changed_fns = true;
	  opts.show_all_fns = false;
	  opts.show_all_vars = false;
	}
      else if (!strcmp(argv[i], "--added-fns"))
	{
	  opts.show_added_fns = true;
	  opts.show_all_fns = false;
	  opts.show_all_vars = false;
	}
      else if (!strcmp(argv[i], "--deleted-vars"))
	{
	  opts.show_deleted_vars = true;
	  opts.show_all_fns = false;
	  opts.show_all_vars = false;
	}
      else if (!strcmp(argv[i], "--changed-vars"))
	{
	  opts.show_changed_vars = true;
	  opts.show_all_fns = false;
	  opts.show_all_vars = false;
	}
      else if (!strcmp(argv[i], "--added-vars"))
	{
	  opts.show_added_vars = true;
	  opts.show_all_fns = false;
	  opts.show_all_vars = false;
	}
      else if (!strcmp(argv[i], "--non-reachable-types")
	       || !strcmp(argv[i], "-t"))
	  opts.show_all_types = true;
      else if (!strcmp(argv[i], "--no-added-syms"))
	{
	  opts.show_added_syms = false;
	  opts.show_added_vars = false;
	  opts.show_added_fns = false;

	  // If any of the {changed,deleted}_{vars,fns} is already
	  // specified, --no-added-syms has no further effect.  If it
	  // is the only option specified (as of the time of parsing
	  // it), it shall mean "show everything, except added vars,
	  // fns and unreferenced symbols.
	  if (!(opts.show_changed_fns
		|| opts.show_changed_vars
		|| opts.show_deleted_fns
		|| opts.show_deleted_vars))
	    {
	      opts.show_changed_fns = true;
	      opts.show_changed_vars = true;

	      opts.show_deleted_vars = true;
	      opts.show_deleted_fns = true;
	    }

	  opts.show_all_fns = false;
	  opts.show_all_vars = false;
	}
      else if (!strcmp(argv[i], "--no-linkage-name"))
	opts.show_linkage_names = false;
      else if (!strcmp(argv[i], "--no-unreferenced-symbols"))
	opts.show_symbols_not_referenced_by_debug_info = false;
      else if (!strcmp(argv[i], "--no-show-locs"))
	opts.show_locs = false;
      else if (!strcmp(argv[i], "--show-bytes"))
	opts.show_offsets_sizes_in_bits = false;
      else if (!strcmp(argv[i], "--show-bits"))
	opts.show_offsets_sizes_in_bits = true;
      else if (!strcmp(argv[i], "--show-hex"))
	opts.show_hexadecimal_values = true;
      else if (!strcmp(argv[i], "--show-dec"))
	opts.show_hexadecimal_values = false;
      else if (!strcmp(argv[i], "--no-show-relative-offset-changes"))
	opts.show_relative_offset_changes = false;
      else if (!strcmp(argv[i], "--suppressions")
	       || !strcmp(argv[i], "--suppr"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  opts.suppression_paths.push_back(argv[j]);
	  ++i;
	}
      else if (!strcmp(argv[i], "--drop"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  opts.drop_fn_regex_patterns.push_back(argv[j]);
	  opts.drop_var_regex_patterns.push_back(argv[j]);
	  ++i;
	}
      else if (!strcmp(argv[i], "--drop-fn"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  opts.drop_fn_regex_patterns.push_back(argv[j]);
	  ++i;
	}
      else if (!strcmp(argv[i], "--drop-var"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  opts.drop_var_regex_patterns.push_back(argv[j]);
	  ++i;
	}
      else if (!strcmp(argv[i], "--keep"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  opts.keep_fn_regex_patterns.push_back(argv[j]);
	  opts.keep_var_regex_patterns.push_back(argv[j]);
	  ++i;
	}
      else if (!strcmp(argv[i], "--keep-fn"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  opts.keep_fn_regex_patterns.push_back(argv[j]);
	}
      else if (!strcmp(argv[i], "--keep-var"))
	{
	  int j = i + 1;
	  if (j >= argc)
	    {
	      opts.missing_operand = true;
	      opts.wrong_option = argv[i];
	      return true;
	    }
	  opts.keep_var_regex_patterns.push_back(argv[j]);
	}
      else if (!strcmp(argv[i], "--harmless"))
	opts.show_harmless_changes = true;
      else if (!strcmp(argv[i], "--no-harmful"))
	opts.show_harmful_changes = false;
      else if (!strcmp(argv[i], "--redundant"))
	opts.show_redundant_changes = true;
      else if (!strcmp(argv[i], "--no-redundant"))
	opts.show_redundant_changes = false;
      else if (!strcmp(argv[i], "--impacted-interfaces"))
	opts.show_impacted_interfaces = true;
      else if (!strcmp(argv[i], "--no-leverage-dwarf-factorization"))
	opts.leverage_dwarf_factorization = false;
      else if (!strcmp(argv[i], "--no-change-categorization")
	       || !strcmp(argv[i], "-x"))
	opts.perform_change_categorization = false;
      else if (!strcmp(argv[i], "--no-assume-odr-for-cplusplus"))
	opts.leverage_dwarf_factorization = false;
      else if (!strcmp(argv[i], "--dump-diff-tree"))
	opts.dump_diff_tree = true;
      else if (!strcmp(argv[i], "--stats"))
	opts.show_stats = true;
      else if (!strcmp(argv[i], "--verbose"))
	opts.do_log = true;
#ifdef WITH_CTF
      else if (!strcmp(argv[i], "--ctf"))
        opts.use_ctf = true;
#endif
#ifdef WITH_BTF
      else if (!strcmp(argv[i], "--btf"))
        opts.use_btf = true;
#endif
#ifdef WITH_DEBUG_SELF_COMPARISON
      else if (!strcmp(argv[i], "--debug-self-comparison"))
	opts.do_debug_self_comparison = true;
#endif
#ifdef WITH_DEBUG_TYPE_CANONICALIZATION
      else if (!strcmp(argv[i], "--debug-tc"))
	opts.do_debug_type_canonicalization = true;
#endif
      else
	{
	  if (strlen(argv[i]) >= 2 && argv[i][0] == '-' && argv[i][1] == '-')
	    opts.wrong_option = argv[i];
	  return false;
	}
    }

  return true;
}

/// Display the function symbol tables for the two corpora.
///
/// @param c1 the first corpus to display the symbol table for.
///
/// @param c2 the second corpus to display the symbol table for.
///
/// @param o the output stream to emit the symbol tables to.
static void
display_symtabs(const corpus_sptr c1, const corpus_sptr c2, ostream& o)
{
  o << "size of the functions symtabs: "
    << c1->get_functions().size()
    << " and "
    << c2->get_functions().size()
    << "\n\n";

  if (c1->get_functions().size())
    o << "First functions symbol table\n\n";
  for (abigail::corpus::functions::const_iterator i =
	 c1->get_functions().begin();
       i != c1->get_functions().end();
       ++i)
    o << (*i)->get_pretty_representation() << std::endl;

  if (c1->get_functions().size() != 0)
    o << "\n";

  if (c2->get_functions().size())
    o << "Second functions symbol table\n\n";
  for (abigail::corpus::functions::const_iterator i =
	 c2->get_functions().begin();
       i != c2->get_functions().end();
       ++i)
    o << (*i)->get_pretty_representation() << std::endl;
}

using abigail::comparison::diff_context_sptr;
using abigail::comparison::diff_context;

/// Check that the suppression specification files supplied are
/// present.  If not, emit an error on stderr.
///
/// @param opts the options instance to use.
///
/// @return true if all suppression specification files are present,
/// false otherwise.
static bool
maybe_check_suppression_files(const options& opts)
{
  for (vector<string>::const_iterator i = opts.suppression_paths.begin();
       i != opts.suppression_paths.end();
       ++i)
    if (!check_file(*i, cerr, "abidiff"))
      return false;

  for (vector<string>::const_iterator i =
	 opts.kernel_abi_whitelist_paths.begin();
       i != opts.kernel_abi_whitelist_paths.end();
       ++i)
    if (!check_file(*i, cerr, "abidiff"))
      return false;

  return true;
}

/// Update the diff context from the @ref options data structure.
///
/// @param ctxt the diff context to update.
///
/// @param opts the instance of @ref options to consider.
static void
set_diff_context_from_opts(diff_context_sptr ctxt,
			   options& opts)
{
  ctxt->default_output_stream(&cout);
  ctxt->error_output_stream(&cerr);
  ctxt->perform_change_categorization(opts.perform_change_categorization);
  ctxt->show_leaf_changes_only(opts.leaf_changes_only);
  ctxt->show_hex_values(opts.show_hexadecimal_values);
  ctxt->show_offsets_sizes_in_bits(opts.show_offsets_sizes_in_bits);
  ctxt->show_relative_offset_changes(opts.show_relative_offset_changes);
  ctxt->show_stats_only(opts.show_stats_only);
  ctxt->show_deleted_fns(opts.show_all_fns || opts.show_deleted_fns);
  ctxt->show_changed_fns(opts.show_all_fns || opts.show_changed_fns);
  ctxt->show_added_fns(opts.show_all_fns || opts.show_added_fns);
  ctxt->show_deleted_vars(opts.show_all_vars || opts.show_deleted_vars);
  ctxt->show_changed_vars(opts.show_all_vars || opts.show_changed_vars);
  ctxt->show_added_vars(opts.show_all_vars || opts.show_added_vars);
  ctxt->show_linkage_names(opts.show_linkage_names);
  ctxt->show_locs(opts.show_locs);
  // Intentional logic flip of ignore_soname
  ctxt->show_soname_change(!opts.ignore_soname);
  // So when we are showing only leaf changes, we want to show
  // redundant changes because of this: Suppose several functions have
  // their return type changed from void* to int*.  We want them all
  // to be reported.  In that case the change is not redundant.  As
  // far as user-defined type changes (like struct/class) they are
  // already put inside a map which makes them be non-redundant, so we
  // don't have to worry about that case.
  //
  // TODO: maybe that in this case we should avoid firing the
  // redundancy analysis pass altogether.  That could help save a
  // couple of CPU cycle here and there!
  ctxt->show_redundant_changes(opts.show_redundant_changes
                               || opts.leaf_changes_only);
  ctxt->show_symbols_unreferenced_by_debug_info
    (opts.show_symbols_not_referenced_by_debug_info);
  ctxt->show_added_symbols_unreferenced_by_debug_info
    (opts.show_symbols_not_referenced_by_debug_info && opts.show_added_syms);
  ctxt->show_unreachable_types(opts.show_all_types);
  ctxt->show_impacted_interfaces(opts.show_impacted_interfaces);

  if (!opts.show_harmless_changes)
      ctxt->switch_categories_off(get_default_harmless_categories_bitmap());

  if (!opts.show_harmful_changes)
    ctxt->switch_categories_off(get_default_harmful_categories_bitmap());

  suppressions_type supprs;
  for (vector<string>::const_iterator i = opts.suppression_paths.begin();
       i != opts.suppression_paths.end();
       ++i)
    read_suppressions(*i, supprs);
  ctxt->add_suppressions(supprs);

  if (!opts.no_default_supprs && opts.suppression_paths.empty())
    {
      // Load the default system and user suppressions.
      suppressions_type& supprs = ctxt->suppressions();

      load_default_system_suppressions(supprs);
      load_default_user_suppressions(supprs);
    }

  if (!opts.headers_dirs1.empty() || !opts.header_files1.empty())
    {
      // Generate suppression specification to avoid showing ABI
      // changes on types that are not defined in public headers.
      suppression_sptr suppr =
	gen_suppr_spec_from_headers(opts.headers_dirs1, opts.header_files1);
      if (suppr)
	ctxt->add_suppression(suppr);
    }

  if (!opts.headers_dirs2.empty() || !opts.header_files2.empty())
    {
      // Generate suppression specification to avoid showing ABI
      // changes on types that are not defined in public headers.
      suppression_sptr suppr =
	gen_suppr_spec_from_headers(opts.headers_dirs2, opts.header_files2);
      if (suppr)
	ctxt->add_suppression(suppr);
    }

  ctxt->dump_diff_tree(opts.dump_diff_tree);

  ctxt->do_log(opts.do_log);
}

/// Set a bunch of tunable buttons on the ELF-based reader from the
/// command-line options.
///
/// @param rdr the reader to tune.
///
/// @param opts the command line options.
static void
set_generic_options(abigail::elf_based_reader& rdr, options& opts)
{
  rdr.options().show_stats = opts.show_stats;
  rdr.options().do_log = opts.do_log;
  rdr.options().leverage_dwarf_factorization =
    opts.leverage_dwarf_factorization;
  rdr.options().assume_odr_for_cplusplus =
    opts.assume_odr_for_cplusplus;
}

/// Set suppression specifications to the @p read_context used to load
/// the ABI corpus from the ELF/DWARF file.
///
/// These suppression specifications are going to be applied to drop
/// some ABI artifacts on the floor (while reading the ELF/DWARF file
/// or the native XML ABI file) and thus minimize the size of the
/// resulting ABI corpus.
///
/// @param read_ctxt the read context to apply the suppression
/// specifications to.  Note that the type of this parameter is
/// generic (class template) because in practise, it can be either an
/// dwarf::read_context type or an
/// abigail::abiabixml_reader::reader type.
///
/// @param opts the options where to get the suppression
/// specifications from.
static void
set_suppressions(abigail::fe_iface& reader, const options& opts)
{
  suppressions_type supprs;
  for (vector<string>::const_iterator i = opts.suppression_paths.begin();
       i != opts.suppression_paths.end();
       ++i)
    read_suppressions(*i, supprs);

  if (reader.corpus_path() == opts.file1
      && (!opts.headers_dirs1.empty() || !opts.header_files1.empty()))
    {
      // Generate suppression specification to avoid showing ABI
      // changes on types that are not defined in public headers for
      // the first binary.
      //
      // As these suppression specifications are applied during the
      // corpus loading, they are going to be dropped from the
      // internal representation altogether.
      suppression_sptr suppr =
	gen_suppr_spec_from_headers(opts.headers_dirs1, opts.header_files1);
      if (suppr)
	{
	  if (opts.drop_private_types)
	    suppr->set_drops_artifact_from_ir(true);
	  supprs.push_back(suppr);
	}
    }

  if (reader.corpus_path() == opts.file2
      && (!opts.headers_dirs2.empty() || !opts.header_files2.empty()))
    {
      // Generate suppression specification to avoid showing ABI
      // changes on types that are not defined in public headers for
      // the second binary.
      //
      // As these suppression specifications are applied during the
      // corpus loading, they are going to be dropped from the
      // internal representation altogether.
      suppression_sptr suppr =
	gen_suppr_spec_from_headers(opts.headers_dirs2, opts.header_files2);
      if (suppr)
	{
	  if (opts.drop_private_types)
	    suppr->set_drops_artifact_from_ir(true);
	  supprs.push_back(suppr);
	}
    }

  const suppressions_type& wl_suppr =
      gen_suppr_spec_from_kernel_abi_whitelists(
	  opts.kernel_abi_whitelist_paths);

  supprs.insert(supprs.end(), wl_suppr.begin(), wl_suppr.end());

  reader.add_suppressions(supprs);
}

/// Configure the abigail::xml_reacher::read_context based on the
/// relevant command-line options.
///
/// @param ctxt the read context to configure.
///
/// @param opts the command-line options to configure @p ctxt from.
static void
set_native_xml_reader_options(abigail::fe_iface& rdr,
			      const options& opts)
{
  abixml::consider_types_not_reachable_from_public_interfaces(rdr,
							      opts.show_all_types);
  rdr.options().do_log = opts.do_log;

}

/// Set the regex patterns describing the functions to drop from the
/// symbol table of a given corpus.
///
/// @param opts the options to the regex patterns from.
///
/// @param c the corpus to set the regex patterns into.
static void
set_corpus_keep_drop_regex_patterns(options& opts, corpus_sptr c)
{
  if (!opts.drop_fn_regex_patterns.empty())
    {
      vector<string>& v = opts.drop_fn_regex_patterns;
      vector<string>& p = c->get_regex_patterns_of_fns_to_suppress();
      p.assign(v.begin(), v.end());
    }

  if (!opts.keep_fn_regex_patterns.empty())
    {
      vector<string>& v = opts.keep_fn_regex_patterns;
      vector<string>& p = c->get_regex_patterns_of_fns_to_keep();
      p.assign(v.begin(), v.end());
    }

  if (!opts.drop_var_regex_patterns.empty())
    {
      vector<string>& v = opts.drop_var_regex_patterns;
      vector<string>& p = c->get_regex_patterns_of_vars_to_suppress();
      p.assign(v.begin(), v.end());
    }

 if (!opts.keep_var_regex_patterns.empty())
    {
      vector<string>& v = opts.keep_var_regex_patterns;
      vector<string>& p = c->get_regex_patterns_of_vars_to_keep();
      p.assign(v.begin(), v.end());
    }
}

/// This function sets diff context options that are specific to
/// kernel module interface comparison.
///
/// @param ctxt the diff context to consider.
static void
adjust_diff_context_for_kmidiff(diff_context &ctxt)
{
  ctxt.show_linkage_names(false);
}

/// Convert options::di_root_paths{1,2} into
/// options::prepared_di_root_paths{1,2} which is the suitable type
/// format that the dwarf_reader expects.
///
/// @param o the options to consider.
static void
prepare_di_root_paths(options& o)
{
  abigail::tools_utils::convert_char_stars_to_char_star_stars
    (o.di_root_paths1, o.prepared_di_root_paths1);

  abigail::tools_utils::convert_char_stars_to_char_star_stars
    (o.di_root_paths2, o.prepared_di_root_paths2);
}

/// Emit an appropriate error message if necessary, given an error
/// code.
///
/// To emit the appropriate error message the function might need to
/// access the context in which the (ELF) input file was being loaded,
/// if it's present.
///
/// @param status_code the status code returned after trying to load
/// the input file.
///
/// @param ctxt the context used to load the ELF file, if we still
/// have it.  If this is nil, then it's ignored.
///
/// @param prog_name the name of the current program.  This is
/// important as it's used in the error message.
///
/// @param input_file_name the name of the input file that we are
/// tryin to load.
///
/// @param debug_info_dir1 if non nil, then this points to the path of
/// the root debug info directory of the first binary that we are
/// trying to load..  If nil, then it's ignored.
///
/// @param debug_info_dir2 if non nil, then this points to the path of
/// the root debug info directory of the second binary that we are
/// trying to load..  If nil, then it's ignored.
///
/// @return abigail::tools_utils::ABIDIFF_ERROR if an error was
/// detected, abigail::tools_utils::ABIDIFF_OK otherwise.
static abigail::tools_utils::abidiff_status
handle_error(abigail::fe_iface::status status_code,
	     const abigail::elf_based_reader* rdr,
	     const string& prog_name,
	     const options& opts)
{
  if (!(status_code & abigail::fe_iface::STATUS_OK)
      || status_code & abigail::fe_iface::STATUS_DEBUG_INFO_NOT_FOUND
      || status_code & abigail::fe_iface::STATUS_ALT_DEBUG_INFO_NOT_FOUND)
    {
      emit_prefix(prog_name, cerr)
	<< "failed to read input file " << opts.file1 << "\n";

      if (status_code & abigail::fe_iface::STATUS_DEBUG_INFO_NOT_FOUND)
	{
	  emit_prefix(prog_name, cerr) <<
	    "could not find the debug info\n";
	  {
	    if (opts.prepared_di_root_paths1.empty() == 0)
	      emit_prefix(prog_name, cerr)
		<< "Maybe you should consider using the "
		"--debug-info-dir1 option to tell me about the "
		"root directory of the debuginfo? "
		"(e.g, --debug-info-dir1 /usr/lib/debug)\n";
	    else
	      {
		emit_prefix(prog_name, cerr)
		  << "Maybe the root path to the debug information '";
		for (vector<char**>::const_iterator i
		       = opts.prepared_di_root_paths1.begin();
		     i != opts.prepared_di_root_paths1.end();
		     ++i)
		  {
		    if (i != opts.prepared_di_root_paths1.end())
		      cerr << ", ";
		    cerr << **i;
		  }
		cerr << "' is wrong?\n";
	      }
	  }

	  {
	    if (opts.prepared_di_root_paths2.empty())
	      emit_prefix(prog_name, cerr)
		<< "Maybe you should consider using the "
		"--debug-info-dir2 option to tell me about the "
		"root directory of the debuginfo? "
		"(e.g, --debug-info-dir2 /usr/lib/debug)\n";
	    else
	      {
		emit_prefix(prog_name, cerr)
		  << "Maybe the root path to the debug information '";
		for (vector<char**>::const_iterator i
		       = opts.prepared_di_root_paths2.begin();
		     i != opts.prepared_di_root_paths2.end();
		     ++i)
		  {
		    if (i != opts.prepared_di_root_paths2.end())
		      cerr << ", ";
		    cerr << **i;
		  }
		  cerr << "' is wrong?\n";
	      }
	  }
	}

      if (status_code & abigail::fe_iface::STATUS_ALT_DEBUG_INFO_NOT_FOUND)
	{
	  emit_prefix(prog_name, cerr)
	    << "could not find the alternate debug info file";

	  if (!rdr->alternate_dwarf_debug_info_path().empty())
	    cerr << " at: "
		 << rdr->alternate_dwarf_debug_info_path();
	  cerr << "\n";
	}

      if (status_code & abigail::fe_iface::STATUS_NO_SYMBOLS_FOUND)
	emit_prefix(prog_name, cerr)
	  << "could not find the ELF symbols in the file '"
	  << opts.file1
	  << "'\n";

      return abigail::tools_utils::ABIDIFF_ERROR;
    }

  return abigail::tools_utils::ABIDIFF_OK;
}

/// Emit an error message saying that the two files have incompatible
/// format versions.
///
/// @param file_path1 the first file path to consider.
///
/// @param version1 the second version to consider.
///
/// @param file_path2 the second file path to consider.
///
/// @param version2 the second version to consider.
///
/// @param prog_name the name of the current program.
static void
emit_incompatible_format_version_error_message(const string& file_path1,
					       const string& version1,
					       const string& file_path2,
					       const string& version2,
					       const string& prog_name)
{
  emit_prefix(prog_name, cerr)
    << "incompatible format version between the two input files:\n"
    << "'" << file_path1 << "' (" << version1 << ")\n"
    << "and\n"
    << "'" << file_path2 << "' (" << version2 << ")\n";
}

/// Display the dependencies of two corpora.
///
/// @param prog_name the name of the current abidiff program.
///
/// @param corp1 the first corpus to consider.
///
/// @param corp2 the second corpus to consider.
///
/// @param deps1 the dependencies to display.
///
/// @param deps2 the dependencies to display.
static void
display_dependencies(const string& prog_name,
		     const corpus_sptr& corp1,
		     const corpus_sptr& corp2,
		     const set<string>& deps1,
		     const set<string>& deps2)
{
  if (deps1.empty())
    emit_prefix(prog_name, cout)
    << "No dependencies found for '" << corp1->get_path() << "':\n";
  else
    {
      emit_prefix(prog_name, cout)
	<< "dependencies of '" << corp1->get_path() << "':\n\t";

      int n = 0;
      for (const auto& dep : deps1)
	{
	  if (n)
	    cout << ", ";
	  cout << dep;
	  ++n;
	}
      cout << "\n";
    }

  if (deps2.empty())
    emit_prefix(prog_name, cout)
      << "No dependencies found for '" << corp2->get_path() << "':\n";
  else
    {
      emit_prefix(prog_name, cout)
	<< "dependencies of '" << corp2->get_path() << "':\n\t";

      int n = 0;
      for (const auto& dep : deps2)
	{
	  if (n)
	    cout << ", ";
	  cout << dep;
	  ++n;
	}
      cout << "\n";
    }
}

int
main(int argc, char* argv[])
{
  options opts;
  if (!parse_command_line(argc, argv, opts))
    {
      emit_prefix(argv[0], cerr)
	<< "unrecognized option: "
	<< opts.wrong_option << "\n"
	<< "try the --help option for more information\n";
      return (abigail::tools_utils::ABIDIFF_USAGE_ERROR
	      | abigail::tools_utils::ABIDIFF_ERROR);
    }

  if (opts.missing_operand)
    {
      emit_prefix(argv[0], cerr)
	<< "missing operand to option: " << opts.wrong_option <<"\n"
	<< "try the --help option for more information\n";
      return (abigail::tools_utils::ABIDIFF_USAGE_ERROR
	      | abigail::tools_utils::ABIDIFF_ERROR);
    }

  if (opts.display_usage)
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

  prepare_di_root_paths(opts);

  if (!maybe_check_suppression_files(opts))
    return (abigail::tools_utils::ABIDIFF_USAGE_ERROR
	    | abigail::tools_utils::ABIDIFF_ERROR);

  abidiff_status status = abigail::tools_utils::ABIDIFF_OK;
  if (!opts.file1.empty() && !opts.file2.empty())
    {
      if (!check_file(opts.file1, cerr))
	return abigail::tools_utils::ABIDIFF_ERROR;

      if (!check_file(opts.file2, cerr))
	return abigail::tools_utils::ABIDIFF_ERROR;

      abigail::tools_utils::file_type t1_type, t2_type;

      t1_type = guess_file_type(opts.file1);
      t2_type = guess_file_type(opts.file2);

      environment env;
      if (opts.exported_interfaces_only.has_value())
	env.analyze_exported_interfaces_only(*opts.exported_interfaces_only);

#ifdef WITH_DEBUG_SELF_COMPARISON
	    if (opts.do_debug_self_comparison)
	      env.self_comparison_debug_is_on(true);
#endif
#ifdef WITH_DEBUG_TYPE_CANONICALIZATION
	    if (opts.do_debug_type_canonicalization)
	      env.debug_type_canonicalization_is_on(true);
#endif
      translation_unit_sptr t1, t2;
      abigail::fe_iface::status c1_status =
	abigail::fe_iface::STATUS_OK,
	c2_status = abigail::fe_iface::STATUS_OK;
      corpus_sptr c1, c2;
      corpus_group_sptr g1, g2;
      bool files_suppressed = false;

      diff_context_sptr ctxt(new diff_context);
      set_diff_context_from_opts(ctxt, opts);
      suppressions_type& supprs = ctxt->suppressions();
      files_suppressed = (file_is_suppressed(opts.file1, supprs)
			  || file_is_suppressed(opts.file2, supprs));

      if (files_suppressed)
	// We don't have to compare anything because a user
	// suppression specification file instructs us to avoid
	// loading either one of the input files.
	return abigail::tools_utils::ABIDIFF_OK;

      switch (t1_type)
	{
	case abigail::tools_utils::FILE_TYPE_UNKNOWN:
	  emit_prefix(argv[0], cerr)
	    << "Unknown content type for file " << opts.file1 << "\n";
	  return abigail::tools_utils::ABIDIFF_ERROR;
	  break;
	case abigail::tools_utils::FILE_TYPE_NATIVE_BI:
	  t1 = abixml::read_translation_unit_from_file(opts.file1,
								       env);
	  break;
	case abigail::tools_utils::FILE_TYPE_ELF: // fall through
	case abigail::tools_utils::FILE_TYPE_AR:
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
	    abigail::elf_based_reader_sptr rdr =
	      create_best_elf_based_reader(opts.file1,
					   opts.prepared_di_root_paths1,
					   env, requested_fe_kind,
					   opts.show_all_types,
					   opts.linux_kernel_mode);
            ABG_ASSERT(rdr);
	    set_generic_options(*rdr, opts);
	    set_suppressions(*rdr, opts);
	    c1 = rdr->read_corpus(c1_status);

	    if (!c1
		|| (opts.fail_no_debug_info
		    && (c1_status & abigail::fe_iface::STATUS_ALT_DEBUG_INFO_NOT_FOUND)
		    && (c1_status & abigail::fe_iface::STATUS_DEBUG_INFO_NOT_FOUND)))
	      return handle_error(c1_status, rdr.get(),
				  argv[0], opts);

	    if (!opts.added_bins1.empty())
	      g1 = stick_corpus_and_binaries_into_corpus_group(rdr, c1,
							       opts.added_bins1,
							       opts.added_bins_dirs1);
	    if (opts.follow_dependencies)
	      {
		if (g1)
		  add_dependencies_into_corpus_group(rdr, *c1,
						     opts.added_bins_dirs1,
						     *g1);
		else
		  g1 = stick_corpus_and_dependencies_into_corpus_group(rdr, c1,
								       opts.added_bins_dirs1);
	      }
	  }
	  break;
	case abigail::tools_utils::FILE_TYPE_XML_CORPUS:
	  {
	    abigail::fe_iface_sptr rdr =
	      abixml::create_reader(opts.file1, env);
	    assert(rdr);
	    set_suppressions(*rdr, opts);
	    set_native_xml_reader_options(*rdr, opts);
	    c1 = rdr->read_corpus(c1_status);
	    if (!c1)
	      return handle_error(c1_status, /*ctxt=*/0, argv[0], opts);
	  }
	  break;
	case abigail::tools_utils::FILE_TYPE_XML_CORPUS_GROUP:
	  {
	    abigail::fe_iface_sptr rdr =
	      abixml::create_reader(opts.file1, env);
	    assert(rdr);
	    set_suppressions(*rdr, opts);
	    set_native_xml_reader_options(*rdr, opts);
	    g1 = abixml::read_corpus_group_from_input(*rdr);
	    if (!g1)
	      return handle_error(c1_status, /*ctxt=*/0,
				  argv[0], opts);
	  }
	  break;
	case abigail::tools_utils::FILE_TYPE_RPM:
	case abigail::tools_utils::FILE_TYPE_SRPM:
	case abigail::tools_utils::FILE_TYPE_DEB:
	case abigail::tools_utils::FILE_TYPE_DIR:
	case abigail::tools_utils::FILE_TYPE_TAR:
	  break;
	}

      switch (t2_type)
	{
	case abigail::tools_utils::FILE_TYPE_UNKNOWN:
	  emit_prefix(argv[0], cerr)
	    << "Unknown content type for file " << opts.file2 << "\n";
	  return abigail::tools_utils::ABIDIFF_ERROR;
	  break;
	case abigail::tools_utils::FILE_TYPE_NATIVE_BI:
	  t2 = abixml::read_translation_unit_from_file(opts.file2,
								       env);
	  break;
	case abigail::tools_utils::FILE_TYPE_ELF: // Fall through
	case abigail::tools_utils::FILE_TYPE_AR:
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
            abigail::elf_based_reader_sptr rdr =
	      create_best_elf_based_reader(opts.file2,
					   opts.prepared_di_root_paths2,
					   env, requested_fe_kind,
					   opts.show_all_types,
					   opts.linux_kernel_mode);
            ABG_ASSERT(rdr);

	    set_generic_options(*rdr, opts);
	    set_suppressions(*rdr, opts);

	    c2 = rdr->read_corpus(c2_status);

	    if (!c2
		|| (opts.fail_no_debug_info
		    && (c2_status & abigail::fe_iface::STATUS_ALT_DEBUG_INFO_NOT_FOUND)
		    && (c2_status & abigail::fe_iface::STATUS_DEBUG_INFO_NOT_FOUND)))
	      return handle_error(c2_status, rdr.get(), argv[0], opts);

	  if (!opts.added_bins2.empty())
	    g2 = stick_corpus_and_binaries_into_corpus_group(rdr, c2,
							     opts.added_bins2,
							     opts.added_bins_dirs2);
	  if (opts.follow_dependencies)
	    {
	      if (g2)
		add_dependencies_into_corpus_group(rdr, *c2,
						   opts.added_bins_dirs2,
						   *g2);
	      else
		g2 = stick_corpus_and_dependencies_into_corpus_group(rdr, c2,
								     opts.added_bins_dirs2);
	    }
	  }
	  break;
	case abigail::tools_utils::FILE_TYPE_XML_CORPUS:
	  {
	    abigail::fe_iface_sptr rdr = abixml::create_reader(opts.file2, env);
	    assert(rdr);
	    set_suppressions(*rdr, opts);
	    set_native_xml_reader_options(*rdr, opts);
	    c2 = rdr->read_corpus(c2_status);
	    if (!c2)
	      return handle_error(c2_status, /*ctxt=*/0, argv[0], opts);

	  }
	  break;
	case abigail::tools_utils::FILE_TYPE_XML_CORPUS_GROUP:
	  {
	    abigail::fe_iface_sptr rdr = abixml::create_reader(opts.file2, env);
	    assert(rdr);
	    set_suppressions(*rdr, opts);
	    set_native_xml_reader_options(*rdr, opts);
	    g2 = abixml::read_corpus_group_from_input(*rdr);
	    if (!g2)
	      return handle_error(c2_status, /*ctxt=*/0, argv[0], opts);
	  }
	  break;
	case abigail::tools_utils::FILE_TYPE_RPM:
	case abigail::tools_utils::FILE_TYPE_SRPM:
	case abigail::tools_utils::FILE_TYPE_DEB:
	case abigail::tools_utils::FILE_TYPE_DIR:
	case abigail::tools_utils::FILE_TYPE_TAR:
	  break;
	}

      if (!opts.added_bins1.empty()
	  || !opts.added_bins2.empty())
	{
	  // We were requested to compare a set of binaries against
	  // another set of binaries.  Let's make sure we construct
	  // two ABI construct groups in all cases.

	  if (!g1 && c1)
	    {
	      // We don't have a corpus group for the first argument.
	      // Let's build one and stick the ABI corpus at hand in
	      // it.
	      g1.reset(new corpus_group(c1->get_environment(),
					c1->get_path()));
	      g1->add_corpus(c1);
	    }

	  if (!g2 && c2)
	    {
	      // We don't have a corpus group for the second argument.
	      // Let's build one and stick the ABI corpus at hand in
	      // it.
	      g2.reset(new corpus_group(c2->get_environment(),
					c2->get_path()));
	      g2->add_corpus(c1);
	    }
	}

      if (!!c1 != !!c2
	  || !!t1 != !!t2
	  || !!g1 != !!g2)
	{
	  emit_prefix(argv[0], cerr)
	    << "the two input should be of the same kind\n";
	  return abigail::tools_utils::ABIDIFF_ERROR;
	}

      if (opts.no_arch)
	{
	  if (c1)
	    c1->set_architecture_name("");
	  if (c2)
	    c2->set_architecture_name("");
	}
      if (opts.no_corpus)
	{
	  if (c1)
	    c1->set_path("");
	  if (c2)
	    c2->set_path("");
	}

      if (t1)
	{
	  tools_utils::timer t;
	  if (opts.do_log)
	    {
	      t.start();
	      std::cerr << "Compute diff ...\n";
	    }

	  translation_unit_diff_sptr diff = compute_diff(t1, t2, ctxt);

	  if (opts.do_log)
	    {
	      t.stop();
	      std::cerr << "diff computed!:" << t << "\n";
	    }

	  if (diff->has_changes())
	    {
	      tools_utils::timer t;
	      if (opts.do_log)
		{
		  t.start();
		  std::cerr << "Computing the report ...\n";
		}

	      diff->report(cout);

	      if (opts.do_log)
		{
		  t.stop();
		  std::cerr << "Report computed!:" << t << "\n";
		}
	    }
	}
      else if (g1)
	{
	  if (opts.show_symtabs)
	    {
	      display_symtabs(c1, c2, cout);
	      return abigail::tools_utils::ABIDIFF_OK;
	    }

	  const auto g1_version = g1->get_format_major_version_number();
	  const auto g2_version = g2->get_format_major_version_number();
	  if (g1_version != g2_version)
	    {
	      emit_incompatible_format_version_error_message(opts.file1,
							     g1_version,
							     opts.file2,
							     g2_version,
							     argv[0]);
	      return abigail::tools_utils::ABIDIFF_ERROR;
	    }

	  adjust_diff_context_for_kmidiff(*ctxt);
	  tools_utils::timer t;
	  if (opts.do_log)
	    {
	      t.start();
	      std::cerr << "Compute diff ...\n";
	    }

	  corpus_diff_sptr diff = compute_diff(g1, g2, ctxt);

	  if (opts.do_log)
	    {
	      t.stop();
	      diff->do_log(true);
	      std::cerr << "diff computed!:" << t << "\n";
	    }

	  if (opts.do_log)
	    {
	      std::cerr << "Computing net changes ...\n";
	      t.start();
	    }

	  if (diff->has_net_changes())
	    status = abigail::tools_utils::ABIDIFF_ABI_CHANGE;
	  if (opts.do_log)
	    {
	      t.stop();
	      std::cerr << "net changes computed!: "<< t << "\n";
	    }

	  if (opts.do_log)
	    {
	      t.start();
	      std::cerr << "Computing incompatible changes ...\n";
	    }

	  if (diff->has_incompatible_changes())
	    status |= abigail::tools_utils::ABIDIFF_ABI_INCOMPATIBLE_CHANGE;

	  if (opts.do_log)
	    {
	      t.stop();
	      std::cerr << "incompatible changes computed!: "<< t << "\n";
	    }

	  if (opts.do_log)
	    {
	      t.start();
	      std::cerr << "Computing changes ...\n";
	    }

	  if (diff->has_changes())
	    {
	      if (opts.do_log)
		{
		  t.stop();
		  std::cerr << "changes computed!: "<< t << "\n";
		}

	      if (opts.do_log)
		{
		  t.start();
		  std::cerr << "Computing report ...\n";
		}

	      diff->report(cout);

	      if (opts.do_log)
		{
		  t.stop();
		  std::cerr << "Report computed!:" << t << "\n";
		}
	    }
	  else
	    {
	      if (opts.do_log)
		{
		  t.stop();
		  std::cerr << "changes computed!: "<< t << "\n";
		}
	    }

	  if (opts.list_dependencies)
	    {
	      set<string> deps1, deps2;
	      get_dependencies(*c1, opts.added_bins_dirs1, deps1);
	      get_dependencies(*c2, opts.added_bins_dirs2, deps2);
	      display_dependencies(argv[0], c1, c2, deps1, deps2);
	    }
	}
      else if (c1)
	{
	  if (opts.show_symtabs)
	    {
	      display_symtabs(c1, c2, cout);
	      return abigail::tools_utils::ABIDIFF_OK;
	    }

	  if (opts.list_dependencies)
	    {
	      set<string> deps1, deps2;
	      get_dependencies(*c1, opts.added_bins_dirs1, deps1);
	      get_dependencies(*c2, opts.added_bins_dirs2, deps2);
	      display_dependencies(argv[0], c1, c2, deps1, deps2);
	      return abigail::tools_utils::ABIDIFF_OK;
	    }
	  const auto c1_version = c1->get_format_major_version_number();
	  const auto c2_version = c2->get_format_major_version_number();
	  if (c1_version != c2_version)
	    {
	      emit_incompatible_format_version_error_message(opts.file1,
							     c1_version,
							     opts.file2,
							     c2_version,
							     argv[0]);
	      return abigail::tools_utils::ABIDIFF_ERROR;
	    }

	  set_corpus_keep_drop_regex_patterns(opts, c1);
	  set_corpus_keep_drop_regex_patterns(opts, c2);

	  tools_utils::timer t;
	  if (opts.do_log)
	    {
	      t.start();
	      std::cerr << "Compute diff ...\n";
	    }

	  corpus_diff_sptr diff = compute_diff(c1, c2, ctxt);

	  if (opts.do_log)
	    {
	      t.stop();
	      std::cerr << "diff computed!:" << t << "\n";
	    }

	  if (opts.do_log)
	    {
	      t.start();
	      std::cerr << "Computing net changes ...\n";
	    }

	  if (diff->has_net_changes())
	    {
	      if (opts.do_log)
		{
		  t.stop();
		  std::cerr << "net changes computed!: "<< t << "\n";
		}
	      status = abigail::tools_utils::ABIDIFF_ABI_CHANGE;
	    }

	  if (opts.do_log)
	    {
	      t.start();
	      std::cerr << "Computing incompatible changes ...\n";
	    }

	  if (diff->has_incompatible_changes())
	    {
	      if (opts.do_log)
		{
		  t.stop();
		  std::cerr << "incompatible changes computed!: "<< t << "\n";
		}
	      status |= abigail::tools_utils::ABIDIFF_ABI_INCOMPATIBLE_CHANGE;
	    }

	  if (opts.do_log)
	    {
	      t.start();
	      std::cerr << "Computing changes ...\n";
	    }

	  if (diff->has_changes())
	    {
	      if (opts.do_log)
		{
		  t.stop();
		  std::cerr << "changes computed!: "<< t << "\n";
		}

	      if (opts.do_log)
		{
		  t.start();
		  std::cerr << "Computing report ...\n";
		}

	      diff->report(cout);

	      if (opts.do_log)
		{
		  t.stop();
		  std::cerr << "Report computed!:" << t << "\n";
		}
	    }
	}
      else
	status = abigail::tools_utils::ABIDIFF_ERROR;
    }

  return status;
}

#ifdef __ABIGAIL_IN_THE_DEBUGGER__

/// Emit a textual representation of a given @ref corpus_diff tree to
/// stdout.
///
/// This is useful when debugging this program.
///
/// @param diff_tree the diff tree to emit a textual representation
/// for.
void
print_diff_tree(abigail::comparison::corpus_diff* diff_tree)
{
  print_diff_tree(diff_tree, std::cout);
}

/// Emit a textual representation of a given @ref corpus_diff tree to
/// stdout.
///
/// This is useful when debugging this program.
///
/// @param diff_tree the diff tree to emit a textual representation
/// for.
void
print_diff_tree(abigail::comparison::corpus_diff_sptr diff_tree)
{
  print_diff_tree(diff_tree, std::cout);
}

/// Emit a textual representation of a given @ref corpus_diff tree to
/// stdout.
///
/// This is useful when debugging this program.
///
/// @param diff_tree the diff tree to emit a textual representation
/// for.
void
print_diff_tree(abigail::comparison::diff_sptr diff_tree)
{
  print_diff_tree(diff_tree.get(), std::cout);
}

/// Emit a textual representation of a given @ref diff tree to
/// stdout.
///
/// This is useful when debugging this program.
///
/// @param diff_tree the diff tree to emit a textual representation
/// for.
void
print_diff_tree(abigail::comparison::diff* diff_tree)
{
  print_diff_tree(diff_tree, std::cout);
}
#endif // __ABIGAIL_IN_THE_DEBUGGER__
