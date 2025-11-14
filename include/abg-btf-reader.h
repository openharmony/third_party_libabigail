// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- Mode: C++ -*-
//
// Copyright (C) 2022-2025 Red Hat, Inc.
//
// Author: Dodji Seketeli

/// @file
///
/// This file contains the declarations of the front-end to analyze the
/// BTF information contained in an ELF file.

#ifndef __ABG_BTF_READER_H__
#define __ABG_BTF_READER_H__

#include "abg-elf-based-reader.h"

namespace abigail
{

/// Namespace of the reader for the BTF debug information.
namespace btf
{

  /// Create and return a BTF reader (or front-end) which is an instance
  /// of @ref btf::reader.
  ///
  /// @param elf_path the path to the path to the elf file the reader is
  /// to be used for.
  ///
  /// @param debug_info_root_paths a vector to the paths to the
  /// directories under which the debug info is to be found for @p
  /// elf_path.  Pass an empty vector if th debug info is not in a split
  /// file.
  ///
  /// @param environment the environment used by the current context.
  /// This environment contains resources needed by the BTF reader and
  /// by the types and declarations that are to be created later.  Note
  /// that ABI artifacts that are to be compared all need to be created
  /// within the same environment.
  ///
  /// Please also note that the life time of this environment object
  /// must be greater than the life time of the resulting @ref
  /// reader the context uses resources that are allocated in the
  /// environment.
  ///
  /// @param load_all_types if set to false only the types that are
  /// reachable from publicly exported declarations (of functions and
  /// variables) are read.  If set to true then all types found in the
  /// debug information are loaded.
  ///
  /// @param linux_kernel_mode if set to true, then consider the special
  /// linux kernel symbol tables when determining if a symbol is
  /// exported or not.
  ///
  /// @return a smart pointer to the resulting btf::reader.
  elf_based_reader_sptr
  create_reader(const std::string& elf_path,
		const vector<string>& debug_info_root_paths,
		environment& env,
		bool load_all_types = false,
		bool linux_kernel_mode = false);

}//end namespace btf
}//end namespace abigail

#endif //__ABG_BTF_READER_H__
