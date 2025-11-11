// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- mode: C++ -*-
//
// Copyright (C) 2013-2025 Red Hat, Inc.

/// @file

#include <string>
#include <iostream>
#include <fstream>
#include "abg-tools-utils.h"

#include "abg-internal.h"
// <headers defining libabigail's API go under here>
ABG_BEGIN_EXPORT_DECLARATIONS

#include "abg-libxml-utils.h"

ABG_END_EXPORT_DECLARATIONS
// </headers defining libabigail's API>

namespace abigail
{

namespace sptr_utils
{
/// Build and return a shared_ptr for a pointer to xmlTextReader
template<>
shared_ptr<xmlTextReader>
build_sptr<xmlTextReader>(::xmlTextReader *p)
{
  return shared_ptr<xmlTextReader>(p, abigail::xml::textReaderDeleter());
}

/// Build and return a shared_ptr for a pointer to xmlChar
template<>
shared_ptr<xmlChar>
build_sptr<xmlChar>(xmlChar *p)
{
  return shared_ptr<xmlChar>(p, abigail::xml::charDeleter());
}

}//end namespace sptr_utils

namespace xml
{
using std::istream;
using std::ifstream;
using tools_utils::xz_decompressor_type;
using tools_utils::file_type;
using tools_utils::guess_file_type;

// <xmlIO callbacks for xz reading support>


/// This is an xmlIO callback function used in the libxml2 I/O input
/// API to detect if the current handler can provider input
/// functionality for a file designed by a path.
///
/// This function should return 1 iff the file contains XZ-compressed
/// data.
///
/// @param filepath the path to file to consider.
///
/// @return 1 iff the file designated by @p filepath is XZ-compressed.
static int
xz_io_match_cb(const char*filepath)
{
  bool does_match = false;
  file_type t = guess_file_type(filepath, /*look_through_compression=*/false);
  if (t == tools_utils::FILE_TYPE_XZ)
    does_match = true;

  return does_match;
}

/// This is the context used by the xmlIO handler that provides input
/// functionality to the libxml2 I/O input API for XZ-compressed XML
/// files.
struct xz_ctxt_type
{
  // The input XZ-compressed file stream.
  std::unique_ptr<std::ifstream> input_fstream;
  // The custom XZ-decompressor streambuf provided by tools-utils.
  std::unique_ptr<xz_decompressor_type> decompressor_streambuf;
  // The decompressed input stream that we can read from.
  std::unique_ptr<std::istream> decompressed_input_stream;

  xz_ctxt_type() = delete;

  /// Constructor.
  ///
  /// @param is the XZ-compressed input file stream to consider.
  xz_ctxt_type(std::ifstream* is)
    : input_fstream(is),
      decompressor_streambuf(new xz_decompressor_type(*is)),
      decompressed_input_stream(new istream(decompressor_streambuf.get()))
  {}
}; // end struct  xz_ctxt_type.

/// Callback used in the I/O input API of libxml2 to open a file
/// designated by a path and containing XZ-compressed content.
///
/// @param filepath the path to the file to open.  The file should
/// contain XZ-compressed data, as detected by @ref xz_io_match_cb.
///
/// @return a pointer to an instance of @ref xz_ctxt_type if the
/// function could successfully open the file denoted by @p filepath.
/// Please note that this instance of @ref xz_ctxt_type has to be
/// deleted by @ref xz_io_close_cb.
static void*
xz_io_open_cb(const char* filepath)
{
  std::ifstream* s = new std::ifstream(filepath, ifstream::binary);
  if (s->bad())
    {
      delete s;
      return nullptr;
    }

  xz_ctxt_type *ctxt = new xz_ctxt_type(s);
  return ctxt;
}

/// Callback used in the I/O input API of libxml2 to read and
/// decompress data from an XZ-compressed file previously opened by
/// @ref xz_io_open_cb.
///
/// @param context a pointer to the instance of @ref xz_ctxt_type
/// returned by @ref xz_io_open_cb.  That context is used to read and
/// decompress the XZ-compressed data coming from input file.
///
/// @param buffer the buffer where to copy the XZ-decompressed data.
///
/// @param len the length of @p buffer.
///
/// @return the actual number of bytes decompressed and copied into @p
/// buffer.
static int
xz_io_read_cb(void* context, char *buffer, int len)
{
  xz_ctxt_type *ctxt = static_cast<xz_ctxt_type *>(context);
  ctxt->decompressed_input_stream->read(buffer, len);
  int nb_bytes_read = ctxt->decompressed_input_stream->gcount();
  return nb_bytes_read;
}

/// Callback used in the I/O input API of libxml2 to delete the
/// instance of @ref xz_ctxt_type created by @ref xz_io_open_cb and
/// free its associated resources.
///
/// @param context the pointer to the instance of @ref xz_ctxt_type to
/// delete.
///
/// @return 0 iff the operation was successful.
static int
xz_io_close_cb(void* context)
{
  xz_ctxt_type *ctxt = static_cast<xz_ctxt_type*>(context);
  ctxt->decompressed_input_stream.reset();
  ctxt->input_fstream->close();
  ctxt->input_fstream.reset();
  delete ctxt;
  return 0;
}

// </xmlIO callbacks for xz reading support>

/// The initialization function of libxml2 abstraction layer.  This
/// function must be called prior to using any of the libxml2 capabilities.
void
initialize()
{
  LIBXML_TEST_VERSION;
  xmlInitParser();
  xmlRegisterInputCallbacks(xz_io_match_cb, xz_io_open_cb,
			    xz_io_read_cb, xz_io_close_cb);
}

/// Instantiate an xmlTextReader that parses the content of an on-disk
/// file, wrap it into a smart pointer and return it.
///
/// @param path the path to the file to be parsed by the returned
/// instance of xmlTextReader.
reader_sptr
new_reader_from_file(const std::string& path)
{
  reader_sptr p =
    build_sptr(xmlNewTextReaderFilename (path.c_str()));

  return p;
}

/// Instanciate an xmlTextReader that parses the content of an
/// in-memory buffer, wrap it into a smart pointer and return it.
///
/// @param buffer the in-memory buffer to be parsed by the returned
/// instance of xmlTextReader.
reader_sptr
new_reader_from_buffer(const std::string& buffer)
{
  reader_sptr p =
    build_sptr(xmlReaderForMemory(buffer.c_str(),
				  buffer.length(),
				  "", 0, 0));
  return p;
}

/// This is an xmlInputReadCallback, meant to be passed to
/// xmlNewTextReaderForIO.  It reads a number of bytes from an istream.
///
/// @param context an std::istream* cast into a void*.  This is the
/// istream that the xmlTextReader is too read data from.
///
/// @param buffer the buffer where to copy the data read from the
/// input stream.
///
/// @param len the number of byte to read from the input stream and to
/// copy into @p buffer.
///
/// @return the number of bytes read or -1 in case of error.
static int
xml_istream_input_read(void*	context,
		       char*	buffer,
		       int	len)
{
  istream* in = reinterpret_cast<istream*>(context);
  in->read(buffer, len);
  return in->gcount();
}

/// This is an xmlInputCloseCallback, meant to be passed to
/// xmlNewTextReaderForIO.  It's supposed to close the input stream
/// that the xmlTextReader is reading from.  This particular
/// implementation is noop; it does nothing.
///
/// @return 0.
static int
xml_istream_input_close(void*)
{return 0;}

/// Instanciate an xmlTextReader that parses a content coming from an
/// input stream.
///
/// @param in the input stream to consider.
///
/// @return reader_sptr a pointer to the newly instantiated xml
/// reader.
reader_sptr
new_reader_from_istream(std::istream* in)
{
  reader_sptr p =
    build_sptr(xmlReaderForIO(&xml_istream_input_read,
			      &xml_istream_input_close,
			      in, "", 0, 0));
  return p;
}

/// Convert a shared pointer to xmlChar into an std::string.
///
/// If the xmlChar is NULL, set "" to the string.
///
/// @param ssptr the shared point to xmlChar to convert.
///
/// @param s the output string.
///
/// @return true if the shared pointer to xmlChar contained a non NULL
/// string, false otherwise.
bool
xml_char_sptr_to_string(xml_char_sptr ssptr, std::string& s)
{
  bool non_nil = false;
  if (CHAR_STR(ssptr))
    {
      s = CHAR_STR(ssptr);
      non_nil = true;
    }
  else
    {
      s = "";
      non_nil = false;
    }

  return non_nil;
}

/// Return the depth of an xml element node.
///
/// Note that the node must be attached to an XML document.
///
/// @param n the xml to consider.
///
/// @return a positive or zero number for an XML node properly
/// attached to an xml document, -1 otherwise.  Note that the function
/// returns -1 if passed an xml document as well.
int
get_xml_node_depth(xmlNodePtr n)
{
  if (n->type == XML_DOCUMENT_NODE || n->parent == NULL)
    return -1;

  if (n->parent->type == XML_DOCUMENT_NODE)
    return 0;

  return 1 + get_xml_node_depth(n->parent);
}

/// Escape the 5 characters representing the predefined XML entities.
///
/// The resulting entities and their matching characters are:
///
///   &lt; for the character '<', &gt; for the character '>', &apos; for
///   the character ''', &quot; for the character '"', and &amp; for the
///   character '&'.
///
//// @param str the input string to read to search for the characters
//// to escape.
////
//// @param escaped the output string where to write the resulting
//// string that contains the pre-defined characters escaped as
//// predefined entitites.
void
escape_xml_string(const std::string& str,
		  std::string& escaped)
{
  for (std::string::const_iterator i = str.begin(); i != str.end(); ++i)
    switch (*i)
      {
      case '<':
	escaped += "&lt;";
	break;
      case '>':
	escaped += "&gt;";
	break;
      case '&':
	escaped += "&amp;";
	break;
      case '\'':
	escaped += "&apos;";
	break;
      case '"':
	escaped += "&quot;";
	break;
      default:
	escaped += *i;
      }
}

/// Escape the 5 characters representing the predefined XML entities.
///
/// The resulting entities and their matching characters are:
///
///   &lt; for the character '<', &gt; for the character '>', &apos; for
///   the character ''', &quot; for the character '"', and &amp; for the
///   character '&'.
///
//// @param str the input string to read to search for the characters
//// to escape.
////
//// @return the resulting string that contains the pre-defined
//// characters escaped as predefined entitites.
std::string
escape_xml_string(const std::string& str)
{
  std::string result;
  escape_xml_string(str, result);
  return result;
}

/// Escape the '-' character, to avoid having a '--' in a comment.
///
/// The resulting entity for '-' is '&#45;'.
///
//// @param str the input string to read to search for the characters
//// to escape.
////
//// @param escaped the output string where to write the resulting
//// string that contains the pre-defined characters escaped as
//// predefined entitites.
void
escape_xml_comment(const std::string& str,
		   std::string& escaped)
{
  for (std::string::const_iterator i = str.begin(); i != str.end(); ++i)
    switch (*i)
      {
      case '-':
	escaped += "&#45;";
	break;
      default:
	escaped += *i;
      }
}

/// Escape the '-' character, to avoid having a '--' in a comment.
///
/// The resulting entity for '-' is '&#45;'.
///
//// @param str the input string to read to search for the characters
//// to escape.
////
//// @return the resulting string that contains the pre-defined
//// characters escaped as predefined entitites.
std::string
escape_xml_comment(const std::string& str)
{
  std::string result;
  escape_xml_comment(str, result);
  return result;
}

/// Read a string, detect the 5 predefined XML entities it may contain
/// and un-escape them, by writting their corresponding characters
/// back in.  The pre-defined entities are:
///
///   &lt; for the character '<', &gt; for the character '>', &apos; for
///   the character ''', &quot; for the character '"', and &amp; for the
///   character '&'.
///
///   @param str the input XML string to consider.
///
///   @param escaped where to write the resulting un-escaped string.
void
unescape_xml_string(const std::string& str,
		  std::string& escaped)
{
  std::string::size_type i = 0;
  while (i < str.size())
    {
      if (str[i] == '&')
	{
	  if (str[i+1]    == 'l'
	      && str[i+2] == 't'
	      && str[i+3] == ';')
	    {
	      escaped += '<';
	      i+= 4;
	    }
	  else if (str[i+1]    == 'g'
		   && str[i+2] == 't'
		   && str[i+3] == ';')
	    {
	      escaped += '>';
	      i += 4;
	    }
	  else if (str[i+1]    == 'a'
		   && str[i+2] == 'm'
		   && str[i+3] == 'p'
		   && str[i+4] == ';')
	    {
	      escaped += '&';
	      i += 5;
	    }
	  else if (str[i+1]    == 'a'
		   && str[i+2] == 'p'
		   && str[i+3] == 'o'
		   && str[i+4] == 's'
		   && str[i+5] == ';')
	    {
	      escaped += '\'';
	      i += 6;
	    }
	  else if (str[i+1]    == 'q'
		   && str[i+2] == 'u'
		   && str[i+3] == 'o'
		   && str[i+4] == 't'
		   && str[i+5] == ';')
	    {
	      escaped += '"';
	      i += 6;
	    }
	  else
	    {
	      escaped += str[i];
	      ++i;
	    }
	}
      else
	{
	  escaped += str[i];
	  ++i;
	}
    }
}

/// Read a string, detect the 5 predefined XML entities it may contain
/// and un-escape them, by writting their corresponding characters
/// back in.  The pre-defined entities are:
///
///   &lt; for the character '<', &gt; for the character '>', &apos; for
///   the character ''', &quot; for the character '"', and &amp; for the
///   character '&'.
///
///   @param str the input XML string to consider.
///
///   @return escaped where to write the resulting un-escaped string.
std::string
unescape_xml_string(const std::string& str)
{
  std::string result;
  unescape_xml_string(str, result);
  return result;
}

/// Read a string, detect the '#&45;' entity and un-escape it into
/// the '-' character.
///
///   @param str the input XML string to consider.
///
///   @param escaped where to write the resulting un-escaped string.
void
unescape_xml_comment(const std::string& str,
		     std::string& escaped)
{
  std::string::size_type i = 0;
  while (i < str.size())
    {
      if (str[i] == '&'
	  && str[i + 1] == '#'
	  && str[i + 2] == '4'
	  && str[i + 3] == '5'
	  && str[i + 4] == ';')
	{
	  escaped += '-';
	  i += 5;
	}
      else
	{
	  escaped += str[i];
	  ++i;
	}
    }
}

/// Read a string, detect the '#&45;' entity and un-escape it into
/// the '-' character.
///
///   @param str the input XML string to consider.
///
///   @return escaped where to write the resulting un-escaped string.
std::string
unescape_xml_comment(const std::string& str)
{
  std::string result;
  unescape_xml_comment(str, result);
  return result;
}

}//end namespace xml
}//end namespace abigail
