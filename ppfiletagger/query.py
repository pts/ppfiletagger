#! /usr/bin/python2.4
# by pts@fazekas.hu at Sun Jan 11 05:56:03 CET 2009

"""Query (search by tag) tool for ppfiletagger.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
"""

__author__ = 'pts@fazekas.hu (Peter Szabo)'

import logging
import re
import sys
import time

from ppfiletagger import matcher  # Import first.
from ppfiletagger import base


class RootInfo(base.RootInfo):
  """Information about a filesystem root directory."""

  __slots__ = ['db', 'root_dir', 'last_scan_at', 'tagdb_name']

  def GenerateFullTextResponse(self, wordlistc, xattr, do_stat):
    """Generate (dir, entry, value) matches, in no particular order."""
    if do_stat:
      fields = ', mtime, size, nlink'
    else:
      fields = ''
    if wordlistc:
      # INDEXED BY applies only to fileattrs. The fulltext index in filewords
      # would be used (hopefully).
      query = ('SELECT dir, entry, value%s '
               'FROM filewords, fileattrs INDEXED BY fileattrs_xattr '
               'WHERE worddata MATCH (?) AND '
               'xattr=? AND filewords.rowid=filewords_rowid' % fields,
               (wordlistc, xattr))
    else:
      query = ('SELECT dir, entry, value%s '
               'FROM fileattrs INDEXED BY fileattrs_xattr '
               'WHERE xattr=?' % fields, (xattr,))
    # TODO: Verify proper use of indexes. 
    for row in self.db.execute(*query):
      yield row


class GlobalInfo(base.GlobalInfo):
  """Queryable info about the indexed state of all mounted filesystems."""

  root_info_class = RootInfo

  def GenerateQueryResponse(self, query, do_stat):
    # TODO: Print warning if tagdb is not up to date.
    # TODO: Accept search_root_dir argument.
    if not isinstance(query, str): raise TypeError
    wordlistc = None
    if not self.roots:
      self.OpenTagDBs(self.ParseMounts())
    else:
      # TODO: do ParseMounts again occasionally
      self.ReopenDBs(do_close_first=False)

    matcher_obj = matcher.Matcher(query)  # May raise matcher.BadQuery.
    if matcher_obj.is_impossible:
      logging.info('impossible query, cannot match any files: %s' % query)
    else:
      if matcher_obj.must_be_untagged:
        raise matcher.BadQuery(
            'query matches only files without tags (no database of those)')
      if not matcher_obj.must_be_tagged:
        raise matcher.BadQuery(
            'query may match files without tags (no database of those)')
      do_assume_match = matcher_obj.do_assume_match
      for scan_root_dir in self.roots:
        root_info = self.roots[scan_root_dir]
        root_slash = root_info.root_dir
        if not root_slash.endswith('/'): root_slash += '/'
        for row in root_info.GenerateFullTextResponse(
            wordlistc=matcher_obj.wordlistc,
            xattr=root_info.FILEWORDS_XATTRS[0], do_stat=do_stat):
          dirname = row[0]
          entry = row[1]
          tags = row[2]
          if dirname == '.':
            filename = root_slash + entry
          else:
            filename = '%s%s/%s' % (root_slash, dirname[2:], entry)
          if do_assume_match or matcher_obj.DoesMatch(filename, tags, False):
            row = list(row)
            row[1] = filename
            yield row


def Usage(argv0):
  return ("Usage: %s [<flag>...] [-]<tag1> [...]  # query `and'\n\n" % argv0 +
          'Flags:\n'
          '--format=tuple\n'
          '--format=name | -n\n'
          '--format=mclist\n'
          '--help\n'
         ).rstrip()


def main(argv):
  use_format = 'tuple'
  i = 1
  while i < len(argv):
    arg = argv[i]
    if arg == '--':
      i += 1
      break
    elif arg == '--format=tuple':
      use_format = 'tuple'
    elif arg == '--format=colon':
      use_format = 'colon'
    elif arg in ('-n', '--format=name', '--format=filename'):
      use_format = 'name'
    elif arg == '--format=mclist':  # Midnight Commander extfs list
      use_format = 'mclist'
    elif arg == '--help':
      print >>sys.stderr, Usage(argv[0])
      return 0
    elif not arg.startswith('--'):
      break
    else:
      print >>sys.stderr, Usage(argv[0])
      print >>sys.stderr, 'error: unknown flag: %s' % arg
      return 1
    i += 1
  if i == len(argv):
    print >>sys.stderr, Usage(argv[0])
    print >>sys.stderr, 'error: missing query'
    return 1
  query = ' '.join(argv[i:])
  if use_format == 'mclist':
    logging.root.setLevel(logging.WARN)  # Prints WARN and ERROR, but not INFO.

  count = 0
  of = sys.stdout
  for row in GlobalInfo().GenerateQueryResponse(
      query=query, do_stat=(use_format == 'mclist')):
    filename = row[1]
    if use_format == 'name':
      of.write(filename + '\n')
    elif use_format == 'tuple':
      of.write(repr((filename, row[2])) + '\n')
    elif use_format == 'colon':
      of.write(''.join((row[2], ' :: ', filename, '\n')))
    elif use_format == 'mclist':
      mtime = row[3]
      size = row[4]
      nlink = row[5]
      basename = filename[1 + filename.rfind('/'):]
      # 4-digit year.
      year, mon, day, hour, min, sec = time.localtime(mtime)[:6]
      at = '%02d/%02d/%d %02d:%02d:%02d' % (mon, day, year, hour, min, sec)
      # mc SUXX: it's not possible to point out to the real filesystem.
      of.write('lrwxrwxrwx %s root root %s %s %s -> %s\n' %
               (nlink, size, at, basename, filename))
    count += 1
  if count:
    logging.info('found result count=%d query=%r' % (count, query))
  else:
    logging.info('no results found query=%r' % (query,))
