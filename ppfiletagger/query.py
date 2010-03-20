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
from ppfiletagger import base


class BadQuery(Exception):
  pass


class RootInfo(base.RootInfo):
  """Information about a filesystem root directory."""

  __slots__ = ['db', 'root_dir', 'last_scan_at', 'tagdb_name']

  def GenerateFullTextResponse(self, wordlistc, xattr):
    """Generate (dir, entry, value) matches, in no particular order."""
    if wordlistc:
      # INDEXED BY applies only to fileattrs. The fulltext index in filewords
      # would be used (hopefully).
      query = ('SELECT dir, entry, value '
               'FROM filewords, fileattrs INDEXED BY fileattrs_xattr '
               'WHERE worddata MATCH (?) AND '
               'xattr=? AND filewords.rowid=filewords_rowid',
               (wordlistc, xattr))
    else:
      query = ('SELECT dir, entry, value '
               'FROM fileattrs INDEXED BY fileattrs_xattr '
               'WHERE xattr=?', (xattr,))
    # TODO: Verify proper use of indexes. 
    for row in self.db.execute(*query):
      yield (row[0], row[1], row[2])  # (dir, entry, value)


def QueryToWordData(query):
  """Return SQLite fulltext query converted to filewords.worddata."""
  if not isinstance(query, str): raise TypeError
  return re.sub(
      RootInfo.PTAG_TO_SQLITEWORD_RE,
      (lambda match: self.PTAG_TO_SQLITEWORD_DICT[match.group(0)]),
      query)



class Matcher(object):
  """Class to match rows against the specified query."""

  __slots__ = ['wordlistc', 'match_with_tag', 'match_without_tag',
               'with_any_exts', 'without_exts', 'with_tags', 'without_tags',
               'do_assume_tags_match']

  INVALID_TERM_CHAR_RE = re.compile('[*?\'"|!&]')
  """Matches characters invalid in query terms."""

  VIDEO_EXTS = set(['avi', 'wmv', 'mpg', 'mpe', 'mpeg', 'mov', 'rm', 'ra',
                    'ram', 'flv', 'mp4', 'ts', 'iso', 'vob', 'fli', 'asf',
                    'asx', 'divx', 'qt', 'flc', 'ogm', 'mkv', 'img', 'vid',
                    'm2ts', 'original', 'rmvb', 'mp2', 'mpa', 'm4v', 'tp',
                    'm1v', 'm2v', 'm3v', 'tvt', '3gp', 'dv', 'flv8', 'flv9'])
  """Lowercase filename extension for video files."""

  IMAGE_EXTS = set(['png', 'jpeg', 'jpg', 'jpe', 'gif', 'tif', 'tiff', 'pcx',
                    'bmp', 'xcf', 'pnm', 'pbm', 'pgm', 'ppm', 'xwd', 'xpm'])
  """Lowercase filename extension for still images."""

  def __init__(self, query):
    self.SetQuery(query)

  def SetQuery(self, query):
    if not isinstance(query, str):
      raise TypeError
    self.do_assume_tags_match = True
    self.wordlistc = None
    self.match_with_tag = None
    self.match_without_tag = False
    self.with_any_exts = None  # Allow anything.
    self.without_exts = set()  # Don't disallow anything.
    terms = query.split()
    if not terms:
      raise BadQuery('empty query')
    # Positive and negative tags.
    pntags = []
    self.with_tags = set()
    self.without_tags = set()  # Without the leading '-'
    has_positive_tag = False
    has_negative_tag = False
    for term in terms:
      # TODO(pts): Add ':size>100' as a valid query term.
      if term in ('*', ':tag'):
        self.match_with_tag = True
      elif term in ('-*', '-:tag'):
        self.match_without_tag = True
      elif term in (':vid', ':video', ':film', ':movie'):
        self.AllowExts(self.VIDEO_EXTS)
      elif term in ('-:vid', '-:video', '-:film', '-:movie'):
        self.DisallowExts(self.VIDEO_EXTS)
      elif term in (':pic', ':picture', ':img', ':image'):
        self.AllowExts(self.IMAGE_EXTS)
      elif term in ('-:pic', '-:picture', '-:img', '-:image'):
        self.DisallowExts(self.IMAGE_EXTS)
      elif self.INVALID_TERM_CHAR_RE.search(term):
        raise BadQuery('query term with forbidden char: ' + term)
      elif ':' in term:
        raise BadQuery('unknown special query term: ' + term)
      elif term.startswith('--'):
        raise BadQuery('query term with double dash: ' + term)
      elif term == '-':
        raise BadQuery('query term is a dash')
      else:
        # Negative tags (starting with '-') are also allowed.
        # TODO(pts): Filter unknown tags.
        if term.startswith('-'):
          has_negative_tag = True
          self.without_tags.add(term[1:])
        else:
          has_positive_tag = True
          self.with_tags.add(term)
        pntags.append(term)

    if has_positive_tag:
      self.match_with_tag = True
      self.wordlistc = QueryToWordData(' '.join(pntags))
      self.do_assume_tags_match = True
    else:
      self.wordlistc = ''

      if has_negative_tag:
        if self.match_with_tag is None:
          # Ask for explicit '*' to avoid accidental slow queries.
          raise BadQuery(
              'please specify \'*\' for negative queries (may be slow)')
        # SQLite3 raises
        # sqlite.OperationalError('SQL logic error or missing database') if
        # if only negative tags are specified in a fulltext index.
        self.do_assume_tags_match = False

  def AllowExts(self, exts):
    if self.with_any_exts is None:
      self.with_any_exts = set(exts)
    else:
      self.with_any_exts.intersection_update(exts)

  def DisallowExts(self, exts):
    self.without_exts.update(exts)

  def IsImpossible(self):
    """Is it impossible that this Matcher ever matches a file?"""
    if self.match_with_tag and self.match_without_tag:
      return True
    if self.with_any_exts is not None:
      if not self.with_any_exts:
        return True
      if self.with_any_exts.intersection(self.without_exts):
        return True
    if self.with_tags.intersection(self.without_tags):
      return True
    return False

  def DoesMatch(self, filename, tags):
    """Does this matcher match a file with the specified filename and tags?

    Args:
      filename: Absolute filename (starting with /).
      tags: String containing positive tags separated by spaces. Can be empty.
    """
    if not isinstance(tags, str):
      raise TypeError
    tags = tags.split()
    if not self.do_assume_tags_match:
      if not tags and (self.with_tags or not self.match_without_tag):
        return False
      if tags and not self.match_with_tag:
        return False
      if self.with_tags.difference(tags):
        return False
      if self.without_tags.intersection(tags):
        return False
    if self.with_any_exts is not None or self.without_exts:
      j = filename.rfind('/')
      if j > 0:
        basename = filename[j + 1:]
      else:
        basename = filename
      j = basename.rfind('.')
      if j > 0:
        ext = basename[j + 1:].lower()
      else:
        ext = basename.lower()
      if self.with_any_exts is not None and ext not in self.with_any_exts:
        return False
      if ext in self.without_exts:
        return False
    return True



class GlobalInfo(base.GlobalInfo):
  """Queryable info about the indexed state of all mounted filesystems."""

  root_info_class = RootInfo

  def GenerateQueryResponse(self, query):
    # TODO: Print warning if tagdb is not up to date.
    # TODO: Accept search_root_dir argument.
    if not isinstance(query, str): raise TypeError
    wordlistc = None
    if not self.roots:
      self.OpenTagDBs(self.ParseMounts())
    else:
      # TODO: do ParseMounts again occasionally
      self.ReopenDBs(do_close_first=False)

    matcher = Matcher(query)  # may raise BadQuery
    if matcher.IsImpossible():
      logging.info('impossible query=%r' % query)
    else:
      if matcher.match_without_tag:
        raise BadQuery(
            'cannot match files without tags (no database of those)')
      for scan_root_dir in self.roots:
        root_info = self.roots[scan_root_dir]
        root_slash = root_info.root_dir
        if not root_slash.endswith('/'): root_slash += '/'
        for dir, entry, tags in root_info.GenerateFullTextResponse(
            wordlistc=matcher.wordlistc, xattr=root_info.FILEWORDS_XATTRS[0]):
          if dir == '.':
            filename = root_slash + entry
          else:
            filename = '%s%s/%s' % (root_slash, dir[2:], entry)
          if matcher.DoesMatch(filename, tags):
            yield filename, tags

def main(argv):
  do_name_only = False
  if len(argv) > 1 and argv[1] == '-n':
    del argv[1]
    do_name_only = True
  if len(argv) <= 1:
    sys.stderr.write("Usage: %s [-n] [-]<tag1> [...]  # query `and'\n" % argv[0])
    return 1
  query = ' '.join(argv[1:])
  count = 0
  for filename, taglistc in GlobalInfo().GenerateQueryResponse(query=query):
    if do_name_only:
      print filename
    else:
      print repr((filename, taglistc))
    count += 1
  if count:
    logging.info('found result count=%d query=%r' % (count, query))
  else:
    logging.info('no results found query=%r' % (query,))
  return
