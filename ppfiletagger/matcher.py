#! /usr/bin/python
# by pts@fazekas.hu at Sun Jan 11 05:56:03 CET 2009

"""<tagquery> matcher library used by rmtimequery.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
"""


# Only standard Python dependencies allowed, for command-line usage.
import re


class BadQuery(Exception):
  """Raised when a <tagquery> is bad (e.g. syntax error)."""


PTAG_TO_SQLITEWORD_RE = re.compile(r'[6789:_]')  # Duplicates base.py.
PTAG_TO_SQLITEWORD_DICT = {  # Duplicates base.py.
  '6': '66',
  '7': '65',
  '8': '64',
  '9': '63',
  ':': '7',
  '_': '8',
}

# Simple superset of UTF-8 words.
# Corresponds to $tagchar_re in ppfiletagger_shell_functions.sh.
TAGVM_RE = re.compile(r'-?(?:v:)?(?:\w|[\xC2-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF4][\x80-\xBF]{3})+\Z')


def QueryToWordData(query):
  """Return SQLite fulltext query converted to filewords.worddata."""
  if not isinstance(query, str): raise TypeError
  return re.sub(
      PTAG_TO_SQLITEWORD_RE,
      (lambda match: PTAG_TO_SQLITEWORD_DICT[match.group(0)]),
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
    self.do_assume_tags_match = True  # True indicates that the SQLite MATCH operator can determine the result, no need additional checks in self.DoesMatch.
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
    for term in terms:
      # TODO(pts): Add ':size>100' as a valid query term.
      if term in ('*', ':tag', ':tagged'):
        self.match_with_tag = True
      elif term in ('-*', '-:tag', ':none'):
        self.match_without_tag = True
      elif term in (':vid', ':video', ':film', ':movie'):
        self.AllowExts(self.VIDEO_EXTS)
      elif term in ('-:vid', '-:video', '-:film', '-:movie'):
        self.DisallowExts(self.VIDEO_EXTS)
      elif term in (':pic', ':picture', ':img', ':image'):
        self.AllowExts(self.IMAGE_EXTS)
      elif term in ('-:pic', '-:picture', '-:img', '-:image'):
        self.DisallowExts(self.IMAGE_EXTS)
      elif term == ':any':  # TODO(pts): Support it.
        continue
      elif term.startswith('*-'):
        raise BadQuery('unsupported *- prefix: ' + term)
      elif self.INVALID_TERM_CHAR_RE.search(term):
        raise BadQuery('query term with forbidden char: ' + term)
      elif ':' in term and not ((term.startswith('v:') and term.rfind(':') == 1) or (term.startswith('-v:') and term.rfind(':') == 2)):
        raise BadQuery('unknown special query term: ' + term)
      elif term.startswith('--'):
        raise BadQuery('query term with double dash: ' + term)
      elif term == '-':
        raise BadQuery('query term is a dash')
      elif not TAGVM_RE.match(term):
        raise BadQuery('invalid tagv syntax: ' + term.lstrip('-'))
      else:
        # Negative tags (starting with '-') are also allowed.
        # TODO(pts): Filter unknown tags.
        if term.startswith('-'):
          self.without_tags.add(term[1:])
        else:
          self.with_tags.add(term)
        pntags.append(term)

    if self.with_tags:
      self.match_with_tag = True
      self.wordlistc = QueryToWordData(' '.join(pntags))
      self.do_assume_tags_match = True
    else:
      self.wordlistc = ''

      if self.without_tags:
        if self.match_with_tag is None:
          # Ask for explicit '*' to avoid accidental slow queries.
          raise BadQuery(
              'please specify \'*\' for negative queries (may be slow)')
        # SQLite3 raises
        # sqlite.OperationalError('SQL logic error or missing database') if
        # only negative tags are specified in a fulltext index.
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
      if not tags and self.match_with_tag:
        return False
      if tags and self.match_without_tag:
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


if __name__ == '__main__':
  import sys
  if len(sys.argv) < 2:
    sys.stderr.write('Usage: %s <tagquery> ["<filetags>" <filename> ...]\n' % sys.argv[0])
    sys.exit(1)
  matcher = Matcher(sys.argv[1])
  keys = sorted(('do_assume_tags_match', 'wordlistc', 'match_with_tag', 'match_without_tag', 'with_any_exts', 'without_exts', 'is_impossible', 'with_tags', 'without_tags'))
  for key in sorted(keys):
    if key == 'is_impossible':
      value = matcher.IsImpossible()
    else:
      value = getattr(matcher, key)
    print 'matcher.%s = %r' % (key, value)
  matcher.do_assume_tags_match = False  # Do a full match.
  i, args = 2, sys.argv
  for i in xrange(2, len(args), 2):
    tags, filename = args[i], args[i + 1]
    print 'match tags=%r filename=%r does_match=%r' % (tags, filename, matcher.DoesMatch(filename, tags))
