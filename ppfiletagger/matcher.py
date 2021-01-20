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

  # Users of Matcher shouldn't change these directly.
  __slots__ = ('wordlistc', 'must_be_tagged', 'must_be_untagged',
               'with_any_exts', 'without_exts', 'with_tags', 'without_tags',
               'with_other_tags',
               'do_assume_match', 'do_assume_tags_match', 'is_impossible')

  VIDEO_EXTS = set(['avi', 'wmv', 'mpg', 'mpe', 'mpeg', 'mov', 'rm',
                    'ram', 'flv', 'mp4', 'ts', 'iso', 'vob', 'fli', 'asf',
                    'asx', 'divx', 'qt', 'flc', 'ogm', 'mkv', 'img', 'vid',
                    'm2ts', 'original', 'rmvb', 'mp2', 'mpa', 'm4v', 'tp',
                    'm1v', 'm2v', 'm3v', 'tvt', '3gp', 'dv', 'flv8', 'flv9'])
  """Lowercase filename extension for video files."""

  IMAGE_EXTS = set(['png', 'jpeg', 'jpg', 'jpe', 'gif', 'tif', 'tiff', 'pcx',
                    'bmp', 'xcf', 'pnm', 'pbm', 'pgm', 'ppm', 'xwd', 'xpm'])
  """Lowercase filename extension for still images."""

  AUDIO_EXTS = set(['wav', 'au', 'mp3', 'mp2', 'ogg', 'm4a', 'opus', 'flac',
                    'aac', 'ac3', 'dts', 'ape', 'vorbis', 'speex', 'ra', 'mid',
                    'midi', 'mov', 's3m', 'it', 'xt', 'sid', 'ralf', 'aiff',
                    'aifc'])
  """Lowercase filename extension for audio files."""

  def __init__(self, query):
    self.SetQuery(query)

  def SetQuery(self, query):
    if not isinstance(query, str):
      raise TypeError
    # Can the SQLite MATCH operator can determine the final result, without the
    # need for additional checks in self.DoesMatch?
    self.do_assume_match = None
    # Can the SQLite MATCH operator can determine the result of the tag match?
    self.do_assume_tags_match = None
    self.wordlistc = None
    self.must_be_tagged = False
    self.must_be_untagged = False
    self.with_any_exts = None  # Allow anything.
    self.without_exts = set()  # Don't disallow anything.
    if '(' in query or ')' in query:
      raise BadQuery('parentheses not supported in <tagquery>: ' + query)
    if '"' in query or "'" in query:
      raise BadQuery('quotes not supported in <tagquery>: ' + query)
    if '|' in query:
      raise BadQuery('unsupported query operator: |')
    terms = query.split()
    if not terms:
      raise BadQuery('empty query')
    # Positive and negative tags.
    pntags = []
    self.with_tags = set()
    self.without_tags = set()  # Without the leading '-'.
    self.with_other_tags = set()  # Without the leading '*-'.
    def AllowExts(exts):
      if self.with_any_exts is None:
        self.with_any_exts = set(exts)
      else:
        self.with_any_exts.intersection_update(exts)
    def DisallowExts(exts):
      self.without_exts.update(exts)
    for term in terms:
      # TODO(pts): Add ':size>100' as a valid query term.
      if term in ('*', ':tag', ':tagged'):
        self.must_be_tagged = True
      elif term in ('-*', '-:tag', ':none'):
        self.must_be_untagged = True
      elif term in (':vid', ':video', ':film', ':movie'):
        AllowExts(self.VIDEO_EXTS)
      elif term in ('-:vid', '-:video', '-:film', '-:movie'):
        DisallowExts(self.VIDEO_EXTS)
      elif term in (':pic', ':picture', ':img', ':image'):
        AllowExts(self.IMAGE_EXTS)
      elif term in ('-:pic', '-:picture', '-:img', '-:image'):
        DisallowExts(self.IMAGE_EXTS)
      elif term in (':aud', ':audio', ':snd', ':sound'):
        AllowExts(self.AUDIO_EXTS)
      elif term in ('-:aud', '-:audio', '-:snd', '-:sound'):
        DisallowExts(self.AUDIO_EXTS)
      elif term == ':any':
        continue
      elif term.startswith('ext:') or term.startswith('-ext:'):
        is_neg = term.startswith('-')
        term = term.split(':', 1)[1]
        if '-' in term or ':' in term:
          raise BadQuery('ext: term with unsupported character: ' + term)
        term2 = term.replace('/', '')
        if term2 and not TAGVM_RE.match(term2):
          raise BadQuery('invalid ext: term syntax: ' + term)
        term = filter(None, term.lower().split('/'))
        if is_neg:
          DisallowExts(term)
        else:
          AllowExts(term)
      elif term.startswith('*-'):
        term = term[2:]
        if not TAGVM_RE.match(term):
          raise BadQuery('invalid tagv syntax: ' + term)
        self.with_other_tags.add(term)
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

    if self.with_other_tags:
      self.must_be_tagged = True
    if self.must_be_untagged:
      if self.with_tags:
        self.must_be_tagged = True
        self.with_tags.clear()
      self.without_tags.clear()  # Optimization.
    if self.with_tags:
      self.must_be_tagged = True
      self.wordlistc = QueryToWordData(' '.join(pntags))
    else:
      # We don't event try to match negative tags only, it fails with
      # sqlite.OperationalError('SQL logic error or missing database') for
      # the standard query syntax, and it fails with another message for the
      # enhanced query syntax.
      self.wordlistc = ''

    # Is it impossible that this Matcher ever matches a file?
    self.is_impossible = bool(
        (self.must_be_tagged and self.must_be_untagged) or
        self.with_any_exts is not None and (
            not self.with_any_exts or
            self.with_any_exts.intersection(self.without_exts)) or
        self.with_tags.intersection(self.without_tags))

    self.do_assume_tags_match = not self.with_other_tags and bool(
        self.with_tags or not (self.without_tags or self.must_be_untagged))
    self.do_assume_match = bool(self.do_assume_tags_match and (
        self.with_any_exts is None and not self.without_exts))

  def DoesMatch(self, filename, tags, do_full_match):
    """Does this matcher match a file with the specified filename and tags?

    Args:
      filename: Absolute filename (starting with /).
      tags: String containing positive tags separated by spaces. Can be empty.
      do_full_match: bool: if true, match on everything; if false, skip some
          matches assuming that the SQLite MATCH operator has already matched
          self.wordlistc.
    """
    if not do_full_match and self.do_assume_match:
      return True
    if do_full_match or not self.do_assume_tags_match:
      if not isinstance(tags, str):
        raise TypeError
      tags = tags.split()
      if not tags and self.must_be_tagged:
        return False
      if tags and self.must_be_untagged:
        return False
      if self.with_tags.difference(tags):
        return False
      if self.without_tags.intersection(tags):
        return False
      # Checking for non-empty before .issuperset makes it faster.
      if self.with_other_tags and self.with_other_tags.issuperset(tags):
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
  keys = sorted(matcher.__slots__)
  for key in sorted(keys):
    value = getattr(matcher, key)
    print 'matcher.%s = %r' % (key, value)
  i, args = 2, sys.argv
  for i in xrange(2, len(args), 2):
    tags, filename = args[i], args[i + 1]
    print 'match tags=%r filename=%r does_match=%r' % (tags, filename, matcher.DoesMatch(filename, tags, True))
