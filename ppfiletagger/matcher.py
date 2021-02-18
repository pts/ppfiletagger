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


# Simple superset of UTF-8 words.
# Corresponds to $tagchar_re in ppfiletagger_shell_functions.sh.
TAGVM_RE = re.compile(r'-?(?:v:)?(?:\w|[\xC2-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF4][\x80-\xBF]{3})+\Z')

def GetFtqclause(with_tags, without_tags):
  """Returns full-text query clause with positives first."""
  # Matching with only negative terms in SQLite would fail with
  # sqlite.OperationalError('SQL logic error or missing database') for
  # the standard query syntax, and it fails with another message for the
  # enhanced query syntax.
  if with_tags:
    return ' '.join(sorted(with_tags) +
                    sorted('-' + tag for tag in without_tags))
  return ''


def GetExtensionLower(filename):
  j = filename.rfind('/')
  if j > 0:
    filename = filename[j + 1:]
  j = filename.rfind('.')
  if j > 0:
    return filename[j + 1:].lower()
  else:
    return filename.lower()


class Clause(object):
  """Class to parse a query clause (without the `|' operator)."""

  # Users of Clause shouldn't change these directly.
  __slots__ = ('must_be_tagged', 'must_be_untagged', 'ftqclause',
               'with_any_exts', 'without_exts', 'with_tags', 'without_tags',
               'with_other_tags',
               'do_assume_match', 'do_assume_tags_match', 'is_impossible')

  VIDEO_EXTS = set(['avi', 'wmv', 'mpg', 'mpe', 'mpeg', 'mov', 'rm', 'webm',
                    'ram', 'flv', 'mp4', 'ts', 'iso', 'vob', 'fli', 'asf',
                    'asx', 'divx', 'qt', 'flc', 'ogm', 'mkv', 'img', 'vid',
                    'm2ts', 'original', 'rmvb', 'mp2', 'mpa', 'm4v', 'tp',
                    'm1v', 'm2v', 'm3v', 'tvt', '3gp', 'dv', 'flv8', 'flv9'])
  """Lowercase filename extension for video files."""

  IMAGE_EXTS = set(['png', 'jpeg', 'jpg', 'jpe', 'gif', 'tif', 'tiff', 'pcx',
                    'bmp', 'xcf', 'pnm', 'pbm', 'pgm', 'ppm', 'xwd', 'xpm',
                    'pam', 'psd', 'miff', 'webp', 'heif', 'heifs', 'heic',
                    'heics', 'avci', 'avcs', 'avif', 'avifs', 'mng', 'apng',
                    'ico', 'jxr', 'wdp', 'hdp', 'jp2', 'j2k', 'jpf', 'jpm',
                    'jpg2', 'j2c', 'jpc', 'jpx', 'mj2'])
  """Lowercase filename extension for still images."""

  AUDIO_EXTS = set(['wav', 'au', 'mp3', 'mp2', 'ogg', 'm4a', 'opus', 'flac',
                    'aac', 'ac3', 'dts', 'ape', 'vorbis', 'speex', 'ra', 'mid',
                    'midi', 'mov', 's3m', 'it', 'xt', 'sid', 'ralf', 'aiff',
                    'aifc'])
  """Lowercase filename extension for audio files."""

  def __init__(self, clause_str):
    self.SetQuery(clause_str)

  def SetQuery(self, clause_str):
    if not isinstance(clause_str, str):
      raise TypeError
    if '(' in clause_str or ')' in clause_str:
      raise BadQuery('parentheses not supported in <tagquery>: ' + clause_str)
    if '"' in clause_str or "'" in clause_str:
      raise BadQuery('quotes not supported in <tagquery>: ' + clause_str)
    if '|' in clause_str:
      raise BadQuery('unsupported query operator in clause: |')
    terms = clause_str.split()
    if not terms:
      raise BadQuery('empty query clause')
    self.must_be_tagged = False
    self.must_be_untagged = False
    self.with_any_exts = None  # Allow anything.
    self.without_exts = set()  # Don't disallow anything.
    # Positive and negative tags.
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
      elif term in (':pic', ':picture', ':img', ':image', ':photo'):
        AllowExts(self.IMAGE_EXTS)
      elif term in ('-:pic', '-:picture', '-:img', '-:image', '-:photo'):
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
    if self.with_tags or self.with_other_tags:
      self.must_be_tagged = True
    if self.must_be_untagged:
      self.with_tags.clear()  # Optimization after setting self.must_be_tagged.
      self.without_tags.clear()  # Optimization.
      self.with_other_tags.clear()  # Optimization.
    if self.with_any_exts is not None:
      self.with_any_exts.difference_update(self.without_exts)
      self.without_exts.clear()  # It's enough to check the positive.

    # Is it impossible that this Clause ever matches a file?
    self.is_impossible = bool(
        (self.must_be_tagged and self.must_be_untagged) or
        (self.with_any_exts is not None and not self.with_any_exts) or
        self.with_tags.intersection(self.without_tags))
    # Can the SQLite MATCH operator determine the result of the tag match,
    # provided that the file is tagged?
    self.do_assume_tags_match = not self.with_other_tags and bool(
        self.with_tags or not (self.without_tags or self.must_be_untagged))
    # Can the SQLite MATCH operator determine the final result,
    # provided that the file is tagged?
    self.do_assume_match = bool(self.do_assume_tags_match and (
        self.with_any_exts is None and not self.without_exts))
    self.ftqclause = GetFtqclause(self.with_tags, self.without_tags)

  def DoesMatch(
      self, filename, tags, do_full_match,
      _have_isdisjoint=getattr(set(), 'isdisjoint', None) is not None):
    """Does this Clause match a file with the specified filename and tags?

    Args:
      filename: Absolute filename (starting with /).
      tags: String containing positive tags separated by whitespace (or
          already split). Can be empty or whitespace-only.
      do_full_match: bool: If true, match on everything; if false, skip some
          matches assuming that the SQLite MATCH operator has already matched
          and tags is not empty (or whitespace-only).
    """
    if not do_full_match and self.do_assume_match:
      return True
    if do_full_match or not self.do_assume_tags_match:
      if not isinstance(tags, str):
        tags = tags.split()
      if tags:
        if self.must_be_untagged:
          return False
        #tags = set(tags)  # The conversion usually makes thje 3 checks below slower.
        # Checking for non-empty before .issuperset etc. makes it faster.
        if self.with_tags and not self.with_tags.issubset(tags):
          return False
        if self.without_tags and (
            (_have_isdisjoint and not self.without_tags.isdisjoint(tags)) or
            self.without_tags.intersection(tags)):
          return False
        if self.with_other_tags and self.with_other_tags.issuperset(tags):
          return False
      elif self.must_be_tagged:
        # No need to check self.with_tags or self.with_other_tags, because if
        # they are nonempty, then self.must_be_tagged is also True.
        return False
    if self.with_any_exts is not None or self.without_exts:
      ext = GetExtensionLower(filename)
      if self.with_any_exts is not None and ext not in self.with_any_exts:
        return False
      if ext in self.without_exts:
        return False
    return True


  def DoesMatchTags(
      self, tags_seq, do_full_match,
      _have_isdisjoint=getattr(set(), 'isdisjoint', None) is not None):
    """Does this Clause match a file with the specified tags?

    Args:
      tags_seq: Sequence of str containing positive tags. Can be empty.
      do_full_match: bool. If true, match on everything; if false, skip some
          matches assuming that the SQLite MATCH operator has already matched
          and tags is not empty.
    """
    if do_full_match or not self.do_assume_tags_match:
      tags = tags_seq
      if tags:
        if self.must_be_untagged:
          return False
        #tags = set(tags)  # The conversion usually makes thje 3 checks below slower.
        # Checking for non-empty before .issuperset etc. makes it faster.
        if self.with_tags and not self.with_tags.issubset(tags):
          return False
        if self.without_tags and (
            (_have_isdisjoint and not self.without_tags.isdisjoint(tags)) or
            self.without_tags.intersection(tags)):
          return False
        if self.with_other_tags and self.with_other_tags.issuperset(tags):
          return False
      elif self.must_be_tagged:
        # No need to check self.with_tags or self.with_other_tags, because if
        # they are nonempty, then self.must_be_tagged is also True.
        return False
    return True


class Matcher(object):
  """Class to match rows against the specified query."""

  # Users of Matcher shouldn't change these directly.
  __slots__ = ('clauses', 'do_assume_match', 'is_impossible',
               'ftqclauses', 'is_multiple_ftqclauses',
               'all_must_be_tagged', 'has_must_be_untagged', 'has_match_on_ext')

  def __init__(self, query):
    self.SetQuery(query)

  @classmethod
  def SimplifyClauses(cls, clauses):
    clauses = [clause for clause in clauses if not clause.is_impossible]
    for clause in clauses:
      if not (clause.must_be_tagged or clause.must_be_untagged or clause.with_any_exts is not None or clause.without_exts or clause.with_tags or clause.without_tags or clause.with_other_tags):
        clauses[:] = (clause,)  # Query matches any file.
        return clauses
    just_tagged_clause = None
    for clause in clauses:
      if clause.must_be_tagged and not (clause.must_be_untagged or clause.with_any_exts is not None or clause.without_exts or clause.with_tags or clause.without_tags or clause.with_other_tags):
        just_tagged_clause = clause
        break
    just_untagged_clause = None
    for clause in clauses:
      if clause.must_be_untagged and not (clause.with_any_exts is not None or clause.without_exts):
        just_untagged_clause = clause
        break
    if just_tagged_clause and just_untagged_clause:
      clauses[:] = [Clause(':any')]  # Query matches any file.
    elif just_tagged_clause:
      clauses[:] = [clause for clause in clauses if clause.must_be_untagged]
      clauses[:0] = (just_tagged_clause,)  # Easy match, put it first.
    elif just_untagged_clause:
      clauses[:] = [clause for clause in clauses if clause.must_be_tagged]
      clauses[:0] = (just_untagged_clause,)  # Easy match, put it first.
    return clauses

  def SetQuery(self, query):
    if not isinstance(query, str):
      raise TypeError
    if not query.strip():
      raise BadQuery('empty query')
    self.clauses = clauses = self.SimplifyClauses(map(Clause, query.split('|')))
    self.is_impossible = not clauses
    self.all_must_be_tagged = not [1 for clause in clauses if not clause.must_be_tagged]
    self.has_must_be_untagged = bool([1 for clause in clauses if clause.must_be_untagged])
    self.has_match_on_ext = bool([1 for clause in clauses if clause.with_any_exts is not None or clause.without_exts])
    if clauses:
      common_with_tags, common_without_tags = (
          set(clauses[0].with_tags), set(clauses[0].without_tags))
      for clause in clauses:
        common_with_tags.intersection_update(clause.with_tags)
        common_without_tags.intersection_update(clause.without_tags)
      common_ftqclause = GetFtqclause(common_with_tags, common_without_tags)
      ftqclauses = set(clause.ftqclause for clause in clauses)
      self.is_multiple_ftqclauses = len(ftqclauses) > 1
      if '' in ftqclauses:
        assert not common_ftqclause
        self.ftqclauses = []
      elif common_ftqclause in ftqclauses:
        self.ftqclauses = [common_ftqclause]  # Optimization: `foo bar | bar' to `bar'.
      else:
        self.ftqclauses = sorted(ftqclauses)
    else:
      self.ftqclauses, self.is_multiple_ftqclauses = [], False
    self.do_assume_match = not (self.is_impossible or self.has_match_on_ext or [1 for clause in clauses if not clause.do_assume_match])

  def DoesMatch(self, filename, tags, do_full_match):
    """Does this Matcher match a file with the specified filename and tags?

    Args:
      filename: Absolute filename (starting with /).
      tags: String containing positive tags separated by whitespace. Can be empty
          or whitespace-only.
      do_full_match: bool: if true, match on everything; if false, skip some
          matches assuming that the SQLite MATCH operator has already matched
          and tags is not empty (or whitespace-only).
    """
    if not do_full_match and self.do_assume_match:
      return True
    if not isinstance(tags, str):
      raise TypeError
    tags, clauses = tags.split(), self.clauses
    if self.is_multiple_ftqclauses:
      do_full_match = True
    if self.has_match_on_ext:
      ext = GetExtensionLower(filename)
      for clause in clauses:
        if (clause.DoesMatchTags(tags, do_full_match) and
            (clause.with_any_exts is None or ext in clause.with_any_exts) and
            ext not in clause.without_exts):
          return True
    else:  # Optimization.
      for clause in clauses:
        if clause.DoesMatchTags(tags, do_full_match):
          return True  # Any of the clauses matches, then the self matches.
    return False


if __name__ == '__main__':
  import sys
  if len(sys.argv) < 2:
    sys.stderr.write(
        '%s: debug tool for matching tags against queries\n'
        'Usage: %s <tagquery> ["<filetags>" <filename> ...]\n'
        % (sys.argv[0], sys.argv[0]))
    sys.exit(1)
  query = sys.argv[1]
  if '|' in query:
    matcher, name = Matcher(query), 'matcher'
  else:
    matcher, name = Clause(query), 'clause'
  keys = sorted(matcher.__slots__)
  for key in keys:
    value = getattr(matcher, key)
    if key == 'clauses':
      output = ['[\n']
      for i, clause in enumerate(value):
        for key2 in sorted(clause.__slots__):
          value2 = getattr(clause, key2)
          output.append('  clause[%d].%s = %r\n' % (i, key2, value2))
        output.append('  ,\n')
      if value:
        output.pop()
      output.append(']')
      value = ''.join(output)
    else:
      value = repr(value)
    print '%s.%s = %s' % (name, key, value)
  i, args = 2, sys.argv
  for i in xrange(2, len(args), 2):
    tags, filename = args[i], args[i + 1]
    print 'match tags=%r filename=%r does_match=%r' % (tags, filename, matcher.DoesMatch(filename, tags, True))
