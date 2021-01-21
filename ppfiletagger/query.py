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
import os
import os.path
import re
import stat
import sys
import time

from ppfiletagger import matcher  # Import first.
from ppfiletagger import base
from ppfiletagger.good_sqlite import sqlite


class RootInfo(base.RootInfo):
  """Information about a filesystem root directory."""


class GlobalInfo(base.GlobalInfo):
  """Queryable info about the indexed state of all mounted filesystems."""

  root_info_class = RootInfo

  @classmethod
  def IsFts3Enhanced(cls, db):
    """Returns bool indicating whether SQLite FTS3 extended query syntax is
    available."""
    # Checks for FTS3 enhanced query syntax:
    # https://www.sqlite.org/fts3.html#_set_operations_using_the_enhanced_query_syntax
    try:
      rows = tuple(db.execute(
          "SELECT 1 FROM filewords WHERE worddata MATCH 'NOT' AND "
          'rowid=0 and rowid<rowid'))
    except sqlite.OperationalError, e:
      if str(e).startswith('malformed MATCH expression:'):
        return True
      raise
    if rows:
      raise RuntimeError('Unexpected rows returned in enhanced test.')
    return False

  @classmethod
  def GetFullTextQuery(cls, wordlistcs, is_fts3_enhanced, xattr, do_stat, dirprefix='', dirupper='', expentry=''):
    """Get query for (dir, entry, value) matches, in no particular order."""
    if do_stat:
      fields = ', mtime, size, nlink'
    else:
      fields = ''
    # INDEXED BY applies only to fileattrs. The FTS3 fulltext index will be
    # used in filewords in the subquery.
    indexed_by, extra_ands, query_params = 'fileattrs_xattr', [], [xattr]
    if wordlistcs:
      if len(wordlistcs) > 1 and is_fts3_enhanced:  # Optimization.
        wordlistcs = [''.join(('(', ') OR ('.join(wordlistcs), ')'))]
      query_params.extend(wordlistcs)
      subqueries = ['SELECT rowid FROM filewords WHERE worddata MATCH ?'] * len(wordlistcs)
      # TODO(pts): Does the number 10 makes sense here (to avoid
      # intermediate rowid set merges)?
      joiner = (' UNION ', ' UNION ALL ')[len(wordlistcs) < 10]
      extra_ands.append(' AND filewords_rowid IN (%s)' % joiner.join(subqueries))
    if dirprefix:
      if expentry:
        # TODO(pts): Don't even consult filewords, do the matching in Python.
        indexed_by = 'fileattrs_nxattr'
        extra_ands.append(' AND dir=? AND entry=?')
        query_params.extend((dirprefix, expentry))
      else:
        # TODO(pts): Maybe it's faster to ignore wordlistc (and thus
        # filewords), and do all the matching in Python. Add a command-line
        # flag.
        extra_ands.append(' AND dir>=? AND dir<?')
        query_params.extend((dirprefix, dirupper))
    query = ('SELECT dir, entry, value%s '
             'FROM fileattrs INDEXED BY %s '
             'WHERE xattr=?%s' %
             (fields, indexed_by, ''.join(extra_ands)))
    return query, query_params

  @classmethod
  def GetDbDir(cls, base_filename):
    """Find database filename by going up from base_filename."""
    try:
      st = os.lstat(base_filename)
    except OSError:
      raise RuntimeError('Search base does not exist: ' + base_filename)
    if stat.S_ISLNK(st.st_mode):
      try:
        st2 = os.stat(base_filename)
      except OSError, e:
        st2 = None
      if st2 and stat.S_ISREG(st2.st_mode):
        st = st2
    if stat.S_ISREG(st.st_mode):
      if base_filename.endswith('/'):
        # Shouldn't happen.
        raise ValueError('Base filename ends with slash: ' + base_filename)
      i = base_filename.rfind('/')
      if i < 0:
        db_dirname, dirprefix, entry = './', [], base_filename
      else:
        db_dirname, dirprefix, entry = base_filename[:i].rstrip('/') + '/', [], base_filename[i + 1:]
    elif stat.S_ISDIR(st.st_mode):
      db_dirname, dirprefix, entry = base_filename.rstrip('/') + '/', [], ''
    else:  # Symlinks are also disallowed.
      raise RuntimeError('Unknown file type in search base: ' + base_filename)
    while True:
      assert db_dirname.endswith('/')
      try:
        os.lstat(db_dirname + cls.TAGDB_NAME)
        break
      except OSError:
        pass
      if db_dirname in ('../', './') or db_dirname.endswith('/../') or db_dirname.endswith('/./'):
        db_dirname = os.path.abspath(db_dirname) + '/'  # Can fail.
        if not db_dirname.startswith('/') or db_dirname.endswith('/../') or db_dirname.endswith('/./'):
          raise ValueError('Bad absolute directory name: ' + db_dirname)
      st = os.lstat(db_dirname)
      if not stat.S_ISDIR(st.st_mode):
        raise RuntimeError('Search base must be a directory: ' + db_dirname)
      i = db_dirname[:-1].rfind('/')
      if i < 0:
        db_dirname = os.path.abspath('.') + '/'  # Can fail.
        if not db_dirname.startswith('/') or db_dirname.endswith('/../') or db_dirname.endswith('/./'):
          raise ValueError('Bad absolute directory name: ' + db_dirname)
        i = db_dirname[:-1].rfind('/')
      if i <= 0:  # Root directory reached.
        raise ValueError('Tag database not found: ' + cls.TAGDB_NAME)
      dirprefix.append(db_dirname[i + 1 : -1])
      db_dirname = db_dirname[:i].rstrip('/') + '/'
    dirprefix.append('.')
    dirprefix.reverse()
    dirprefix = '/'.join(dirprefix)
    return db_dirname.rstrip('/') or '/', dirprefix, entry

  @classmethod
  def GetUpperLimitForPrefix(cls, prefix):
    """Returns a suitable (but not accurate) upper limit corresponding to a
    string prefix, i.e. prefix <= string < upper will be true."""
    if not isinstance(prefix, str):
      raise ValueError
    upper = prefix
    while True:
      if not upper:
        # This won't happen for dirprefix, because it starts with '.'
        raise ValueError('No upper limit for prefix: %r' % prefix)
      if not upper.endswith('\xff'):
        return upper[:-1] + chr(ord(upper[-1]) + 1)
      upper = upper[:-1]

  def GenerateQueryResponse(self, query, do_stat, base_filenames):
    # TODO: Print warning if tagdb is not up to date.
    if not isinstance(query, str): raise TypeError
    if not self.roots:
      if base_filenames:
        subdir_restricts = {}
        for base_filename in base_filenames:
          db_dirname, dirprefix, expentry = self.GetDbDir(base_filename)
          dirupper = ''
          if not expentry:
            dirupper = self.GetUpperLimitForPrefix(dirprefix)
          if db_dirname not in subdir_restricts:
            subdir_restricts[db_dirname] = []
          subdir_restricts[db_dirname].append((dirprefix, dirupper, expentry))
        mounts = sorted(subdir_restricts)
        del db_dirname, dirprefix, dirupper, expentry
      else:
        mounts = self.ParseMounts()
        subdir_restricts = None
      self.OpenTagDBs(mounts)
      if subdir_restricts is not None:
        assert sorted(subdir_restricts) == sorted(self.roots), (
            sorted(subdir_restricts), sorted(self.roots))
      del mounts
    else:
      if base_filenames:
        raise ValueError('Multiple initialization with base_filename.')
      # TODO: do ParseMounts again occasionally
      self.ReopenDBs(do_close_first=False)

    matcher_obj = matcher.Matcher(query)  # May raise matcher.BadQuery.
    if matcher_obj.is_impossible:
      logging.info('impossible query, cannot match any files: %s' % query)
    else:
      if matcher_obj.has_must_be_untagged:
        raise matcher.BadQuery(
            'query attempts to matches files without tags (no database of those)')
      if not matcher_obj.all_must_be_tagged:
        raise matcher.BadQuery(
            'query may match files without tags (no database of those)')
      do_assume_match = matcher_obj.do_assume_match
      wordlistcs = map(base.QueryToWordData, matcher_obj.ftqclauses)
      has_negative = bool([1 for ftqclause in matcher_obj.ftqclauses if '-' in ftqclause])
      is_fts3_enhanced = None
      if not (has_negative or len(wordlistcs) > 1):
        is_fts3_enhanced = False  # Optimization.
      if len(matcher_obj.clauses) == 1:
        does_match_func = matcher_obj.clauses[0].DoesMatch  # Optimization.
      else:
        does_match_func = matcher_obj.DoesMatch
      query_kwargs = None
      for scan_root_dir in self.roots:
        root_info = self.roots[scan_root_dir]
        if is_fts3_enhanced is None:
          is_fts3_enhanced = self.IsFts3Enhanced(root_info.db)
          if is_fts3_enhanced and has_negative:
            # SQLite requires that NOT does not come first, but wordlistc
            # ensures it.
            wordlistcs[:] = (wordlistc.replace(' -', ' NOT ') for wordlistc in wordlistcs)
        if query_kwargs is None:
          query_kwargs = dict(
              wordlistcs=wordlistcs, is_fts3_enhanced=is_fts3_enhanced,
              xattr=root_info.FILEWORDS_XATTRS[0], do_stat=do_stat)
          if subdir_restricts is None:
            query, query_params = self.GetFullTextQuery(**query_kwargs)
            restrict_tuples, good_pairs = (('', '', ''),), None
        if subdir_restricts is not None:
          restrict_tuples = subdir_restricts[root_info.root_dir]
          good_pairs = {}
          for dirprefix, dirupper, expentry in restrict_tuples:
            if expentry:
              pair = (dirprefix, expentry)
              good_pairs[pair] = good_pairs.get(pair, 0) + 1
            else:
              good_pairs = None
              break
          if good_pairs is not None:
            restrict_tuples = (('', '', ''),)
        root_slash = root_info.root_dir
        if not root_slash.endswith('/'): root_slash += '/'
        for dirprefix, dirupper, expentry in restrict_tuples:
          lp = len(dirprefix)
          lp1 = lp + 1
          if subdir_restricts is not None:
            query_kwargs.update(dict(
                dirprefix=dirprefix, dirupper=dirupper, expentry=expentry))
            query, query_params = self.GetFullTextQuery(**query_kwargs)
          for row in root_info.db.execute(query, query_params):
            dirname = row[0]
            entry = row[1]
            tags = row[2]
            if good_pairs is None:
              if expentry and not (dirname == dirprefix and entry == expentry):
                continue
              if dirupper and not (dirname.startswith(dirprefix) and dirname[lp : lp1] in ('', '/')):
                continue
              count = 1
            else:
              count = good_pairs.get((dirname, entry), 0)
              if not count:
                continue
            if do_assume_match or does_match_func(entry, tags, False):
              row = list(row)
              if dirname == '.':
                row[1] = root_slash + entry
              else:
                row[1] = ''.join((root_slash, dirname[2:], '/', entry))
              for _ in xrange(count):
                yield row


def Usage(argv0):
  # Command-line should be similar to _mmfs find.
  return ('%s: searches for matching files, prints list or dump to stdout\n'
          "Usage: %s [<flag> ...] ['<tagquery>'] [<filename> ...]\n"
          'Without a <filename>, indexes on all filesystems are searched.\n'
          'Flags:\n'
          '--tagquery=<tagquery> : Print files with matching tags.\n'
          '--print-empty=yes | --any : Same as --tagquery=:any\n'
          '--print-empty=no | --tagged : Same as --tagquery=:tagged\n'
          '--untagged : Same as --tagquery=:none , prints files without tags.\n'
          '--format=tuple\n'
          '--format=colon\n'
          '--format=name | --firmat=filename | -n (default) : Print filename only.\n'
          '--format=mclist\n'
          '--help : Print this help.\n'
          'It reports an error when searching for files without tags.\n'
          'It follows symlinks.\n'
          % (argv0, argv0)).rstrip()


def main(argv):
  use_format = 'filename'
  query = None
  i = 1
  while i < len(argv):
    arg = argv[i]
    if arg == '--':
      i += 1
      break
    elif arg.startswith('--tagquery='):
      query = arg[arg.find('=') + 1:]
    elif arg in ('--print-empty=yes', '--any'):
      query = ':any'
    elif arg in ('--print-empty=no', '--tagged'):
      query = ':tagged'
    elif arg == '--untagged':
      query = ':none'
    elif arg == '--format=tuple':
      use_format = 'tuple'
    elif arg == '--format=colon':
      use_format = 'colon'
    elif arg in ('-n', '--format=name', '--format=filename'):
      use_format = 'filename'
    elif arg == '--format=mclist':  # Midnight Commander extfs list
      use_format = 'mclist'
    elif arg in ('--sh', '--colon', '--mfi', '--mscan'):
      use_format = arg[2:]
    elif arg == '--help':
      print >>sys.stderr, Usage(argv[0])
      return 0
    elif not arg.startswith('--'):
      break
    else:
      print >>sys.stderr, Usage(argv[0])
      print >>sys.stderr, 'fatal: unknown flag: %s' % arg
      return 1
    i += 1
  if query is None:
    if i >= len(argv):
      print >>sys.stderr, Usage(argv[0])
      print >>sys.stderr, 'fatal: missing query'
      return 1
    query = argv[i]
    i += 1
  base_filenames = argv[i:]
  if use_format == 'mclist':
    logging.root.setLevel(logging.WARN)  # Prints WARN and ERROR, but not INFO.

  count = 0
  of = sys.stdout
  for row in GlobalInfo().GenerateQueryResponse(
      query=query, do_stat=(use_format == 'mclist'), base_filenames=base_filenames):
    filename = row[1]
    if use_format == 'filename':
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
  of.flush()  # Flush before writing the log message below.
  if count:
    logging.info('found result count=%d query=%r' % (count, query))
  else:
    logging.info('no results found query=%r' % (query,))
