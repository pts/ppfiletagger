#! /usr/bin/python2.4
# by pts@fazekas.hu at Sun Jan 11 05:56:03 CET 2009

import logging
import sys

from pts.rmtimetools import base


class RootInfo(base.RootInfo):
  """Information about a filesystem root directory."""

  __slots__ = ['db', 'root_dir', 'last_scan_at', 'tagdb_name']

  def GenerateTagsResponse(self, wordlistc, xattr):
    """Generate (dir, entry, value) matches, in no particular order."""
    # TODO: Verify proper use of indexes. 
    for row in self.db.execute(
        'SELECT dir, entry, value '
        'FROM filewords, fileattrs INDEXED BY fileattrs_xattr '
        'WHERE worddata MATCH (?) AND '
        'xattr=? AND filewords.rowid=filewords_rowid', (wordlistc, xattr)):
      yield (row[0], row[1], row[2])  # (dir, entry, value)


class GlobalInfo(base.GlobalInfo):
  """Queryable info about the indexed state of all mounted filesystems."""

  root_info_class = RootInfo

  def GenerateTagsResponse(self, tags, xattr='tags'):
    # TODO: Print warning if tagdb is not up to date.
    # TODO: Accept search_root_dir argument.
    if not isinstance(tags, str): raise TypeError
    if not isinstance(xattr, str): raise TypeError
    wordlistc = None
    if not self.roots:
      self.OpenTagDBs(self.ParseMounts())
    else:
      # TODO: do ParseMounts again occasionally
      self.ReopenDBs(do_close_first=False)

    for scan_root_dir in self.roots:
      root_info = self.roots[scan_root_dir]
      if wordlistc is None:
        wordlistc = root_info.ValueToWordData(tags)
      root_slash = root_info.root_dir
      if not root_slash.endswith('/'): root_slash += '/'
      for dir, entry, value in root_info.GenerateTagsResponse(
          wordlistc=wordlistc, xattr=xattr):
        if dir == '.':
          filename = root_slash + entry
        else:
          filename = '%s%s/%s' % (root_slash, dir[2:], entry)
        yield filename, value

def main(argv):
  if len(argv) <= 1:
    sys.stderr.write("Usage: %s <tag1> [...]  # query `and'\n" % argv[0])
    return 1
  tags = ' '.join(argv[1:])
  count = 0
  for filename, taglistc in GlobalInfo().GenerateTagsResponse(tags=tags):
    print repr((filename, taglistc))
    count += 1
  if count:
    logging.info('found result count=%d tags=%r' % (count, tags))
  else:
    logging.info('no results found tags=%r' % (tags,))
  return
