#! /usr/bin/python2.4
# by pts@fazekas.hu at Wed Jan  7 06:22:51 CET 2009

"""Scanner tool to build tags.sqlite files of ppfiletagger.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

The scanner should not be run as root (to restrict the effects of
security vulnerabilities).

TODO: Remove files in phantom directories: /mnt/arc/d/E
      How were these created at the first place?
"""

__author__ = 'pts@fazekas.hu (Peter Szabo)'

import errno
import logging
import math
import os
import select
import stat
import time
from ppfiletagger import good_xattr
from ppfiletagger import base


class StackEntry(object):
  """An entry on the Scanner.ScanRootDir stack."""

  __slots__ = ['dir', 'sibling_entries', 'up', 'ino']

  def __init__(self, dir, ino=None, sibling_entries=(), up=False):
    # String holding a directory name.
    self.dir = str(dir)
    # A boolean indicating whether we've already descended to the children of
    # this entry.
    self.up = bool(up)
    # Inode number of self.dir, or None if not known yet.
    if ino is None:
      self.ino = None
    else:
      self.ino = int(ino)
    # A list holding names of directory entries in the parent of self.dir.
    # Only those entries are listed which (recursively) contain files with
    # xattrs.
    self.sibling_entries = list(sibling_entries)

  def __repr__(self):
    buf = ['StackEntry(dir=', repr(self.dir), ', ino=', repr(self.ino)]
    if self.sibling_entries:
      buf.append(', sibling_entries=')
      buf.append(repr(self.sibling_entries))
    if self.up:
      buf.append(', up=True')
    buf.append(')')
    return ''.join(buf)


class RootInfo(base.RootInfo):
  """Information about a filesystem root directory."""

  def UpdateOrInsertManyByName(self, db, table, dicts,
      update_count=0, insert_count=0, cursor=None):
    """Update or insert many rows by (dir, entry, xattr).

    Args:
      db: An SQLite connection.
      table: Name of the table.
      dicts: Sequence of dicts, each with the same key, each having the
        same string keys, including 'dir', 'entry' and 'xattr'.
    Returns:
      (update_count, insert_count)
    """
    keys = None
    do_close_cursor = False
    for adict in dicts:
      if keys is None:
        keys = sorted(adict)
        assert 'nlink' in adict
        assert 'dir' in adict
        assert 'filewords_rowid' in adict
        assert adict['filewords_rowid'] is None
        has_entry = 'entry' in adict
        has_xattr = 'xattr' in adict
        update_keys = list(keys)
        update_keys.remove('dir')
        update_keys.remove('filewords_rowid')
        if has_entry: update_keys.remove('entry')
        if has_xattr: update_keys.remove('xattr')
        assert update_keys
        update_assignments = ', '.join(['%s=:%s' % (key, key)
            for key in update_keys])
        if cursor is None:
          cursor = db.cursor()
          do_close_cursor = True
        and_entry = ''
        if has_entry: and_entry = ' AND entry=:entry'
        and_xattr = ''
        if has_xattr: and_xattr = ' AND xattr=:xattr'
        # We could escape table or field names, this would be too much work.
        update_sql = ('UPDATE %s SET %s WHERE dir=:dir%s%s' %
            (table, update_assignments, and_entry, and_xattr))
        insert_sql = 'INSERT INTO %s (%s) VALUES (%s)' % (
            (table, ', '.join(keys), ', '.join([':' + key for key in keys])))
      else:
        assert sorted(adict) == keys, 'keys mismatch: new=%r vs old=%r' % (
            (sorted(adict), keys))

      if adict['xattr'] in self.FILEWORDS_XATTRS:
        worddata = self.ValueToWordData(adict['value'])
        adict = dict(adict)  # Shallow copy. Imp: speed up.
      else:
        worddata = None

      #print (update_sql, adict)
      cursor.execute(update_sql, adict)
      if cursor.rowcount == 0:
        if worddata is not None:
          cursor.execute(
              'INSERT INTO filewords (worddata) VALUES (?)', (worddata,))
          insert_count += 1
          adict['filewords_rowid'] = cursor.lastrowid
        cursor.execute(insert_sql, adict)
        insert_count += 1
      else:
        # Increase even if no column changed.
        assert cursor.rowcount == 1
        do_update_again = adict['nlink'] > 1
        if worddata is not None:
          rows = tuple(cursor.execute(
              'SELECT filewords_rowid FROM %s INDEXED BY %s_nxattr '
              'WHERE dir=:dir%s%s' % (table, table, and_entry, and_xattr),
              adict))
          if rows:
            assert len(rows) == 1
            cursor.execute('UPDATE filewords SET worddata=? WHERE rowid=?',
                (worddata, rows[0][0]))
            if cursor.rowcount:
              update_count += 1
            else:
              cursor.execute(
                  'INSERT INTO filewords (worddata) VALUES (?)', (worddata,))
              insert_count += 1
              adict['filewords_rowid'] = cursor.lastrowid
              update_assignments += ', filewords_rowid=:filewords_rowid'
              do_update_again = True
            
        if adict['nlink'] > 1:
          # Update all files with the same adict['ino'].
          # This SQL updates the original row as well, never mind.
          cursor.execute('UPDATE %s INDEXED BY %s_ino SET %s WHERE ino=:ino' %
              (table, table, update_assignments), adict)
          update_count += cursor.rowcount
        else:
          update_count += 1
    if do_close_cursor: cursor.close()
    return (update_count, insert_count)

  def UpdateDirs(self, cursor, adict, do_delete,
      update_count=0, insert_count=0, delete_count=0):
    assert adict['ino'] is not None
    if do_delete:
      cursor.execute('DELETE FROM dirs WHERE dir=:dir', adict)
      delete_count += cursor.rowcount
    else:
      cursor.execute('DELETE FROM dirs INDEXED BY dirs_ino '
          'WHERE ino=:ino AND dir<>:dir', adict)
      cursor.execute('UPDATE dirs INDEXED BY dirs_dir '
          'SET entrylist=:entrylist, at=:at, '
          'ino=:ino WHERE dir=:dir', adict)
      if cursor.rowcount:
        update_count += 1
      else:
        cursor.execute('INSERT INTO dirs (dir, entrylist, at, ino) '
            'VALUES (:dir, :entrylist, :at, :ino)', adict)
        insert_count += 1
    return update_count, insert_count, delete_count

  def ScanRootDir(self, now, do_incremental, get_xattr_items_func):
    """Scan filesystem root directory root_dir to db at now.

    Returns:
      Boolean indicating whether a new scan is necessary at
      math.floor(now) + 1.
    """
    root_dir = self.root_dir
    if self.last_scan_at is None:
      ats = tuple(self.db.execute("SELECT at FROM lastscans WHERE which=''"))
      if ats:
        prev_scan_at = ats[0][0]
        prev_scan_floor = math.floor(prev_scan_at)
      else:
        prev_scan_at = prev_scan_floor = float('-inf')
    else:
      prev_scan_at = self.last_scan_at
      prev_scan_floor = math.floor(prev_scan_at)
    self.had_last_incremental = (
        do_incremental and prev_scan_at != float('-inf'))

    # Return quickly if nothing has changed.
    try:
      st = os.stat(root_dir)
      assert stat.S_ISDIR(st.st_mode)
      if st.st_mtime < prev_scan_floor and do_incremental:
        logging.info('skipping root_dir=%r now=%r prev_scan_at=%r' %
            (root_dir, now, prev_scan_at))
        return False
    except OSError, e:
      pass
    logging.info('scanning root_dir=%r now=%r prev_scan_at=%r' %
        (root_dir, now, prev_scan_at))

    succ_slash = chr(ord('/') + 1)
    now_floor = math.floor(now)  # int(now) rounds towards 0.
    update_count = 0
    insert_count = 0
    delete_count = 0
    cursor = self.db.cursor()

    stack = [StackEntry('.', ino=None)]
    subdirs = []
    fileattrs = []
    stat_count = 0
    dirscan_count = 0
    dirskip_count = 0
    dirs_to_delete = []
    need_again = False

    # Do an inorder scan (files before subdirs), entries alphanumerically.
    try:
      while stack:
        #print 'STACK', stack
        stack_entry = stack[-1]
        dir = stack_entry.dir
        sibling_entries = stack_entry.sibling_entries

        if stack_entry.up:
          if len(stack) >= 2:
            if base.IsSubPath(stack[-2].dir, dir):
              assert stack[-2].up, 'stack prev must go up'
              if sibling_entries:
                upentry = base.EntryOf(stack[-2].dir)
                if upentry not in stack[-2].sibling_entries:
                  # If we have xattrs (i.e. sibling_entries is true), propagate
                  # that to our parent.
                  stack[-2].sibling_entries.append(upentry)
              adict = {'dir': stack[-2].dir, 'at': now,
                       'ino': stack[-2].ino,
                       'entrylist': '/'.join(sibling_entries)}
              update_count, insert_count, delete_count = self.UpdateDirs(
                  cursor=cursor, adict=adict, do_delete=(not sibling_entries),
                  update_count=update_count, insert_count=insert_count,
                  delete_count=delete_count)
            else:  # stack[-2] is our sibling.
              prev_updir = stack[-2].dir
              prev_updir = prev_updir[: prev_updir.rindex('/') + 1]
              assert dir.startswith(prev_updir), (
                  'bad stack neighbour dirs: prev=%r current=%r' %
                  (stack[-2].dir, dir))
              assert not stack[-2].up, 'stack prev must not go up'
              if stack[-2].sibling_entries:
                stack[-2].sibling_entries.extend(sibling_entries)
              else:
                stack[-2].sibling_entries = sibling_entries

          stack.pop()
          continue

        if dir != '.':
          assert dir[1] == '/'
          fsdir = root_dir + dir[1:]
        else:
          fsdir = root_dir

        try:
          st = os.stat(fsdir)
          stack_entry.ino = st.st_ino
        except OSError, e:
          logging.info('cannot list dir: %s' % e)
          st = None

        if st and stat.S_ISDIR(st.st_mode):
          if st.st_mtime < prev_scan_floor and do_incremental:
            # Don't descend to dir, because it has not changed since last scan.
            # This condition assumes that rmtimeup.ko is loaded.
            # TODO: Make the scanner work (slowly) without rmtimeup.ko.
            rows = tuple(cursor.execute(
                'SELECT dir FROM dirs INDEXED BY dirs_ino WHERE ino=?',
                (st.st_ino,)))
            assert len(rows) < 2
            # We have the `rows[0][0] == dir' check in case dir has been
            # renamed since the last scan. If so, the condition is false,
            # and we'll rescan it.
            # TODO: just rename in the database instead of rescanning.
            if not rows or rows[0][0] == dir:
              #logging.info('skip---- dir=%r dirscan_count=%d rows=%r' %
              #    (dir, dirscan_count, rows))
              if rows:
                # If db contains xattrs in dir (recursively), add dir to its
                # sibling_entries.
                sibling_entries.append(base.EntryOf(dir))
              stack_entry.up = True
              dirskip_count += 1
              continue
          elif st.st_mtime >= now_floor:
            need_again = True

        dirscan_count += 1
        #logging.info('scanning dir=%r dirscan_count=%d' % (dir, dirscan_count))

        try:
          entries = sorted(os.listdir(fsdir))
        except OSError, e:
          logging.info('cannot list dir: %s' % e)
          entries = ()
        #print (dir, entries)
        del subdirs[:]
        del fileattrs[:]
        had_xattrs = False
        for entry in entries:
          fn = '%s/%s' % (dir, entry)
          if root_dir.endswith('/'):  # Usually when root_dir == '/'
            fsfn = root_dir + fn[2:]
          else:
            fsfn = root_dir + fn[1:]
          if dir == '.' and entry.startswith(self.tagdb_name):
            # Ignore the tagdb file.
            continue

          stat_count += 1
          if stat_count % 1000 == 0:
            logging.info('scanning in progress filename=%r '
                'dirscan_count=%d dirskip_count=%d '
                'update_count=%d insert_count=%d delete_count=%d' %
                (fn, dirscan_count, dirskip_count,
                 update_count, insert_count, delete_count))
          try:
            # Don't follow symbolic links.
            st = os.lstat(fsfn)
          except OSError, e:
            # str(e) contains the filename as well
            logging.info('cannot stat: %s' % e)
            st = None

          if st and stat.S_ISLNK(st.st_mode):
            try:
              st2 = os.stat(fsfn)
            except OSError, e:
              st2 = None
            if st2 and stat.S_ISREG(st2.st_mode):
              st = st2  # Follow symlink to file only (not to directory etc.).
              # There is some race codition (between the stat and the
              # get_xattr_items_func), but we ignore it for simplicity.
          if st and stat.S_ISREG(st.st_mode):
            try:
              xattrs = get_xattr_items_func(fsfn)
            except EnvironmentError, e:
              logging.info('cannot list xattrs of %s: %s' % (fsfn, e))
              xattrs = []
            if st.st_nlink > 1 and not xattrs:
              # Add files with multiple hard links but without xattrs to the
              # database in case an xattr gets added to one of them later.
              xattrs.append(('', ''))
            if xattrs:
              adict = {
                  'at': now, 'filewords_rowid': None,
                  'ino': int(st.st_ino), 'dir': dir, 'entry': entry,
                  'nlink': int(st.st_nlink), 'size': int(st.st_size),
                  'ctime': int(st.st_ctime), 'mtime': int(st.st_mtime)}
              for xattr_name, value in xattrs:
                if not value: continue
                had_xattrs = True
                adict2 = dict(adict)
                adict2['xattr'] = xattr_name
                adict2['value'] = value
                fileattrs.append(adict2)
          elif st and stat.S_ISDIR(st.st_mode):
            subdirs.append(fn)
        if fileattrs:
          update_count, insert_count = self.UpdateOrInsertManyByName(
              db=self.db, table='fileattrs', dicts=fileattrs, cursor=cursor,
              update_count=update_count, insert_count=insert_count)

        # TODO: check if DELETE is fast enough
        cursor.execute('DELETE FROM filewords WHERE rowid IN '
            '(SELECT filewords_rowid FROM fileattrs '
            'INDEXED BY fileattrs_nxattr '
            'WHERE dir=? AND at<>? AND filewords_rowid IS NOT NULL)',
            (dir, now))
        delete_count += cursor.rowcount
        cursor.execute('DELETE FROM fileattrs INDEXED BY fileattrs_nxattr '
            'WHERE dir=? AND at<>?', (dir, now))
        delete_count += cursor.rowcount

        # Delete subdirs of dir which are no longer present on the filesystem
        # from table dirs.        
        rows = list(cursor.execute('SELECT entrylist FROM dirs WHERE dir=?',
            (dir,)))
        if rows and rows[0][0]:
          subdirs_gone = sorted(
              set(['%s/%s' % (dir, entry) for entry in rows[0][0].split('/')])
              .difference(subdirs))
          # TODO: use less memory by putting dirs_to_delete to the database
          #       (or setting mtime=None etc.)
          # We must defer deletion after scanning, because otherwise
          # after the move `mv /mnt/mini/{sub/shallow,other/deep}' not all
          # subdirectories would be scanned, because
          # `SELECT dir FROM dirs INDEXED BY dirs_ino WHERE ino=?' above needs
          # the old rows.
          dirs_to_delete.extend(subdirs_gone)
        else:
          old_entrylist = ()

        if had_xattrs: sibling_entries.append(base.EntryOf(dir))
        stack_entry.up = True

        # Scan all subdirectories.
        if subdirs:
          stack.extend(reversed([StackEntry(dir) for dir in subdirs]))
        else:
          adict = {'dir': dir, 'at': now, 'ino': stack_entry.ino,
                   'entrylist': ''}
          update_count, insert_count, delete_count = self.UpdateDirs(
              cursor=cursor, adict=adict, do_delete=(not had_xattrs),
              update_count=update_count, insert_count=insert_count,
              delete_count=delete_count)

      for dir_to_delete in dirs_to_delete:
        # TODO: test this by removing /mnt/mini/other/deep/a  (or even one level deeper)
        #       mkdir -p /mnt/mini/other/deep/a/b && echo c.data >/mnt/mini/other/deep/a/b/c && setfattr -n user.tags -v c.tag /mnt/mini/other/deep/a/b/c
        # TODO: test this by: mv /mnt/mino/other/{shallow,deep}
        # TODO: cursor.executemany()
        cursor.execute('DELETE FROM dirs WHERE dir=?', (dir_to_delete,))
        delete_count += cursor.rowcount
        cursor.execute('DELETE FROM dirs WHERE dir>=? AND dir<?',
            (dir_to_delete + '/', dir_to_delete + succ_slash))
        delete_count += cursor.rowcount
        cursor.execute('DELETE FROM filewords WHERE rowid IN '
            '(SELECT filewords_rowid FROM fileattrs '
            'INDEXED BY fileattrs_nxattr '
            'WHERE dir=? AND filewords_rowid IS NOT NULL)',
            (dir,))
        delete_count += cursor.rowcount
        cursor.execute('DELETE FROM fileattrs INDEXED BY fileattrs_nxattr '
            'WHERE dir=?', (dir_to_delete,))
        delete_count += cursor.rowcount
        cursor.execute('DELETE FROM filewords WHERE rowid IN '
            '(SELECT filewords_rowid FROM fileattrs '
            'INDEXED BY fileattrs_nxattr '
            'WHERE dir>=? AND dir<? AND filewords_rowid IS NOT NULL)',
            (dir_to_delete + '/', dir_to_delete + succ_slash))
        delete_count += cursor.rowcount
        cursor.execute('DELETE FROM fileattrs INDEXED BY fileattrs_nxattr '
            'WHERE dir>=? AND dir<?',
            (dir_to_delete + '/', dir_to_delete + succ_slash))
        delete_count += cursor.rowcount

      lastscans_at = now_floor - 1  # In case we restart.
      cursor.execute("UPDATE lastscans SET at=? WHERE which=''",
          (lastscans_at,))
      if not cursor.rowcount:
        cursor.execute('INSERT INTO lastscans (which, at) VALUES (?, ?)',
            ('', lastscans_at))
      self.db.commit()
    finally:
      cursor.close()
    self.last_scan_at = now
    logging.info('scan done, dirscan_count=%d dirskip_count=%d '
        'update_count=%d insert_count=%d delete_count=%d' %
        (dirscan_count, dirskip_count,
         update_count, insert_count, delete_count))
    return need_again


class Scanner(base.GlobalInfo):
  """Object which scans filesystems with tags recursively."""

  root_info_class = RootInfo

  def __init__(self):
    base.GlobalInfo.__init__(self)
    # Do we need a new scan because of timestamp rounding differences?
    self.need_new_scan = True
    self.had_last_incremental = False
    xattr_impl = good_xattr.xattr_detect()()
    self.getxattr_func, self.listxattr_func = (
        xattr_impl['getxattr'], xattr_impl['listxattr'])
    #assert 0, (self.GetUserXattrItems('fool'), self.getxattr_func('fool', 'user.other'))

  def GetUserXattrItems(self, filename, do_not_follow_symlinks=False):
    getxattr_func = self.getxattr_func
    namespace = 'user.'
    result, ln = [], len(namespace)
    for key in self.listxattr_func(filename, do_not_follow_symlinks):
      if key.startswith(namespace):
        value = getxattr_func(filename, key, do_not_follow_symlinks)
        if value is not None:
          result.append((key[ln:], value))
    return result

  def DoingIncremental(self):
    assert self.event_fd >= 0, ('event file %r not found, '
        'please load kernel module rmtimeup.ko '
        '(or specify --slow)' % self.EVENT_FILENAME)

  def ScanRootDirs(self, do_incremental):
    scan_root_dirs = sorted(self.roots)
    logging.info('scanning root_dirs=%s do_incremental=%r' %
        (scan_root_dirs, do_incremental))
    if do_incremental:
      self.DoingIncremental()
    # Round the time to millisecond precision in order to not to loose
    # precision with SQLite.
    while True:
      now = int(time.time() * 1024) / 1024.0
      if now != self.last_scan_at: break
      time.sleep(0.001)
    self.need_new_scan = False
    had_last_incremental = True
    get_xattr_items_func = self.GetUserXattrItems
    for scan_root_dir in scan_root_dirs:
      if scan_root_dir == '.empty':
        continue
      root = self.roots[scan_root_dir]
      got_now = tuple(root.db.execute("SELECT ?", (now,)))
      assert ((now,),) == got_now, ('timestamp mismatch: sent=%r, got=%r' %
          (now, got_now))
      if root.ScanRootDir(now=now, do_incremental=do_incremental, get_xattr_items_func=get_xattr_items_func):
        self.need_new_scan = True
      if not root.had_last_incremental:
        had_last_incremental = False
    self.last_scan_at = now
    self.had_last_incremental = had_last_incremental

  def RunMainLoop(self):
    """Infinite main loop waiting for changes and processing them."""
    logging.info('starting main loop')
    self.DoingIncremental()
    while True:
      # We close the tagdbs so the filesystems remain unmountable.
      self.CloseDBs()
      logging.info('waiting for change bits on event=%r need_new_scan=%r' %
          (self.EVENT_FILENAME, self.need_new_scan))
      if self.need_new_scan:
        sleep_amount = math.floor(self.last_scan_at) + 1 - time.time()
        if sleep_amount > 0:
          # Imp: ensure that we don't sleep too little.
          rlist = select.select((self.event_fd,), (), (), sleep_amount)[0]
        else:
          rlist = True
      else:
        rlist = True

      if rlist:
        bits = ord(os.read(self.event_fd, 1))  # A blocking read.
      else:
        bits = 0x1
      logging.info('got change bits=0x%x' % bits)

      if 0 != (bits & 2):  # EVENT_MOUNTS_CHANGED
        self.OpenTagDBs(self.ParseMounts())
      if 0 != (bits & 1):  # EVENT_FILES_CHANGED
        self.ReopenDBs(do_close_first=False)
        self.ScanRootDirs(do_incremental=True)

  def Run(self, do_forever, do_incremental):
    try:
      self.OpenEvent()
      self.OpenTagDBs(self.ParseMounts())
      self.ScanRootDirs(do_incremental=do_incremental)
      if do_forever:
        self.RunMainLoop()
      else:
        if self.had_last_incremental:
          scan_type = 'incremental'
        else:
          scan_type = 'full'
        logging.info('one %s scan done, exiting.' % scan_type)
    finally:
      self.Close()


def main(argv):
  Scanner().Run(
      do_forever=(len(argv) > 1 and argv[1] == '--forever'),
      do_incremental=not (len(argv) > 1 and argv[1] == '--slow'))
