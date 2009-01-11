#! /usr/bin/python2.4
# by pts@fazekas.hu at Wed Jan  7 06:22:51 CET 2009
#
# * The scanner needs a Linux systems with the rmtimeup.ko kernel module
#   loaded.
# * The scanner should not be run as root (to restrict the effects of
#   security vulnerabilities).
#
# TODO: Test by faking the filesystem.
# TODO: Reduce the amount of unnecessary stats, listdirs, and xattrs.get_alls.
#       (also modify rmtimeup).
# TODO: Reduce the amount of database UPDATEs (is a SELECT before an UPDATE
#       really faster?)
# TODO: Add a modified-file-list to rmtimeup, and use mtime-based scanning only
#       as a safety fallback. This will speed up response time.
# TODO: Add INDEXED BY to each query.
# TODO: Don't let two instances of scan.py run at the same time.
# TODO: Ignore or defer SIGINT (KeyboardInterrupt).

import errno
import logging
import math
import os
import pysqlite2.dbapi2 as sqlite
import re
import select
import stat
import time
import xattr

def IsSubPath(a, ab):
  if not isinstance(a, str): raise TypeError
  if not isinstance(ab, str): raise TypeError
  return len(ab) > len(a) and ab[len(a)] == '/' and ab.startswith(a)


def EntryOf(filename):
  """Return the last name of component a relative ('.' or './*') filename."""
  try:
    return filename[filename.rindex('/') + 1:]
  except ValueError:
    return filename


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


class RootInfo(object):
  """Information about a filesystem root directory."""

  __slots__ = ['db', 'root_dir', 'last_scan_at', 'tagdb_name']

  FILEWORDS_XATTRS = ('tags',)
  """Sequence of user.* extended attribute names to be added to the full-text
  index (table filewords)."""

  def __init__(self, db, root_dir, last_scan_at, tagdb_name):
    # sqlite.Connection or None.
    self.db = db
    self.root_dir = root_dir
    self.last_scan_at = last_scan_at
    self.tagdb_name = tagdb_name

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

  WORDDATA_NONWORDCHAR_RE = re.compile(r'[^a-z0-9:_ ]')
  WORDDATA_SPLIT_WORD_RE = re.compile(r'[^\s?!.,;\[\](){}<>"\']+')
  PTAG_TO_SQLITEWORD_RE = re.compile(r'[6789:_]')
  PTAG_TO_SQLITEWORD_DICT = {
    '6': '66',
    '7': '65',
    '8': '64',
    '9': '63',
    ':': '7',
    '_': '8',
  }

  def ValueToWordListc(self, value):
    """Return a list of normalized words concatenated by space."""
    if not isinstance(value, str): raise TypeError
    words = []
    re.sub(  # Igore return value, only update words.
        self.WORDDATA_SPLIT_WORD_RE,
        (lambda match: words.append(match.group(0).lower())), value)
    return re.sub(self.WORDDATA_NONWORDCHAR_RE, '_', ' '.join(words))

  def ValueToWordData(self, value):
    """Return fileattrs.value converted to filewords.worddata."""
    if not isinstance(value, str): raise TypeError
    return re.sub(
        self.PTAG_TO_SQLITEWORD_RE,
        (lambda match: self.PTAG_TO_SQLITEWORD_DICT[match.group(0)]),
        self.ValueToWordListc(value))

  def ScanRootDir(self, now):
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

    # Return quickly if nothing has changed.
    try:
      st = os.stat(root_dir)
      assert stat.S_ISDIR(st.st_mode)
      if st.st_mtime < prev_scan_floor:
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
            if IsSubPath(stack[-2].dir, dir):
              assert stack[-2].up, 'stack prev must go up'
              if sibling_entries:
                upentry = EntryOf(stack[-2].dir)
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
          if st.st_mtime < prev_scan_floor:
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
                sibling_entries.append(EntryOf(dir))
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
            st = os.stat(fsfn)
          except OSError, e:
            # str(e) contains the filename as well
            logging.info('cannot stat: %s' % e)
            st = None

          if st and stat.S_ISREG(st.st_mode):
            try:
              xattrs = xattr.get_all(fsfn, namespace=xattr.NS_USER)
            except EnvironmentError, e:
              logging.info('cannot list xattrs: %s' % e)
              xattrs = ()
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

        if had_xattrs: sibling_entries.append(EntryOf(dir))
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
            (dir_low, dir_high))
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

  def GenerateTagsResponse(self, wordlistc, xattr):
    """Generate (dir, entry, value) matches, in no particular order."""
    # TODO: Verify proper use of indexes. 
    for row in self.db.execute(
        'SELECT dir, entry, value '
        'FROM filewords, fileattrs INDEXED BY fileattrs_xattr '
        'WHERE worddata MATCH (?) AND '
        'xattr=? AND filewords.rowid=filewords_rowid', (wordlistc, xattr)):
      yield (row[0], row[1], row[2])  # (dir, entry, value)


# TODO: move this to a test
assert 'i said: hello wonderful_world 0123456789' == RootInfo(db=None, root_dir=None, last_scan_at=None, tagdb_name=None).ValueToWordListc('  I said:\tHello,  Wonderful_World! 0123456789\r\n')
assert 'i said7 hello wonderful8world 01234566656463' == RootInfo(db=None, root_dir=None, last_scan_at=None, tagdb_name=None).ValueToWordData('I said: Hello,  Wonderful_World! 0123456789')


class Scanner(object):
  """Object which scans filesystems with tags recursively."""

  TAGDB_NAME = 'tags.sqlite'
  """Name of the SQLite tags database file on each partition.

  This must be the same as the TAGDB_NAME in rmtimeup/main.mod.c ."""

  EVENT_FILENAME = '/proc/rmtimeup-event'

  def __init__(self):
    # Maps scan_root_dir strings to RootInfo objects.
    self.roots = {}
    # None or file descriptor of open /proc/rmtimeup-event.
    self.event_fd = None
    # Timestamp of last scan, or None.
    self.last_scan_at = None
    # Do we need a new scan because of timestamp rounding differences?
    self.need_new_scan = True

  def CloseDBs(self):
    # Close old roots in case a different filesystem was mounted.
    for scan_root_dir in sorted(self.roots):
      db = self.roots[scan_root_dir].db
      if db is not None:
        db.close()
        self.roots[scan_root_dir].db = None

  def ReopenDBs(self, do_close_first):
    for scan_root_dir in self.roots:
      db = self.roots[scan_root_dir].db
      if db is not None:
        if not do_close_first: continue
        db.close()
        self.roots[scan_root_dir].db = None
      if scan_root_dir.endswith('/'):
        tagdb_fn = scan_root_dir + self.TAGDB_NAME
      else:
        tagdb_fn = '%s/%s' % (scan_root_dir, self.TAGDB_NAME)
      logging.info('opening tagdb %r' % tagdb_fn)
      st = os.stat(tagdb_fn)
      if st.st_size <= 1:
        # sqlite.connect() converts an empty database file to a file of size
        # 1. But that file is still not a completely functional SQLite
        # database, because PRAGMA journal_mode = TRUNCATE or doesn't work,
        # the first table cannot be created that way. So we create the tables
        # in PRAGMA journal_mode = MEMORY mode.
        db = self.ConnectToDB(db_filename=tagdb_fn, journal_mode='MEMORY')
        self.InitializeDB(db_filename=tagdb_fn, db=db)
        db.commit()
        db.close()
      db = self.ConnectToDB(db_filename=tagdb_fn, journal_mode='TRUNCATE')
      if not tuple(db.execute(
          "SELECT name FROM sqlite_master WHERE type='table'")):
        self.InitializeDB(db_filename=tagdb_fn, db=db)
        db.commit()
      self.roots[scan_root_dir].db = db

  def ConnectToDB(self, db_filename, journal_mode):
    db = sqlite.connect(db_filename, timeout=6.0)
    db.text_factory = str  # Return byte strings instead of Unicode.
    #db.filename = tagdb_fn  # We cannot add new attributes.
    db.execute('PRAGMA journal_mode = ' + journal_mode)
    return db

  def Close(self):
    if self.event_fd is not None:
      os.close(self.event_fd)
      self.event_fd = None
    self.CloseDBs()

  def __del__(self):
    self.Close()

  def OpenEvent(self):
    """(Re)opens /proc/rmtimeup-event."""
    if self.event_fd is not None:
      os.close(self.event_fd)
      self.event_fd = None
    try:
      self.event_fd = os.open(self.EVENT_FILENAME, os.O_RDONLY)
    except OSError, e:
      if e.errno == errno.ENOENT:
        assert 0, ('event file %r not found, '
            'please load kernel module rmtimup.ko' % EVENT_FILENAME)
      raise

  def ParseMounts(self, mounts_filename='/proc/mounts'):
    if not isinstance(mounts_filename, str): raise TypeError
    logging.info('ParseMounts mounts_filename=%r' % mounts_filename)
    f = open(mounts_filename)
    dirs = set()
    # Dict mapping a good dev name to a set of dirs.
    good_devs = {}
    try:
      for line in f:
        dev, dir, type, flags, mode1, mode2 = line.strip('\r\n').split(' ', 5)
        dirs.add(dir)

        dir_slash = dir
        if not dir_slash.endswith('/'): dir_slash += '/'
        flags_comma = ',%s,' % flags
        if ('/' not in dev or  # NFS and CIFS devs do have '/'.
            ',rw,' not in flags_comma or
            dir_slash.startswith('/proc/') or
            dir_slash.startswith('/dev/') or
            dir_slash.startswith('/sys/')):
            # Imp: ignore --bind
          continue
        # Good values for type: +ext2 +ext3 +ext4 +jfs +xfs +reiserfs +nfs +ntfs
        # +vfat +reiser4 +cifs +fuseblk (NTFS-3g) +fuse
        # Bad values for type:  -devpts -rootfs -sysfs -tmpfs -nfsd -rpc_pipefs
        # -usbfs -proc -procfs  (FreeBSD) fuse.gvfs-fuse-daemon -fusectl -iso9660
        # -securityfs -vmblock (vmware host)

        tagdb_fn = dir_slash + self.TAGDB_NAME
        try:
          st = os.lstat(tagdb_fn)
        except OSError:
          # Silently ignore the mount if self.TAGDB_NAME doesn't exist.
          continue
        assert stat.S_ISREG(st.st_mode), 'tagdb %r not a regular file' % (
            tagdb_fn)

        try:
          f = open(tagdb_fn, 'r+')
        except IOError:
          assert 0, 'cannot open read-write tagdb %r' % tagdb_fn
        f.close()

        journal_fn = tagdb_fn + '-journal'
        try:
          fd = os.open(journal_fn, os.O_CREAT | os.O_RDWR, st.st_mode & 0777)
        except OSError:
          assert 0, 'cannot open read-write journal %r' % journal_fn
        os.close(fd)

        #print (dev, dir, type, flags, mode1, mode2)
        if dev not in good_devs: good_devs[dev] = set()
        good_devs[dev].add(dir)
    finally:
      f.close()

    # Find the dir with the least number of mount subdirs. On equality,
    # use the shortest dir name. On equality, use the first dir name in the
    # alphabet. (Usually it is a bad idea to mount a dev in multiple dirs
    # anyway, except for network filesystems.)
    scan_root_dirs = ([
        sorted((len([1 for dir_long in dirs if IsSubPath(dir, dir_long)]),
           len(dir), dir) for dir in good_devs[dev])[0][2]
        for dev in sorted(good_devs)])
    logging.info('ParseMounts found scan_root_dirs=%r' % scan_root_dirs)
    return scan_root_dirs

  def OpenTagDBs(self, scan_root_dirs):
    """Initialize or update self.roots from scan_root_dirs."""
    if type(scan_root_dirs) not in (list, tuple, set): raise TypeError
    for scan_root_dir in scan_root_dirs:
      if not isinstance(scan_root_dir, str): raise TypeError

    # Close old databases in case a different filesystem was mounted.
    self.CloseDBs()

    self.roots.clear()
    for scan_root_dir in scan_root_dirs:
      self.roots[scan_root_dir] = RootInfo(
          db=None, root_dir=scan_root_dir, last_scan_at=None,
          tagdb_name=self.TAGDB_NAME)

    self.ReopenDBs(do_close_first=True)

  def InitializeDB(self, db_filename, db):
    # Imp: do this in a transaction?
    logging.info('creating tables in tagdb %r' % db_filename)
    try:
      # TODO: remember added and last-modified timestamps
      # List of files with user.* extended attributes.
      # We could normalize this table to link to inodeattrs (ino, attr, value). 
      db.execute('CREATE TABLE fileattrs (ino INTEGER NOT NULL, '
                 'dir TEXT NOT NULL, entry TEXT NOT NULL, '
                 'nlink INTEGER NOT NULL, ctime INTEGER NOT NULL, '
                 'mtime INTEGER NOT NULL, size INTEGER NOT NULL, '
                 'at FLOAT NOT NULL, filewords_rowid INTEGER, '
                 'xattr TEXT NOT NULL, value TEXT NOT NULL)')
      # Field ino is not unique, a file can have multiple links.
      db.execute('CREATE INDEX fileattrs_nxattr ON fileattrs '
          '(dir, entry, xattr)')
      db.execute('CREATE INDEX fileattrs_xattr ON fileattrs '
          '(xattr, filewords_rowid)')
      db.execute('CREATE INDEX fileattrs_ino ON fileattrs (ino)')

      # filewords.rowid == fileattrs.xattrs_rowid. filewords.worddata contains
      # RootInfo.ValueToWordData(fileattrs.value) for the corresponding row. 
      db.execute('CREATE VIRTUAL TABLE filewords '
                 'USING FTS3(worddata TEXT NOT NULL)')

      # Non-root directories of name dir + '/' + entry.
      db.execute('CREATE TABLE dirs (ino INTEGER NOT NULL, '
                 'dir TEXT NOT NULL, entrylist TEXT NOT NULL, '
                 'at FLOAT NOT NULL)')
      db.execute('CREATE UNIQUE INDEX dirs_dir ON dirs (dir)')
      db.execute('CREATE UNIQUE INDEX dirs_ino ON dirs (ino)')

      db.execute('CREATE TABLE lastscans (which TEXT PRIMARY KEY NOT NULL, '
                 'at FLOAT)')
    except sqlite.OperationalError:
      db.rollback()
      db.execute('DROP TABLE IF EXISTS lastscans')
      db.execute('DROP TABLE IF EXISTS dirs')
      db.execute('DROP TABLE IF EXISTS fileattrs')
      raise
    db.commit()

  def ScanRootDirs(self):
    scan_root_dirs = sorted(self.roots)
    logging.info('scanning root dirs %s' % scan_root_dirs)
    # Round the time to millisecond precision in order to not to loose
    # precision with SQLite.
    while True:
      now = int(time.time() * 1024) / 1024.0
      if now != self.last_scan_at: break
      time.sleep(0.001)
    self.need_new_scan = False
    for scan_root_dir in scan_root_dirs:
      root = self.roots[scan_root_dir]
      got_now = tuple(root.db.execute("SELECT ?", (now,)))
      assert ((now,),) == got_now, ('timestamp mismatch: sent=%r, got=%r' %
          (now, got_now))
      if root.ScanRootDir(now=now): self.need_new_scan = True
    self.last_scan_at = now

  def RunMainLoop(self):
    """Infinite main loop waiting for changes and processing them."""
    logging.info('starting main loop')
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
        self.ScanRootDirs()

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

  def Run(self, do_forever):
    try:
      self.OpenEvent()
      self.OpenTagDBs(self.ParseMounts())
      self.ScanRootDirs()
      if do_forever:
        self.RunMainLoop()
      else:
        logging.info('first scan done, exiting.')
    finally:
      self.Close()


def main(argv):
  if len(argv) > 1 and argv[1][0] != '-':
    tags = ' '.join(argv[1:])
    count = 0
    for filename, taglistc in Scanner().GenerateTagsResponse(tags=tags):
      print repr((filename, taglistc))
      count += 1
    if count:
      logging.info('found result count=%d tags=%r' % (count, tags))
    else:
      logging.info('no results found tags=%r' % (tags,))
    return
  Scanner().Run(do_forever=(len(argv) > 1 and argv[1] == '--forever'))
