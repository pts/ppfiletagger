#! /usr/bin/python2.4
# by pts@fazekas.hu at Wed Jan  7 06:22:51 CET 2009
#
# * The scanner needs a Linux systems with the rmtimeup.ko kernel module
#   loaded.
# * The scanner should not be run as root (to restrict the effects of
#   security vulnerabilities).
#
# TODO: Reduce the amount of unnecessary stats, listdirs, and xattrs.get_alls.
#       (also modify rmtimeup).
# TODO: Reduce the amount of database UPDATEs (is a SELECT before an UPDATE
#       really faster?)
# TODO: Add a modified-file-list to rmtimeup, and use mtime-based scanning only
#       as a safety fallback. This will speed up response time.
# TODO: add INDEXED BY to each query.

import errno
import logging
import os
import pysqlite2.dbapi2 as sqlite
import stat
import sys
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

  __slots__ = ['dir', 'sibling_entries', 'up']

  def __init__(self, dir, sibling_entries=(), up=False):
    # String holding a directory name.
    self.dir = str(dir)
    # A boolean indicating whether we've already descended to the children of
    # this entry.
    self.up = bool(up)
    # A list holding names of directory entries in the parent of self.dir.
    # Only those entries are listed which (recursively) contain files with
    # xattrs.
    self.sibling_entries = list(sibling_entries)

  def __repr__(self):
    buf = ['StackEntry(dir=', repr(self.dir)]
    if self.sibling_entries:
      buf.append(', sibling_entries=')
      buf.append(repr(self.sibling_entries))
    if self.up:
      buf.append(', up=True')
    buf.append(')')
    return ''.join(buf)


class Scanner(object):
  """Object which scans filesystems with tags recursively."""

  TAGDB_NAME = 'tags.sqlite'
  """Name of the SQLite tags database file on each partition.

  This must be the same as the TAGDB_NAME in rmtimeup/main.mod.c ."""

  EVENT_FILENAME = '/proc/rmtimeup-event'

  def __init__(self):
    # Maps scan_root_dir strings to sqlite.Connection objects.
    self.dbs = {}
    # None or file descriptor of open /proc/rmtimeup-event.
    self.event_fd = None
    # Timestamp of last scan, or None.
    self.last_scan_at = None

  def CloseDBs(self):
    # Close old dbs in case a different filesystem was mounted.
    for scan_root_dir in sorted(self.dbs):
      if self.dbs[scan_root_dir] is not None:
        self.dbs[scan_root_dir].close()
      self.dbs[scan_root_dir] = None

  def ReopenDBs(self, do_close_first):
    for scan_root_dir in self.dbs:
      if self.dbs[scan_root_dir] is not None:
        if not do_close_first: continue
        self.dbs[scan_root_dir].close()
        self.dbs[scan_root_dir] = None
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
      self.dbs[scan_root_dir] = db

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
    """Initialize or update self.dbs from scan_root_dirs."""
    if type(scan_root_dirs) not in (list, tuple, set): raise TypeError
    for scan_root_dir in scan_root_dirs:
      if not isinstance(scan_root_dir, str): raise TypeError

    # Close old dbs in case a different filesystem was mounted.
    self.CloseDBs()

    self.dbs.clear()
    for scan_root_dir in scan_root_dirs:
      self.dbs[scan_root_dir] = None

    self.ReopenDBs(do_close_first=True)

  def ScanRootDirs(self):
    scan_root_dirs = sorted(self.dbs)
    logging.info('scanning root dirs %s' % scan_root_dirs)
    # Round the time to millisecond precision in order to not to loose
    # precision with SQLite.
    while True:
      now = (512 + int(time.time() * 1024)) / 1024.0
      if now != self.last_scan_at: break
      time.sleep(0.001)
    for scan_root_dir in scan_root_dirs:
      db = self.dbs[scan_root_dir]
      got_now = tuple(db.execute("SELECT ?", (now,)))
      assert ((now,),) == got_now, ('timestamp mismatch: sent=%r, got=%r' %
          (now, got_now))
      self.ScanRootDir(db=db, root_dir=scan_root_dir, now=now)
    self.last_scan_at = now

  def InitializeDB(self, db_filename, db):
    # Imp: do this in a transaction?
    logging.info('creating tables in tagdb %r' % db_filename)
    try:
      # TODO: add indexes
      # TODO: add fts3
      # TODO: remember added and last-modified timestamps
      # List of files with user.* extended attributes.
      # We could normalize this table to link to inodeattrs (ino, attr, value). 
      db.execute('CREATE TABLE fileattrs (ino INTEGER NOT NULL, '
                 'dir TEXT NOT NULL, entry TEXT NOT NULL, '
                 'nlink INTEGER NOT NULL, ctime INTEGER NOT NULL, '
                 'mtime INTEGER NOT NULL, size INTEGER NOT NULL, '
                 'at FLOAT NOT NULL, '
                 'xattr TEXT NOT NULL, value TEXT NOT NULL)')
      # Field ino is not unique, a file can have multiple links.
      db.execute('CREATE INDEX fileattrs_nxattr ON fileattrs '
          '(dir, entry, xattr)')
      db.execute('CREATE INDEX fileattrs_ino ON fileattrs (ino)')
      db.execute('CREATE INDEX fileattrs_at ON fileattrs (at)')
      # Non-root directories of name dir + '/' + entry.
      db.execute('CREATE TABLE dirs ('
                 'dir TEXT NOT NULL, entrylist TEXT NOT NULL, '
                 'at FLOAT NOT NULL)')
      db.execute('CREATE UNIQUE INDEX dirs_dir ON dirs (dir)')
      # !! EXPLAIN SELECT * FROM fileattrs INDEXED BY fileattrs_at WHERE at>5 AND at<6
      db.execute('CREATE TABLE lastscans (which TEXT PRIMARY KEY NOT NULL, '
                 'at FLOAT)')
    except sqlite.OperationalError:
      db.rollback()
      db.execute('DROP TABLE IF EXISTS lastscans')
      db.execute('DROP TABLE IF EXISTS dirs')
      db.execute('DROP TABLE IF EXISTS fileattrs')
      raise
    db.commit()

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
        assert 'dir' in keys
        has_entry = 'entry' in keys
        has_xattr = 'xattr' in keys
        update_keys = list(keys)
        update_keys.remove('dir')
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
      #print (update_sql, adict)
      cursor.execute(update_sql, adict)
      if cursor.rowcount == 0:
        cursor.execute(insert_sql, adict)
        insert_count += 1
      else:
        # Increase even if no column changed.
        update_count += 1
        assert cursor.rowcount == 1
    if do_close_cursor:
      cursor.close()
    return (update_count, insert_count)

  def ScanRootDir(self, db, root_dir, now):
    logging.info('scanning root_dir=%r now=%r' % (root_dir, now))
    succ_slash = chr(ord('/') + 1)
    update_count = 0
    insert_count = 0
    delete_count = 0
    cursor = db.cursor()
    ats = tuple(cursor.execute("SELECT at FROM lastscans WHERE which=''"))
    if ats:
      prev_scan_at = ats[0][0]
      logging.info('prev scan at=%r' % prev_scan_at)
    else:
      prev_scan_at = float('-inf')
      logging.info('no prev scan')

    # Do an inorder scan (files before subdirs), entries alphanumerically.
    try:
      stack = [StackEntry('.')]
      subdirs = []
      fileattrs = []
      stat_count = 0
      dir_count = 0
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
                         'entrylist': '/'.join(sibling_entries)}
                cursor.execute('UPDATE dirs SET entrylist=:entrylist, at=:at '
                    'WHERE dir=:dir', adict)
                if cursor.rowcount:
                  update_count += 1
                else:
                  cursor.execute('INSERT INTO dirs (dir, entrylist, at) '
                      'VALUES (:dir, :entrylist, :at)', adict)                  
                  insert_count += 1
              else:
                cursor.execute('DELETE FROM dirs WHERE dir=?',
                    (stack[-2].dir,))
                delete_count += cursor.rowcount
              #print (dir, stack[-2].dir, sibling_entries, stack[-2].sibling_entries)
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

        dir_count += 1

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
          if dir_count == 1 and entry.startswith(self.TAGDB_NAME):
            # Ignore the tagdb file.
            continue

          stat_count += 1
          if stat_count % 1000 == 0:
            logging.info('scanning in progress filename=%r '
                'update_count=%d insert_count=%d delete_count=%d' %
                (fn, update_count, insert_count, delete_count))
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
              had_xattrs = True
              adict = {
                  'at': now,
                  'ino': int(st.st_ino), 'dir': dir, 'entry': entry,
                  'nlink': int(st.st_nlink), 'size': int(st.st_size),
                  'ctime': int(st.st_ctime), 'mtime': int(st.st_mtime)}
              for xattr_name, value in xattrs:
                adict2 = dict(adict)
                adict2['xattr'] = xattr_name
                adict2['value'] = value
                fileattrs.append(adict2)
              if st.st_nlink > 1:
                # !! update all files with the same ino
                pass
          elif st and stat.S_ISDIR(st.st_mode):
            subdirs.append(fn)
        if fileattrs:
          update_count, insert_count = self.UpdateOrInsertManyByName(
              db=db, table='fileattrs', dicts=fileattrs, cursor=cursor,
              update_count=update_count, insert_count=insert_count)

        cursor.execute('DELETE FROM fileattrs INDEXED BY fileattrs_nxattr '
            'WHERE dir=? AND at<>?', (dir, now))
        delete_count += cursor.rowcount

        # Delete subdirs of dir which are no longer present on the filesystem
        # from table dirs.        
        rows = list(cursor.execute('SELECT entrylist FROM dirs WHERE dir=?',
            (dir,)))
        if rows and rows[0][0]:
          subdirs_deleted = sorted(
              set(['%s/%s' % (dir, entry) for entry in rows[0][0].split('/')])
              .difference(subdirs))
          for dir_deleted in subdirs_deleted:
            # TODO: test this by removing /mnt/mini/other/deep/a  (or even one level deeper)
            #       mkdir -p /mnt/mini/other/deep/a/b && echo c.data >/mnt/mini/other/deep/a/b/c && setfattr -n user.tags -v c.tag /mnt/mini/other/deep/a/b/c
            cursor.execute('DELETE FROM dirs WHERE dir=?', (dir_deleted,))
            delete_count += cursor.rowcount
            cursor.execute('DELETE FROM dirs WHERE dir>=? AND dir<?',
                (dir_deleted + '/', dir_deleted + succ_slash))
            delete_count += cursor.rowcount
            cursor.execute('DELETE FROM fileattrs INDEXED BY fileattrs_nxattr '
                'WHERE dir=?', (dir_deleted,))
            delete_count += cursor.rowcount
            cursor.execute('DELETE FROM fileattrs INDEXED BY fileattrs_nxattr '
                'WHERE dir>=? AND dir<?',
                (dir_deleted + '/', dir_deleted + succ_slash))
            delete_count += cursor.rowcount
        else:
          old_entrylist = ()

        if had_xattrs: sibling_entries.append(EntryOf(dir))
        stack_entry.up = True
        # Scan all subdirectories.
        stack.extend(reversed([StackEntry(dir) for dir in subdirs]))

      # !! use now-1 etc. in case the dir was modified in the same second.
      cursor.execute("UPDATE lastscans SET at=? WHERE which=''", (now,))
      if not cursor.rowcount:
        cursor.execute('INSERT INTO lastscans (which, at) VALUES (?, ?)',
            ('', now))
      db.commit()
    finally:
      cursor.close()
    logging.info('scan done, update_count=%d insert_count=%d delete_count=%d' %
        (update_count, insert_count, delete_count))

def main(argv):
  scanner = Scanner()
  try:
    scanner.OpenEvent()
    scanner.OpenTagDBs(scanner.ParseMounts())
    scanner.ScanRootDirs()
    #scanner.MainLoop()
  finally:
    scanner.Close()

if __name__ == '__main__':
  logging.BASIC_FORMAT = '[%(created)f] %(levelname)s %(message)s'
  logging.root.setLevel(logging.INFO)  # Prints INFO, but not DEBUG.
  main(sys.argv)
