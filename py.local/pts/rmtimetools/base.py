#! /usr/bin/python2.4
# by pts@fazekas.hu at Sun Jan 11 05:43:18 CET 2009

import errno
import logging
import os
import pysqlite2.dbapi2 as sqlite
import re
import stat
import time


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

# TODO: move this to a test
assert 'i said: hello wonderful_world 0123456789' == RootInfo(db=None, root_dir=None, last_scan_at=None, tagdb_name=None).ValueToWordListc('  I said:\tHello,  Wonderful_World! 0123456789\r\n')
assert 'i said7 hello wonderful8world 01234566656463' == RootInfo(db=None, root_dir=None, last_scan_at=None, tagdb_name=None).ValueToWordData('I said: Hello,  Wonderful_World! 0123456789')


class GlobalInfo(object):
  """Information about the indexed state of all mounted filesystems."""

  TAGDB_NAME = 'tags.sqlite'
  """Name of the SQLite tags database file on each partition.

  This must be the same as the TAGDB_NAME in rmtimeup/main.mod.c ."""

  EVENT_FILENAME = '/proc/rmtimeup-event'

  root_info_class = RootInfo

  def __init__(self):
    # Maps scan_root_dir strings to RootInfo objects.
    self.roots = {}
    # None or file descriptor of open /proc/rmtimeup-event.
    self.event_fd = None
    # Timestamp of last scan, or None.
    self.last_scan_at = None

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
      self.roots[scan_root_dir] = self.root_info_class(
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
