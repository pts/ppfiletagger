#! /usr/bin/python2.4
#
# Python module pts.tagstore_sqlite
# by pts@fazekas.hu at Sun Aug 31 16:40:26 CEST 2008
#
# This Python module needs sqlite3 with the fts3 fulltext index.
#
# Misc information on Python SQLite3 and fulltext indexes:
#
# http://oss.itsystementwicklung.de/download/pysqlite/doc/usage-guide.html
# sqlite.connect: You can also supply the special name ":memory:" to create a database in RAM.
# APSW is "Another Python SQLite Wrapper". Its goal is to directly wrap the SQLite API for Python. If there's SQLite functionality that is only wrapped via APSW, but not (yet) via pysqlite, then you can still use the APSW functionality in pysqlite.
# Imp: do we need a cursor object? (c = con.cursor())
#      cursor has rowcount, conn does not
# * sqlite3: INSERT OR REPLACE INTO always creates a new rowid
# * sqlite3: UPDATE doesn't return the lastrowid updated
# Imp: recompile SQLite3 with proper compilation options (-D...).
#

import re
import sys
from pysqlite2 import dbapi2 as sqlite
from pts import tagdict

PTAG_TO_SQLITEWORD_RE = re.compile(r'[6789:_]')
PTAG_TO_SQLITEWORD_DICT = {
  '6': '66',
  '7': '65',
  '8': '64',
  '9': '63',
  ':': '7',
  '_': '8',
}

def connect(db_filename):
  conn = sqlite.connect(db_filename, timeout=10)
  conn.text_factory = str

  conn.execute("DROP TABLE IF EXISTS fastxtags")
  try:
    conn.execute("CREATE VIRTUAL TABLE fastxtags USING FTS3(positive TEXT NOT NULL)")
  except sqlite.OperationalError, e:
    if str(e) != 'table fastxtags already exists': raise

  conn.execute("DROP TABLE IF EXISTS xtags")
  try:
    conn.execute("CREATE TABLE xtags ("
        "id INTEGER PRIMARY KEY NOT NULL, "
        "filename TEXT UNIQUE NOT NULL, "
        "opaquetext TEXT NOT NULL, "
        "fastxtags_rowid INTEGER NOT NULL)")  # rowid in fastxtags
  except sqlite.OperationalError, e:
    if str(e) != 'table xtags already exists': raise
  return conn

SQLITEWORD_RE = re.compile(r'\A[A-Za-z0-9]+\Z')
"""Regexp matching a word, as split by the sqlite3 fts3 fulltext search
engine."""


def xtag_to_sqliteword(ptag):
  ret = re.sub(PTAG_TO_SQLITEWORD_RE,
      (lambda match: PTAG_TO_SQLITEWORD_DICT[match.group(0)]), ptag)
  assert re.match(SQLITEWORD_RE, ret)
  return ret


class Sqlite3TagStore(tagdict.TagStore):
  def __init__(self, cursor):
    self._cursor = cursor

  def set_tuple(self, filename, xtags, opaquetext):
    positive = ' '.join([xtag_to_sqliteword(xtag) for xtag in xtags])
    self._cursor.execute("SELECT fastxtags_rowid, opaquetext "
        "FROM xtags WHERE filename=?", (filename,))
    result = list(self._cursor)
    assert len(result) < 2
    if result:
      ret = result[0][1]
    else:
      ret = None
    if not opaquetext:
      if result:
        self._cursor.execute("DELETE FROM fastxtags WHERE rowid=?",
            (result[0][0],))
        self._cursor.execute("DELETE FROM xtags WHERE filename=?",
            (filename,))
    elif result:
      if result[0][1] != opaquetext:
        self._cursor.execute("UPDATE xtags SET opaquetext=? WHERE filename=?",
            (opaquetext, filename))
        assert self._cursor.rowcount == 1
        self._cursor.execute("UPDATE fastxtags SET positive=? WHERE rowid=?",
            (positive, result[0][0]))
        assert self._cursor.rowcount == 1
      #else:
      #  print 'U', repr((filename, opaquetext))
    else:
      self._cursor.execute("INSERT INTO fastxtags (positive) VALUES (?)",
          (positive,))
      fastxtags_rowid = self._cursor.lastrowid
      assert type(fastxtags_rowid) in (int, long)
      # `INSERT OR REPLACE INTO' always creates a new rowid
      self._cursor.execute("INSERT OR REPLACE INTO xtags "
          "(filename, opaquetext, fastxtags_rowid) VALUES(?, ?, ?)",
          (filename, opaquetext, fastxtags_rowid))
    #print {'rowcount': self._cursor.rowcount, 'lastrowid': self._cursor.lastrowid}
    return ret

  def contains_filename(self, filename):
    self._cursor.execute("SELECT 1 FROM xtags WHERE filename=?", (filename,))
    return bool(list(self._cursor))

  def get_opaquetext(self, filename):
    self._cursor.execute("SELECT opaquetext FROM xtags WHERE filename=?",
        (filename,))
    result = list(self._cursor)
    if not result: return None
    return result[0][0]

  def search_with_xtags(self, xtags):
    # SQLite3 fts3 MATCH does a case insensitive search, but this doesn't
    # matter since column `positive' contains only characters [a-z0-9 ].
    # SQLIte3 doesn't use stop words in MATCH. Good. 
    # !! performance testing -- do we get the proper, optimized query plan?
    self._cursor.execute(
        "SELECT filename, opaquetext FROM fastxtags, xtags WHERE "
        "positive MATCH (?) AND fastxtags.rowid = fastxtags_rowid",
        (' '.join([xtag_to_sqliteword(ptag) for ptag in xtags]),))
    return list(self._cursor)
