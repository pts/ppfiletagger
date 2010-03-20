#! /usr/bin/python2.4

"""Import a good version of the `pysqlite2.dbapi2' module.

Usage:

  from ppfiletagger.good_sqlite import sqlite

instead of:

  import pysqlite2.dbapi2 as sqlite
"""

sqlite = None
try:
  # TODO(pts): Import from module root (not current dir).
  import pysqlite2.dbapi2 as sqlite
  sqlite.connect(':memory:').execute(
      'CREATE VIRTUAL TABLE v USING FTS3 (t TEXT)')
except (ImportError, SystemError,
        getattr(sqlite, 'OperationalError', None)), e:
  sqlite = None

if sqlite is None:
  try:
    import ppfiletagger.pysqlite2.dbapi2 as sqlite
    sqlite.connect(':memory:').execute(
        'CREATE VIRTUAL TABLE v USING FTS3 (t TEXT)')
  except (ImportError, getattr(sqlite, 'OperationalError', None)), e:
    sqlite = None

if sqlite is None:
  del sqlite
  raise ImportError('cannot import psqlite2.dbapi2 with the FTS3 module')
