#! /usr/bin/python2.4

"""Import a good version of the `pysqlite2.dbapi2' module.

Usage:

  from ppfiletagger.good_sqlite import sqlite

instead of:

  import pysqlite2.dbapi2 as sqlite
"""

sqlite = None
try:
  import pysqlite2.dbapi2 as sqlite
  sqlite.connect(':memory:').execute(
      'CREATE VIRTUAL TABLE v USING FTS3 (t TEXT)')
except (ImportError, SystemError,
        getattr(sqlite, 'OperationalError', None)), e:
  sqlite = None

if sqlite is None:
  try:
    # The `good' subdirectory here lets us load the system's pysqlite2 above.
    # i386, Python 2.4
    import ppfiletagger.good.pysqlite2.dbapi2 as sqlite
    sqlite.connect(':memory:').execute(
        'CREATE VIRTUAL TABLE v USING FTS3 (t TEXT)')
  except (ImportError, getattr(sqlite, 'OperationalError', None)), e:
    sqlite = None

if sqlite is None:
  del sqlite
  raise ImportError('cannot import psqlite2.dbapi2 with the FTS3 module')