#! /usr/bin/python2.4

"""Import a good version of the `pysqlite2.dbapi2' module.

Usage:

  from ppfiletagger.good_sqlite import sqlite

instead of:

  import pysqlite2.dbapi2 as sqlite
"""

sqlite = None

if sqlite is None:
  try:
    import sqlite3 as sqlite  # Standard in Python 2.5, 2.6 and 2.7.
    sqlite.connect(':memory:').execute(
        'CREATE VIRTUAL TABLE v USING FTS3 (t TEXT)')
  except (ImportError, SystemError,
          getattr(sqlite, 'OperationalError', None)), e:
    sqlite = None

if sqlite is None:
  try:
    import pysqlite2.dbapi2 as sqlite
    sqlite.connect(':memory:').execute(
        'CREATE VIRTUAL TABLE v USING FTS3 (t TEXT)')
  except (ImportError, SystemError,
          getattr(sqlite, 'OperationalError', None)), e:
    sqlite = None

if sqlite is None:
  if __import__('sys').platform.startswith('linux'):
    v1, v2 = __import__('sys').version_info[:2]
    a = __import__('os').uname()[4]  # Kernel architecture.
    if a in ('x86', '386', '486', '586', '686', 'ia32', 'x86_64', 'amd64', 'em64t'):
      # This is not accurata e.g. with qemu-user-arm.
      a = ('i386', 'amd64')[__import__('struct').calcsize('P') == 8]  # Pointer size.
    else:
      a = a.replace('-', '_')
    import os.path
    d = __file__
    for _ in __name__.split('.'):
      d = os.path.dirname(d)
    d = os.path.join(d, 'ppfiletagger', 'py%d%d_linux_%s' % (v1, v2, a))
    if os.path.isfile(os.path.join(d, 'pysqlite2', 'dbapi2.py')):
      __import__('sys').path[:0] = (d,)
      try:
        try:
          # TODO(pts): Do it as a non-global import.
          import pysqlite2.dbapi2 as sqlite
          sqlite.connect(':memory:').execute(
              'CREATE VIRTUAL TABLE v USING FTS3 (t TEXT)')
          #a = ''  # Always remove from path.
        except (ImportError, getattr(sqlite, 'OperationalError', None)), e:
          sqlite = None
      finally:
        if a and d in __import__('sys').path:
          __import__('sys').path.remove(d)
    del v1, v2, a, d

if sqlite is None:
  del sqlite
  raise ImportError('cannot import SQLite with the FTS3 module')
