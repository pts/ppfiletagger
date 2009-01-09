#! /bin/bash --
#
# build_pysqlite.h: download and build pysqlite
# by pts@fazekas.hu at Thu Jan  8 09:33:38 CET 2009
#
# This shell script downloads SQLite and pysqlite, and builds pysqlite to
# py.local with an FTS3-enabled SQLite statically linked to it.
#
# Prepare with:
#
#   $ apt-get install python2.4 python2.4-dev make gcc libc6-dev

# A Python source tree root.
TARGETDIR="${TARGETDIR:-py.local}"
TMPDIR="${TMPDIR:-tmp.pysqlite}"

set -ex
mkdir -p "$TMPDIR"
test -d "$TMPDIR"

if test \! -f "$TMPDIR/amalgamation.zip" || test "$1" == --download; then
  if wget -O "$TMPDIR/amalgamation.zip" http://www.sqlite.org/sqlite-amalgamation-3_6_7.zip; then
    :
  else
    rm -f "$TMPDIR/amalgamation.zip"
    exit 2
  fi
fi

if test \! -f "$TMPDIR/pysqlite.tar.gz" || test "$1" == --download; then
  if wget -O "$TMPDIR/pysqlite.tar.gz" http://oss.itsystementwicklung.de/download/pysqlite/2.5/2.5.1/pysqlite-2.5.1.tar.gz; then
    :
  else
    rm -f "$TMPDIR/pysqlite.tar.gz"
    exit 2
  fi
fi

rm -rf "$TMPDIR/pysqlite.extract" "$TMPDIR/pysqlite"
mkdir -p "$TMPDIR/pysqlite.extract"
(cd "$TMPDIR/pysqlite.extract"; tar xzvf ../pysqlite.tar.gz)
mv "$TMPDIR/pysqlite.extract/pysqlite-"* "$TMPDIR/pysqlite"
test -f "$TMPDIR/pysqlite/src/cursor.c"

# This is a little superfluous, setup.py can download itself
# (but it forgets to create the sqlite3.h symlink).
rm -rf "$TMPDIR/pysqlite/amalgamation"
mkdir -p "$TMPDIR/pysqlite/amalgamation"
(cd "$TMPDIR/pysqlite/amalgamation"; unzip ../../amalgamation.zip)
test "$?" = 0  # Exit if subshell failed.
test -f "$TMPDIR/pysqlite/amalgamation/sqlite3.h"
test -f "$TMPDIR/pysqlite/amalgamation/sqlite3.c"
ln -s ../amalgamation/sqlite3.h "$TMPDIR/pysqlite/src/sqlite3.h"

# * build_static enables FTS3 by default.
# * gcc -O2 optimization is used to build sqlite3.c
grep SQLITE_ENABLE_FTS3 "$TMPDIR/pysqlite/setup.py"
(cd "$TMPDIR/pysqlite" && python2.4 setup.py build_static)
test "$?" = 0  # Exit if subshell failed.

mkdir -p "$TARGETDIR/pysqlite2"
cp "$TMPDIR/pysqlite/build"/lib.*/pysqlite2/{_sqlite.so,__init__.py,dbapi2.py} "$TARGETDIR/pysqlite2"
strip "$TARGETDIR/pysqlite2/_sqlite.so"
# This also creates $TARGETDIR/pysqlite2/*.pyc
PYTHONPATH="$TARGETDIR:$PYTHONPATH" python2.4 "$TMPDIR/pysqlite/pysqlite2/test/dbapi.py"

: All OK, see "$TARGETDIR/pysqlite2"
