#! /bin/bash --
#
# build_pyxattr.h: download and build pyxattr
# by pts@fazekas.hu at Fri Jan  9 10:41:46 CET 2009
#
# This shell script downloads pyxattr, and builds it into py.local.
#
# Prepare with:
#
#   $ apt-get install python2.4 python2.4-dev make gcc libc6-dev
#   $ apt-get install libattr1-dev python-setuptools

# A Python source tree root.
TARGETDIR="${TARGETDIR:-py.local}"
TMPDIR="${TMPDIR:-tmp.pyxattr}"

set -ex
mkdir -p "$TMPDIR"
test -d "$TMPDIR"

if test \! -f "$TMPDIR/pyxattr.tar.gz" || test "$1" == --download; then
  # Old URL: http://kent.dl.sourceforge.net/sourceforge/pyxattr/pyxattr-0.4.0.tar.gz
  if wget -O "$TMPDIR/pyxattr.tar.gz" http://github.com/pts/ppfiletagger/releases/download/python2.4src/pyxattr-0.4.0.tar.gz; then
    :
  else
    rm -f "$TMPDIR/pyxattr.tar.gz"
    exit 2
  fi
fi

rm -rf "$TMPDIR/pyxattr.extract" "$TMPDIR/pyxattr"
mkdir -p "$TMPDIR/pyxattr.extract"
(cd "$TMPDIR/pyxattr.extract"; tar xzvf ../pyxattr.tar.gz)
mv "$TMPDIR/pyxattr.extract/pyxattr-"* "$TMPDIR/pyxattr"
test -f "$TMPDIR/pyxattr/xattr.c"

# Use distutils instead of setuptools, in case setuptools is not available.
perl -pi -e 's@^#*@#@ if m@import@ and m@setuptools@; s@^#*@@ if m@import@ and m@distutils@' "$TMPDIR/pyxattr/setup.py"
# Link -lattr statically.
test -f /lib/libattr.a && perl -pi -e 's@libraries=\[[^\]]*\]@extra_objects=["/lib/libattr.a"]@' "$TMPDIR/pyxattr/setup.py"
(cd "$TMPDIR/pyxattr" && python2.4 setup.py build)
test "$?" = 0  # Exit if subshell failed.

mkdir -p "$TARGETDIR/pyxattr"
cp "$TMPDIR/pyxattr/build"/lib.*/xattr.so "$TARGETDIR/xattr.so"
strip "$TARGETDIR/xattr.so"
## This also creates $TARGETDIR/pyxattr2/*.pyc
# no main function: PYTHONPATH="$TARGETDIR:$PYTHONPATH" python2.4 "$TMPDIR/pyxattr/test/test_xattr.py"
PYTHONPATH="$TARGETDIR:$PYTHONPATH" python2.4 -c 'import xattr; print xattr.listxattr; print xattr.setxattr; print xattr.listxattr("/bin/sh")'

: All OK, see "$TARGETDIR/xattr.so"
