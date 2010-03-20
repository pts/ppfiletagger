#! /usr/bin/python2.4

"""Import a good version of the `xattr' module.

Usage:

  from ppfiletagger.good_xattr import xattr

instead of:

  import xattr
"""

version = None
try:
  import xattr
  version = getattr(xattr, '__version__', None)
except ImportError:
  xattr = version = None

if version is None or version < '0.2.2':  # same check as in rdiff-backup
  try:
    # i386, Python 2.4
    from ppfiletagger.good import xattr
  except ImportError:
    pass
del version

if xattr is None:
  del xattr
  raise ImportError('cannot import xattr (try installing a recent pyxattr)')
