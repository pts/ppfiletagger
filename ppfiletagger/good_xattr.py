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

if (getattr(xattr, 'get_all', ()) is not () and
    getattr(xattr, 'NS_USER', ()) is not ()):  # e.g. pyxattr-0.2.2
  get_all, NS_USER = xattr.get_all, xattr.NS_USER
elif (getattr(xattr, 'listxattr', ()) is not () and
      getattr(xattr, 'getxattr', ()) is not ()):  # e.g. xattr-0.6.4
  NS_USER = 'user.'
  def get_all(filename, namespace=''):  # Example namespace: NS_USER.
    # xattr.listxattr and xattr.getxattr may raise IOError or OSError, of which
    # EnvironmentError is a superclass.
    result, ln = [], len(namespace)
    for key in xattr.listxattr(filename):  # Doesn't follow symlinks.
      if isinstance(key, unicode):
        key = key.encode('utf-8')
      if key.startswith(namespace):
        value = xattr.getxattr(filename, key)  # Doesn't follow symlinks.
        result.append((key[ln:], value))
    return result
else:
  del xattr
  raise ImportError('cannot use xattr (try installing a recent pyxattr)')
