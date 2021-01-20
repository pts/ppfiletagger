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

if (getattr(xattr, 'listxattr', ()) is not () and
    getattr(xattr, 'getxattr', ()) is not ()):  # e.g. pyxattr-0.2.2, pyxattr-0.4.0, pyxattr-0.6.4, pyxattr-0.9.1
  import errno
  if getattr(errno, 'ENOATTR', None):  # Mac OS X.
    ENOATTR = errno.ENOATTR
  else:  # Linux.
    ENOATTR = errno.ENODATA
  NS_USER = 'user.'
  def get_all(filename, namespace=''):  # Example namespace: NS_USER.
    # xattr.listxattr and xattr.getxattr may raise IOError or OSError, of which
    # EnvironmentError is a superclass.
    result, ln = [], len(namespace)
    for key in xattr.listxattr(filename):  # Follows sylinks.
      key_str = key
      if isinstance(key, unicode):
        key_str = key.encode('utf-8')
      if key_str.startswith(namespace):
        try:
          value = xattr.getxattr(filename, key)  # Follows symlinks.
          result.append((key_str[ln:], value))
        except EnvironmentError, e:  # (IOError, OSError).
          if e[0] != ENOATTR:
            raise
    return result
elif (getattr(xattr, 'get_all', ()) is not () and
      getattr(xattr, 'NS_USER', ()) is not ()):  # e.g. pyxattr-0.4.0
  # Follows symlinks. Good.
  get_all, NS_USER = xattr.get_all, xattr.NS_USER
else:
  del xattr
  raise ImportError('cannot use xattr (try installing a recent pyxattr)')
