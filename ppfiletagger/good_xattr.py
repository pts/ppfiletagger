"""Listing and reading extended attributes."""

XATTR_KEYS = ('getxattr', 'listxattr')

XATTR_DOCS = {
    'getxattr': """Get an extended attribute of a file.

Args:
  filename: Name of the file or directory.
  xattr_name: Name of the extended attribute.
  do_not_follow_symlinks: Bool prohibiting to follow symlinks, False by
    default, so it follows symlinks.
Returns:
  str containing the value of the extended attribute, or None if the file
  exists, but doesn't have the specified extended attribute.
Raises:
  OSError: If the file does not exists or the extended attribute cannot be
    read.
""",
    'listxattr': """List the extended attributes of a file.

Args:
  filename: Name of the file or directory.
  do_not_follow_symlinks: Bool prohibiting to follow symlinks, False by
    default, so it follows symlinks.
Returns:
  (New) list of str containing the extended attribute names.
Raises:
  OSError: If the file does not exists or the extended attributes cannot be
    read.
""",
}


def _xattr_doc(name, function):
  function.__doc__ = XATTR_DOCS[name]
  return name, function


def xattr_impl_xattr_xattr():
  import errno

  # sudo apt-get install python-xattr
  # or: sudo apt-get install libattr1-dev && pip install xattr
  #
  # Please note that there is python-pyxattr, it doesn't work.
  import xattr

  XATTR_ENOATTR = getattr(errno, 'ENOATTR', getattr(errno, 'ENODATA', 0))
  del errno  # Save memory.

  def getxattr(filename, attr_name, do_not_follow_symlinks=False):
    try:
      # This does 2 lgetattxattr(2) syscalls, the first to determine size.
      return xattr._xattr.getxattr(
          filename, attr_name, 0, 0, do_not_follow_symlinks)
    except EnvironmentError, e:
      if e[0] != XATTR_ENOATTR:
        # We convert the IOError raised by the _xattr module to OSError
        # expected from us.
        raise OSError(e[0], e[1])
      return None

  def listxattr(filename, do_not_follow_symlinks=False):
    # Please note that xattr.listxattr returns a tuple of unicode objects,
    # so we have to call xattr._xattr.listxattr to get the str objects.
    try:
      data = xattr._xattr.listxattr(filename, do_not_follow_symlinks)
    except EnvironmentError, e:
      raise OSError(e[0], e[1])
    if data:
      assert data[-1] == '\0'
      data = data.split('\0')
      data.pop()  # Drop last empty string because of the trailing '\0'.
      return data
    else:
      return []

  return dict(_xattr_doc(k, v) for k, v in locals().iteritems()
              if k in XATTR_KEYS)


# E.g. *xattr-0.2.2, *xattr-0.4.0, *xattr-0.5.1, *xattr-0.6.4, *xattr-0.9.1.
# pyxattr-0.4.0 also has .get_all(...), but we don't use it, for
# compatibility.
def xattr_impl_xattr():
  import errno

  # sudo apt-get install python-xattr
  # or: sudo apt-get install libattr1-dev && pip install xattr
  #
  # Please note that there is python-pyxattr, it also works:
  #
  # sudo apt-get install python-pyxattr
  # or: sudo apt-get install libattr1-dev && pip install pyxattr

  import xattr

  XATTR_ENOATTR = getattr(errno, 'ENOATTR', getattr(errno, 'ENODATA', 0))
  del errno  # Save memory.

  def getxattr(filename, attr_name, do_not_follow_symlinks=False):
    try:
      # This does 2 lgetattxattr(2) syscalls, the first to determine size.
      return xattr.getxattr(filename, attr_name, do_not_follow_symlinks)
    except EnvironmentError, e:
      if e[0] != XATTR_ENOATTR:
        raise OSError(e[0], e[1])
      return None

  def listxattr(filename, do_not_follow_symlinks=False):
    # Please note that xattr.listxattr returns a tuple of unicode objects,
    # so we have to call xattr._xattr.listxattr to get the str objects.
    try:
      data = xattr.listxattr(filename, do_not_follow_symlinks)
    except EnvironmentError, e:
      raise OSError(e[0], e[1])
    if not isinstance(data, list):
      data = list(data)
    for i in xrange(len(data)):
      if isinstance(data[i], unicode):
        data[i] = data[i].encode('utf-8')
    return data

  return dict(_xattr_doc(k, v) for k, v in locals().iteritems()
              if k in XATTR_KEYS)


def xattr_impl_dl():
  import dl  # Only i386, in Python >= 2.4.
  import errno
  import os
  import struct

  LIBC_DL = dl.open(None)
  XATTR_ENOATTR = getattr(errno, 'ENOATTR', getattr(errno, 'ENODATA', 0))
  XATTR_ERANGE = errno.ERANGE
  del errno  # Save memory.
  assert struct.calcsize('l') == 4  # 8 on amd64.

  def getxattr(filename, attr_name, do_not_follow_symlinks=False):
    getxattr_name = ('getxattr', 'lgetxattr')[bool(do_not_follow_symlinks)]
    # TODO(pts): Do we need to protect errno in multithreaded code?
    errno_loc = LIBC_DL.call('__errno_location')
    err_str = 'X' * 4
    value = 'x' * 256
    got = LIBC_DL.call(getxattr_name, filename, attr_name, value, len(value))
    if got < 0:
      LIBC_DL.call('memcpy', err_str, errno_loc, 4)
      err = struct.unpack('i', err_str)[0]
      if err == XATTR_ENOATTR:
        # The file exists, but doesn't have the specified xattr.
        return None
      elif err != XATTR_ERANGE:
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      got = LIBC_DL.call(getxattr_name, filename, attr_name, None, 0)
      if got < 0:
        LIBC_DL.call('memcpy', err_str, errno_loc, 4)
        err = struct.unpack('i', err_str)[0]
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      assert got > len(value)
      value = 'x' * got
      # We have a race condition here, someone might have changed the xattr
      # by now.
      got = LIBC_DL.call(getxattr_name, filename, attr_name, value, got)
      if got < 0:
        LIBC_DL.call('memcpy', err_str, errno_loc, 4)
        err = struct.unpack('i', err_str)[0]
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      return value
    assert got <= len(value)
    return value[:got]

  def listxattr(filename, do_not_follow_symlinks=False):
    listxattr_name = ('listxattr', 'llistxattr')[bool(do_not_follow_symlinks)]
    errno_loc = LIBC_DL.call('__errno_location')
    err_str = 'X' * 4
    value = 'x' * 256
    got = LIBC_DL.call(listxattr_name, filename, value, len(value))
    if got < 0:
      LIBC_DL.call('memcpy', err_str, errno_loc, 4)
      err = struct.unpack('i', err_str)[0]
      if err != XATTR_ERANGE:
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      got = LIBC_DL.call(listxattr_name, filename, None, 0)
      if got < 0:
        LIBC_DL.call('memcpy', err_str, errno_loc, 4)
        err = struct.unpack('i', err_str)[0]
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      assert got > len(value)
      value = 'x' * got
      # We have a race condition here, someone might have changed the xattr
      # by now.
      got = LIBC_DL.call(listxattr_name, filename, value, got)
      if got < 0:
        LIBC_DL.call('memcpy', err_str, errno_loc, 4)
        err = struct.unpack('i', err_str)[0]
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
    if got:
      assert got <= len(value)
      assert value[got - 1] == '\0'
      return value[:got - 1].split('\0')
    else:
      return []

  return dict(_xattr_doc(k, v) for k, v in locals().iteritems()
              if k in XATTR_KEYS)


def xattr_impl_ctypes():
  import ctypes  # Python >= 2.6. Tested with both i386 and amd64.
  import errno
  import os

  if getattr(ctypes, 'get_errno', None):  # Python >=2.6.
    LIBC_CTYPES = ctypes.CDLL(None, use_errno=True)  # Also: 'libc.so.6'.
    get_errno = ctypes.get_errno
    def errcheck(ret, func, args):
      if ret < 0:
        return -get_errno()
      return ret
  else:  # Workaround for ctypes in Python 2.5.
    # https://stackoverflow.com/a/661303
    LIBC_CTYPES = ctypes.CDLL(None)
    errno_location = LIBC_CTYPES['__errno_location']
    errno_location.restype = ctypes.POINTER(ctypes.c_int)
    def errcheck(ret, func, args):
      if ret < 0:
        return -errno_location()[0]
      return ret
  functions = {}
  for k in ('lgetxattr', 'getxattr', 'llistxattr', 'listxattr'):
    functions[k] = LIBC_CTYPES[k]
    functions[k].errcheck = errcheck
  del LIBC_CTYPES, ctypes  # Save memory.
  XATTR_ENOATTR = getattr(errno, 'ENOATTR', getattr(errno, 'ENODATA', 0))
  XATTR_ERANGE = errno.ERANGE
  del errno  # Save memory.

  def getxattr(filename, attr_name, do_not_follow_symlinks=False):
    getxattr_function = functions[
        ('getxattr', 'lgetxattr')[bool(do_not_follow_symlinks)]]
    value = 'x' * 2048
    got = getxattr_function(filename, attr_name, value, len(value))
    if got < 0:
      err = -got
      if err == XATTR_ENOATTR:
        # The file exists, but doesn't have the specified xattr.
        return None
      elif err != XATTR_ERANGE:
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      got = getxattr_function(filename, attr_name, None, 0)
      if got < 0:
        err = -got
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      assert got > len(value)
      value = 'x' * got
      # We have a race condition here, someone might have changed the xattr
      # by now.
      got = getxattr_function(filename, attr_name, value, got)
      if got < 0:
        err = -got
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      return value
    assert got <= len(value)
    return value[:got]

  def listxattr(filename, do_not_follow_symlinks=False):
    listxattr_function = functions[
        ('listxattr', 'llistxattr')[bool(do_not_follow_symlinks)]]
    value = 'x' * 2048
    got = listxattr_function(filename, value, len(value))
    if got < 0:
      err = -got
      if err != XATTR_ERANGE:
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      got = listxattr_function(filename, None, 0)
      if got < 0:
        err = -got
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
      assert got > len(value)
      value = 'x' * got
      # We have a race condition here, someone might have changed the xattr
      # by now.
      got = listxattr_function(filename, value, got)
      if got < 0:
        err = -got
        raise OSError(err, '%s: %r' % (os.strerror(err), filename))
    if got:
      assert got <= len(value)
      assert value[got - 1] == '\0'
      return value[:got - 1].split('\0')
    else:
      return []

  return dict(_xattr_doc(k, v) for k, v in locals().iteritems()
              if k in XATTR_KEYS)


def xattr_detect():
  import os
  import sys
  is_linux = sys.platform.startswith('linux')
  implspec = os.getenv('PYTHON_XATTR_IMPL', '')

  try:
    if (implspec and implspec != 'ctypes') or not is_linux:
      # TODO(pts): Also support Mac OS X, similarly to
      # ppfiletagger_shell_functions does it (with syscall).
      raise ImportError
    import ctypes
    import errno
    try:
      LIBC_CTYPES = ctypes.CDLL(None)  # Also: 'libc.so.6'.
    except EnvironmentError:
      LIBC_CTYPES = None
    try:
      if LIBC_CTYPES and LIBC_CTYPES['lgetxattr']:
        return xattr_impl_ctypes
    except (KeyError, AttributeError):
      pass
  except ImportError:
    pass

  try:
    if (implspec and implspec != 'dl') or not is_linux:
      raise ImportError
    import struct
    import dl  # Only 32-bit architectures, e.g. i386.
    import errno
    try:
      LIBC_DL = dl.open(None)  # Also: dl.open('libc.so.6')
    except dl.error:
      LIBC_DL = None
    if (LIBC_DL and LIBC_DL.sym('memcpy') and LIBC_DL.sym('__errno_location')
        and LIBC_DL.sym('lgetxattr')):
     return xattr_impl_dl
  except ImportError:
    pass

  # We try this last, because it does 2 syscalls by default.
  try:
    import xattr
    # pyxattr <0.2.2 are buggy.
    if getattr(xattr, '__version__', '') < '0.2.2':
      xattr = None
  except ImportError:
    xattr = None
  if xattr is None and __import__('sys').platform.startswith('linux'):
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
    if os.path.isfile(os.path.join(d, 'xattr.so')):
      __import__('sys').path[:0] = (d,)
      try:
        try:
          # TODO(pts): Do it as a non-global import.
          import xattr
          # pyxattr <0.2.2 are buggy.
          if getattr(xattr, '__version__', '') < '0.2.2':
            xattr = None
          #a = ''  # Always remove from path.
        except ImportError:
          xattr = None
      finally:
        if a and d in __import__('sys').path:
          __import__('sys').path.remove(d)
    del v1, v2, a, d
  if xattr:
    if (not (implspec and implspec != 'xattr_xattr') and
        is_linux and getattr(xattr, '_xattr', None) and
        getattr(xattr._xattr, 'getxattr', None)):
      # This works with python-xattr, but not with python-pyxattr.
      return xattr_impl_xattr_xattr
    elif not (implspec and implspec != 'xattr'):
      # This works with python-xattr and python-pyxattr.
      return xattr_impl_xattr

  raise NotImplementedError(
      'xattr implementation not found or too old. Please install xattr (python-xattr) or ctypes.')
