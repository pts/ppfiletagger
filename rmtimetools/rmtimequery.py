#! /usr/bin/python2.4
#
# rmtimequery: query the xattr databases for tag full-text search
# by pts@fazekas.hu at Sun Jan 11 05:54:42 CET 2009
#

if __name__ == '__main__':
  import os.path
  import logging
  import sys
  logging.BASIC_FORMAT = '[%(created)f] %(levelname)s %(message)s'
  logging.root.setLevel(logging.INFO)  # Prints INFO, but not DEBUG.
  prog_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
  sys.path[:] = [dir for dir in sys.path if dir not in (prog_dir, '.')]
  local_dir = None
  for i in xrange(len(prog_dir.split('/'))):
    local_dir = prog_dir + '/py.local'
    if os.path.isdir(local_dir): break
    local_dir = None
    prog_dir += '/..'
  if local_dir is None:
    logging.info('starting without local_dir')
  else:
    logging.info('starting local_dir=%r' % local_dir)
    sys.path[: 0] = [local_dir]
  sys.exit(
      __import__('pts.rmtimetools.query', {}, {}, ('',)).main(sys.argv) or 0)
