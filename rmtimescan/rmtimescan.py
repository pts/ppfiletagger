#! /usr/bin/python2.4
#
# rmtimescan.py: command line utility for pts.rmtimescan.scan
# by pts@fazekas.hu at Sat Jan 10 20:09:57 CET 2009
#

if __name__ == '__main__':
  import os.path
  import logging
  import sys
  logging.BASIC_FORMAT = '[%(created)f] %(levelname)s %(message)s'
  logging.root.setLevel(logging.INFO)  # Prints INFO, but not DEBUG.
  prog_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
  try:
    sys.path.remove(prog_dir)
  except ValueError:
    pass
  try:
    sys.path.remove('.')
  except ValueError:
    pass
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
  __import__('pts.rmtimescan.scan', {}, {}, ('',)).main(sys.argv)
