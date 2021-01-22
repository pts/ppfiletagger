#! /bin/sh --
#
# rebuild Python packages in Ubuntu 8.04 (Hardy) chroot
# by pts@fazekas.hu at Fri Jan 22 13:54:36 CET 2021
#
# The resulting .so files will be dynamically linked against glibc 2.7
# (libc.so.6 and libpthread.so.0) and will work with Python 2.4.
#
# About setting up the qq command used by this build:
#
#   $ git clone https://github.com/pts/pts-chroot-env-qq
#   $ ln -s pts_chroot_env_qq.sh pts-chroot-env-qq/qq
#   $ export PATH="$PWD/pts-chroot-env-qq:$PATH"
#

set -ex

sudo rm -rf hardy32.dir hardy64.dir

qq pts-debootstrap --arch i386 hardy hardy32.dir
(cd hardy32.dir/tmp && qq root sh -c 'exec >/etc/apt/sources.list;
 for X in hardy hardy-updates hardy-security; do
 echo deb http://old-releases.ubuntu.com/ubuntu "$X" main; done') || exit "$?"
(cd hardy32.dir/tmp && qq apt-get update) || exit "$?"
# We use libattr1-dev only for the headers. glibc has setxattr etc.
(cd hardy32.dir/tmp &&
 qq apt-get install -y python2.4-dev gcc libc6-dev unzip libattr1-dev) ||
  exit "$?"
rm -rf tmp.pysqlite
./build_pysqlite.sh --no-build  # Just download sources to tmp.pysqlite.
cp -a build_pysqlite.sh tmp.pysqlite hardy32.dir/tmp/
(cd hardy32.dir/tmp && qq ./build_pysqlite.sh)
rm -rf tmp.pyxattr
./build_pyxattr.sh --no-build  # Just download sources to tmp.pyxattr.
cp -a build_pyxattr.sh tmp.pyxattr hardy32.dir/tmp/
(cd hardy32.dir/tmp && qq ./build_pyxattr.sh)
mv hardy32.dir/tmp/py.local ppfiletagger/py24_linux_i386
rm -rf hardy32.dir/tmp/py.local/pyxattr
sudo rm -rf hardy32.dir

qq pts-debootstrap --arch amd64 hardy hardy64.dir
(cd hardy64.dir/tmp && qq root sh -c 'exec >/etc/apt/sources.list;
 for X in hardy hardy-updates hardy-security; do
 echo deb-src http://old-releases.ubuntu.com/ubuntu "$X" main
 echo deb http://old-releases.ubuntu.com/ubuntu "$X" main; done')
(cd hardy64.dir/tmp && qq apt-get update) || exit "$?"
(cd hardy64.dir/tmp &&
 qq apt-get install -y python2.4-dev gcc libc6-dev unzip libattr1-dev) ||
  exit "$?"
rm -rf tmp.pysqlite
./build_pysqlite.sh --no-build  # Just download sources to tmp.pysqlite.
cp -a build_pysqlite.sh tmp.pysqlite hardy64.dir/tmp/
(cd hardy64.dir/tmp && qq ./build_pysqlite.sh) || exit "$?"
rm -rf tmp.pyxattr
./build_pyxattr.sh --no-build  # Just download sources to tmp.pyxattr.
cp -a build_pyxattr.sh tmp.pyxattr hardy64.dir/tmp/
(cd hardy64.dir/tmp && qq ./build_pyxattr.sh)
rm -rf hardy64.dir/tmp/py.local/pyxattr
mv hardy64.dir/tmp/py.local ppfiletagger/py24_linux_amd64
sudo rm -rf hardy64.dir

: "$0" OK.
