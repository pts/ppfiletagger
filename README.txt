README for ppfiletagger
"""""""""""""""""""""""
ppfiletagger lets you tag your Linux files and then search for filenames
matching the tags you specify. ppfiletagger is a collection of Linux
software (including a Linux 2.6 kernel module and Python utilities).
ppfiletagger works by generating an index (in SQLite database files) of the
filesystem metadata (extended attributes and names of files), updating the
index on-line (getting the filesystem update events from the kernel module),
and querying the index (including full-text search on tags).

ppfiletagger is work in progress alpha software. Once finished, it is going
to be a safer (and eventually faster) replacement of movemetafs; it will
probably be able to communicate with other filesystem indexing software such
as Beagle; and it will contain a web application for tagging files and
searching for them.

TODO: write this README
TODO: write about system design, why is rescanning safe?
TODO: write about what happens if we remount elsewhere?
TODO: write about what happens if we move the hard drive?
TODO: write how not to run the scanner as root

System requirements
~~~~~~~~~~~~~~~~~~~
ppfiletagger needs:

* A Linux system running kernel 2.4 or later.
* Filesystems with extended attribute support (such as ext2, ext3, ext4, xfs
  and reiserfs), and user.* extended attributes turned on (mount -o
  user_xattr).
* Python 2.4.
* libattr1 (tried with 2.4.32; on Debian Etch: apt-get install libattr1;
  included, linked against python-2.4.4 and libc-2.3.6).
* Recommeded: attr (command setfattr; on Debian Etch: apt-get install attr).
* SQLite (version 3.6.7 included, static, linked against libc-2.3.6).
* pysqlite (included, linked against python-2.4.4 and libc-2.3.6).
* pyxattr (linked against python-2.4.4 and static libattr1-2.4.32).
* For the incremental rescanning feature, the provided Linux kernel module
  rmtimeup.ko has to be loaded. It needs:
** A Linux system running kernel 2.6 on i386 (x86) 32-bit architecture.
   Other architectures, including 64-bit (x86-64, amd64, ia64) are not
   supported. See more in rmtimeup/rmtimeup.txt .
** Kernel loadable module support (LKM, CONFIG_MODULES=y).

How to install and use
~~~~~~~~~~~~~~~~~~~~~~
If you'd like to use the the incremental rescanning feature (not needed for
the first time trying out ppfiletagger, but it is strongly recommended in
the long run for performance reasons), make sure that the rmtimeup.ko
kernel module is installed and loaded. For installing the rmtimeup.ko kernel
module, see the installation instructions in rmtimeup/rmtimeup.txt .

Create new Linux user `rmtimescan' whose UID rmtimscan.py will use for
scanning all filesystems and building the index of files with extended
attributes. You can skip this step and use your regular user if it can reach
and read the files you want to index.

Mount all filesystems on which you want to tag files, create extended
attributes, and build the index for. Let's call these ``media filesystems''.
Make sure you allow user.* extended attributes (mount -o user_xattr, e.g.
mount / -o remount,user_xattr).

Make sure that your media filesystems are consistent with your system clock,
i.e no directories have an mtime larger than the current system time. If you
keep having such directories, rmtimescan may not find files (recursively)
in them upon the incremental rescanning.

Add metadata to your files' extended attributes. For example:

  $ setfattr -n user.xattr1 -v value1 /media/big/my/album/photo01.jpg
  $ setfattr -n user.mmfs.tags   -v '2009 nature Europe' /media/big/my/a/*.jpg
  $ setfattr -n user.mmfs.tags   -v 'calendar 2009' /media/big2/calendar09.txt

Please note that the extended attribute `user.mmfs.tags' has special
sigificance: it is the whitespace-separated list of tags (keywords)
associated to the file.  You can use the characters a-zA-Z0-9_: in tag
names.  Tag names are case preserving, but tag search is case insensitive. 
See more information about tag syntax later.

Add some tags for all files you want to search for. Specify them using
`setfattr -n user.mmfs.tags -v ...', as outlined above.  You will be able to
add more tags or change tags later.

For each filesystem you want to build the index for, create the empty files
named `tags.sqlite' and `tags.sqlite-journal', and chown them properly.
For example:

  $ su -
  # touch             /media/big/tags.sqlite{,-journal}
  # chmod 644         /media/big/tags.sqlite{,-journal}
  # chown rmtimescan. /media/big/tags.sqlite{,-journal}

The presence of the tags.sqlite files tells the ppfiletagger tools that
there is an extended attribute index for that filesystem. The file
tags.sqlite contains the index as an SQLite database with a few tables and
an FTS3 full text index for the tags.

Build the index for the first time using:

  $ su rmtimescan -c './rmtimescan.py --slow'

This will take lots of time, longer than `ls -laR' on all the media
filesystems, because it also fetches all user.* extended attributes in
addition to the filenames and the inodes. The second run of rmtimescan.py
(without `--slow') will be much faster, because it does an incremental
rescanning, visiting only paths which have changed -- but this needs the
rmtimeup.ko kernel module.

Search for files by tag using rmtimequery.py:

  $ ./rtimequery.py 2009
  ...
  ('/media/big/my/album/photo01.jpg', '2009 nature Europe')
  ('/media/big/my/album/photo02.jpg', '2009 nature Europe')
  ('/media/big2/calendar09.txt', 'calendar 2009')
  ...
  $ ./rtimequery.py 2009 naTUre
  ...
  ('/media/big/my/album/photo01.jpg', '2009 nature Europe')
  ('/media/big/my/album/photo02.jpg', '2009 nature Europe')
  ...

You specify a cunjunction (``and'') of case insensitive tags in the
rmtimequery.py command line, and rmtimequery.py lists very quickly all files
(and all associated tags) having _all_ the specified tags in their
user.mmfs.tags extended attribute.  The files are listed in no particular
order.

If you have the rmtimeup.ko loaded, then start `rmtimescan.py --forever' in
a new terminal window, like one of those:

  $ su rmtimescan -c './rmtimescan.py --forever'
  $ su rmtimescan -c 'screen -S rmtimescan ./rmtimescan.py --forever'

This will run incremental scanning forever in the background, getting
notified by the rmtimeup.ko kernel module when extended attributes on a
media filesystem get changed, and doing an incremental rescanning each time.

Upon system boot, make sure that rmtimeup.ko is loaded, and `rmtimescan.py
--forever' is started just like above. It doesn't matter how early you start
rmtimescan.py, but it matters how early you load rmtimeup.ko: you should
load it before changing any of your media filesystems -- you can ensure this
by loading the kernel module before your media filesystems get mounted. If
you change your media filesystems before loading rmtimeup.ko, then
the incremental rescan in rmtimescan.py may not find some of your changed
extended attributes.

The index in the tags.sqlite database contains all extended attributes, but
only user.mmfs.tags is searchable so far.

Copyright
~~~~~~~~~
rmtimeup is written and copyright by Peter Szabo <pts@fazekas.hu> from January
2009.

rmtimeup is free software under the GNU GPL v2.

TODO
~~~~
# rmtimescan:
# TODO: Test by using a fake filesystem.
# TODO: Reduce the amount of unnecessary stats, listdirs, and xattrs.get_all()s
#       (also modify rmtimeup).
# TODO: Reduce the amount of database UPDATEs (is a SELECT before an UPDATE
#       really faster?)
# TODO: Add a modified-file-list to rmtimeup, and use mtime-based scanning only
#       as a safety fallback. This will speed up response time.
# TODO: Don't let two instances of rmtimescan.py run at the same time.
# TODO: Ignore or defer SIGINT (KeyboardInterrupt).
# TODO: doc: what kind of mtime clock sync is necessary? what can go wrong?
# rmtimeup:
# TODO: investigate and get rid of this dmesg on umount /mnt/mini:
#       VFS: Busy inodes after unmount of loop0. Self-destruct in 5 seconds.  Have a nice day...
# TODO: add x86_64 64-bit support (including disassembly)
# TODO: use mtime/atime/ctime of fs root inode to detect that it has been
#       mounted without this kernel module. atime detects ls /fsroot, but not
#       any operatin on /fsroot/foo/bar.
#       * propose a solution which survives an unclean umount
#       * ext2 has mount count, last mount time, last write time (tune2fs),
#         reiserfs doesn't have these features
# TODO: test for stability
# TODO: sometime reiserfs fails and loses xattrs:
#       [3532016.778751] REISERFS warning (device dm-2): jdm-20002 reiserfs_xattr_get: Invalid hash for xattr (user.mmfs.tags) associated with [1919251317 1718447406 0x61742e73 UNKNOWN]
#       also elsewhere, but consistent like this:
#       _mmfs_show after setfattr -n user.mmfs.tags -v fort_boyard valerieperez13082005collage49i.jpg
