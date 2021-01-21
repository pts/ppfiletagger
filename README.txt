ppfiletagger: file tagging and search by tag for Linux
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
ppfiletagger lets you tag your Linux files and then search for filenames
matching the tags you specify. ppfiletagger is a collection of Linux
software (including a Linux 2.6 kernel module, Perl script and Python
scripts). Fast search works by generating an index (in SQLite database
files) of the filesystem metadata (extended attributes and names of files),
updating the index incrementally online (getting the filesystem notification
events from the kernel module), and querying the index (including full-text
search on tags).

The basic functionality of ppfiletagger is mature; fast search is beta, and
incremental online index update is alpha, unmaintained, legacy, abandonware.

System requirements
~~~~~~~~~~~~~~~~~~~
The basic functionality of ppfiletagger (tagging and slow search) needs:

* A Linux system running kernel 2.4 or later (known to work with 2.4.32 --
  5.9.12.) or macOS: Mac OS X 10.5 or later.
* A filesystem which supports extended attributes. On Linux, ext2, ext3,
  ext4, ZFS, Btrfs, JFS, XFS etc. On macOS, HFS+ and APFS. On Windows, NTFS.
  Unfortunately, FAT, VFAT, FAT32 and exFAT don't support extended
  attributes.
* On Linux, user.* extended attributes enabled. Do it for / like this:
  sudo mount -o remount,user_xattr /
* For ppfiletagger_shell_functions.sh, Perl >= 5.8.2 (2003-11-05). Such a Perl
  is usually installed on Linux and macOS by default.

Fast search (building the full index (rmtimescan) and doing fast searches
(rmtimequery)) needs:

* A Linux system running kernel 2.4 or later (known to work with 2.4.32 --
  5.9.12.). It may also work on macOS: Mac OS X 10.5 or later, but it is
  not tested.
* Python 2.4, 2.5, 2.6 or 2.7. Python 3.x won't work.
  * Most modern default installations of Python on Linux work. That's
    because it's Python 2.5, 2.6 or 2.7, it contains the ctypes module
    (for reading extended attributes), and it contains the sqlite3 module
    (for writing and querying SQLite database files).
  * For reading extended attributes, any of these:
    * ctypes on Linux. Python 2.5, 2.6 and 2.7 have the ctypes module by
      default, it can also be installed for Python 2.4.
    * dl (`import dl') on Linux i386. Python 2.4, 2.5, 2.6 and 2.7 have
      the dl module by default on Linux i386.
    * xattr (https://pypi.org/project/xattr/ , sudo apt-get install
      python-xattr) >= 0.2.2. Tested with 0.6.4, 0.9.1.
      This should be the preferred solution for Python 2.4 if ctypes and
      dl above don't work. It also works with Python 2.5, 2.6 and 2.7.
      When installing with pip on Linux, libattr1-dev may be needed first
      (sudo apt-get install libattr1-dev). libattr1 version 2.4.32 on
      Debian Etch is known to work, later versions will also work.
      xattr is preferred to pyxattr, because the former has fewer Debian
      package dependencies.
    * pyxattr (https://pypi.org/project/pyxattr/ , sudo apt-get install
      python-pyxattr) >= 0.2.2. Tested with 0.2.2, 0.4.0, 0.5.1, 0.6.4,
      0.9.1. This should be the preferred solution for Python 2.4 if ctypes,
      dl and xattr above don't work. It also works with Python 2.5, 2.6 and
      2.7. When installing with pip on Linux, libattr1-dev may be needed
      first (sudo apt-get install libattr1-dev). libattr1 version 2.4.32 on
      Debian Etch is known to work, later versions will also work.
    * pyxattr 0.4.0 for Linux i386, linked against python 2.4.4, glibc 2.3.6
      and static libattr1 2.4.32, is bundled as ppfiletagger/good/xattr.so .
  * For writing and querying SQLite database files, any of these:
    * sqlite3. Python 2.5, 2.6 and 2.7 have the sqlite3 module by default.
    * pysqlite (https://pypi.org/project/pysqlite/ , sudo apt-get install
      python-pysqlite2).  Tested with 2.5.1.
      This should be the strongly preferred solution for Python 2.4,
      but it also works with Python 2.5, 2.6 and 2.7.
      When installing with pip on Linux, libsqlite3-dev may be needed first
      (sudo apt-get install libseqlite3-dev), libsqlite3 version 3.6.7 and
      above should work.
      Please note that https://pypi.org/project/pysqlite3/ is a different
      project, with a different API, don't install that.
    * pysqlite 2.5.1 for Linux i386, linked against python 2.4.4, glibc 2.3.6
      and static stripped-down libsqlite3 version 3.6.7 is bundled as
      ppfiletagger/good/pysqlite2/_sqlite.so .
* The same filesystem requirements as of the basic functionality.

Incremental online index update needs:

* A Linux system running kernel 2.6 (known to work with 2.6.24 -- 2.6.35) on
  i386 (x86) 32-bit architecture. Other architectures, including 64-bit
  (x86_64 == amd64, arm64, ia64) are not supported. See more in
  rmtimeup/rmtimeup.txt .
* Kernel loadable module support (LKM, CONFIG_MODULES=y).
* The Linux kernel module rmtimeup.ko provided in the rmtimeup directory of
  ppfiletagger has to be compiled and loaded.
* The same filesystem requirements as of the basic functionality.
* The same Python dependencies as for fast search.

Optional, for debugging only:

* attr (command-line tools setfattr and getfattr).
  On Debian Etch: apt-get install attr
* sqlite3 command-line tool. The provided executable sqlite3-3.6.7.bin
  contains SQLite version 3.6.7, it is compiled for Linux i386, and it
  links against glibc-2.3.6. See more sqlite3 executables for Linux and
  macOS in https://github.com/pts/pts-sqlite3-tool-build/releases .

How to install and use
~~~~~~~~~~~~~~~~~~~~~~
Tagging and slow search
"""""""""""""""""""""""
Mount all filesystems on which you want to tag files, create extended
attributes, and build the index for. Let's call these ``media filesystems''.
Make sure you allow user.* extended attributes (`mount -o user_xattr', e.g.
`sudo mount -o remount,user_xattr /').

Add metadata to your files' extended attributes. For example:

  $ setfattr -n user.xattr1 -v value1 /media/big/my/album/photo01.jpg
  $ setfattr -n user.mmfs.tags -v '2009 nature Europe' /media/big/my/a/*.jpg
  $ setfattr -n user.mmfs.tags -v 'calendar 2009' /media/big2/calendar09.txt

Please note that the extended attribute `user.mmfs.tags' has special
significance: it is the whitespace-separated list of tags (keywords)
associated to the file.  You can use the characters a-zA-Z0-9_: in tag
names.  Tag names are case preserving, but tag search is case insensitive.
See more information about tag syntax later.

Alternatively, use ppfiletagger_shell_functions.sh to add and remove tags:

  $ eval "$(./ppfiletagger_shell_functions.sh --load)"
  $ (echo 2009; echo 2010; echo nature; echo Europe; echo calendar) >
    ~/.ppfiletagger_tags
  $ _mmfs tag '2010 nature' /media/big/my/a/*.jpg
  $ _mmfs tag '2009 -2010 Europe' /media/big/my/a/*.jpg
  $ _mmfs tag 'calendar 2009' /media/big2/calendar09.txt

Add some tags for all files you want to search for. Specify them using
ppfiletagger_shell_functions.sh or `setfattr -n user.mmfs.tags -v ...', as
outlined above. You will be able to add more tags or change tags later.

After adding tags, you can already find files matching a query:

  $ eval "$(./ppfiletagger_shell_functions.sh --load)"
  $ _mmfs find '2009' /media/big/my/a
  /media/big/my/album/photo01.jpg
  /media/big/my/album/photo02.jpg
  ...
  $ _mmfs find --format=colon '2009 -nature' /media/big2
  calendar 2009 :: /media/big2/calendar09.txt
  ...

Please note that the `_mmfs find' command is very slow (may take several
minutes), because it does a recursive file and diretory scan, and it
retrieves the user.mmfs.tags extended attribute for each file, typically
needing 4 disk seeks per file. See below for fast search.

Midnight Commander (mc) integration
"""""""""""""""""""""""""""""""""""
With Midnight Commander integration, you can add or remove tags, and show
tags of specified files. (Search by tag is not implemented.)

To install it, append ppfiletagger_mc.menu (or, better insert it after the
first `#...; comment block) to your ~/.config/mc/menu (older systems have
~/.mc/menu), and restart Midnight Commander.

Then use <F2> <T> to add or remove tags to the current file or to the
selected files. In the dialog that pops up, type the list of changes, e.g.
`2009 -2010' (without quotes) would add the tag 2009 and remove the tag 2010.

Use <F2> <S> to show tags of the current file or of the selected files.

Fast search with rmtimescan and rmtimequery
"""""""""""""""""""""""""""""""""""""""""""
For fast search, use `rmtimescan --slow' to build or rebuild a search index
(database), and use rmtimequery to run the search using the index (typically
finishes faster than 1 second).

On modern Linux systems, fast search won't work, because the rmtimescan and
rmtimequery tools have some Python 2.x dependencies (an old bundled pyxattr
package and an old bundled pysqlite2 package). On very modern systems
(released in 2020 or later), Python 2.x may not even be available anymore.

Create new Linux user `rmtimescan' whose UID rmtimscan.py will use for
scanning all filesystems and building the index of files with extended
attributes.

Make sure that your media filesystems are consistent with your system clock,
i.e no directories have an mtime larger than the current system time. If you
keep having such directories, rmtimescan may not find files (recursively)
in them upon the incremental rescanning.

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

  $ su rmtimescan -c './rmtimescan --slow'

You can run the command above to rebuild the index (e.g. after adding and
removing tags). Rebuilding the index takes the same amount of time as
building it, typically several minutes on an HDD, because it needs 4 disk
seeks per file.

This will take lots of time, longer than `ls -laR' on all the media
filesystems, because it also fetches all user.* extended attributes in
addition to the filenames and the inodes. The second run of rmtimescan
(without `--slow') will be much faster, because it does an incremental
rescanning, visiting only paths which have changed -- but this needs the
rmtimeup.ko kernel module.

Search for files by tag using rmtimequery:

  $ ./rtimequery 2009
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
rmtimequery command line, and rmtimequery lists very quickly all files
(and all associated tags) having _all_ the specified tags in their
user.mmfs.tags extended attribute.  The files are listed in no particular
order.

Incremental online index update with rmtimeup.ko
""""""""""""""""""""""""""""""""""""""""""""""""
Incremental online index update keeps the index up-to-date (with a few
seconds or minutes of delay) so that you don't have to run `rmtimescan
--slow' manually or wait for it to finish (typically several minutes).
To do so, the Linux kernel module rmtimeup.ko has to be loaded (because it
helps rmtimescan do an incremental file and directory scan, avoiding
directory subtrees which haven't changed recently), and `rmtimescan
--forever' has to be running in the background. For installing the
rmtimeup.ko kernel module, see the installation instructions in
rmtimeup/rmtimeup.txt .

On modern Linux systems (anything more recent than Ubuntu 10.04 Lucid,
released in 2010-04), the kernel module won't work, because the system has a
more recent, incompatible kernel. Also the kernel module requires the i386
(x86) 32-bit architecture, and modern Linux systems tend to use 64-bit
architectures (e.g. x86_64 == amd64, arm64, ia64) instead.

Incremental online index update in ppfiletagger is safer (and bit slower)
than in movemetafs (https://github.com/pts/movemetafs), because there are
much fewer ways for the filesystem and the database to diverge and go out of
sync beyond easy repair. However, ppfiletagger (rmtimeup.ko) can crash the
entire system if there are some memory or thread safety issues in the C
source code of rmtimeup.ko (probably there are some), but movemetafs uses
FUSE, so the system won't ever crash because of a bug in movemetafs.

After you have loaded the kernel module rmtimeup.ko, start `rmtimescan
--forever' in a new terminal window, like one of these:

  $ su rmtimescan -c './rmtimescan --forever'
  $ su rmtimescan -c 'screen -S rmtimescan ./rmtimescan --forever'

This will run incremental scanning forever in the background, getting
notified by the rmtimeup.ko kernel module when extended attributes on a
media filesystem get changed, and doing an incremental rescanning each time.

Upon system boot, make sure that rmtimeup.ko is loaded, and `rmtimescan
--forever' is started just like above. It doesn't matter how early you start
rmtimescan, but it matters how early you load rmtimeup.ko: you should
load it before changing any of your media filesystems -- you can ensure this
by loading the kernel module before your media filesystems get mounted. If
you change your media filesystems before loading rmtimeup.ko, then
the incremental rescan in rmtimescan may not find some of your changed
extended attributes.

The index in the tags.sqlite database contains all extended attributes, but
only user.mmfs.tags is searchable so far.

Copyright
~~~~~~~~~
rmtimeup is written and copyright by Peter Szabo <pts@fazekas.hu> from January
2009.

rmtimeup is free software under the GNU GPL v2.

Future plans
~~~~~~~~~~~~
The future plans of ppfiletagger, in 2021:

* Make the query language of rmtimequery and ppfiletagger_shell_functions.sh
  the same, adding the missing features to both. Also document the query
  language.

* Add each other's --format=... values to rmtimequery and
  ppfiletagger_shell_function.sh.

The old (2009), obsolete, future plans of ppfiletagger:

* Add communication with other filesystem indexing software such as Beagle.

* Add a web application for tagging files and searching by tag.

TODO
~~~~
# rmtimequery:
# TODO: make search case sensitive, for compatibility with
#       ppfiletagger_shell_functions.sh
# TODO: add only tags (no other extended attributes) to the database
# TODO: implement --format=name, --format=tuple, --format=mclist in
#       ppfiletagger_shell_functions.sh
# TODO: ppfiletagger_shell_functions.sh fnq should quote empty string
# TODO: ppfiletagger_shell_functions.sh shouldn't follow symlinks to directories
# TODO: add Midnight Commander integration for search
# rmtimescan:
# TODO: doc: write about what happens if we remount elsewhere
# TODO: doc: write about what happens if we move the hard drive
# TODO: Test by using a fake filesystem.
# TODO: Reduce the amount of unnecessary stats, listdirs, and xattrs.get_all()s
#       (also modify rmtimeup).
# TODO: Reduce the amount of database UPDATEs (is a SELECT before an UPDATE
#       really faster?)
# TODO: Add a modified-file-list to rmtimeup, and use mtime-based scanning only
#       as a safety fallback. This will speed up response time.
# TODO: Don't let two instances of rmtimescan run at the same time.
# TODO: Ignore or defer SIGINT (KeyboardInterrupt).
# TODO: doc: what kind of mtime clock sync is necessary? what can go wrong?
# TODO: use large transactions to speed up the update
# rmtimeup.ko:
# TODO: doc: write about system design, why is rescanning safe?
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
# TODO: sometimes reiserfs fails and loses xattrs:
#       [3532016.778751] REISERFS warning (device dm-2): jdm-20002 reiserfs_xattr_get: Invalid hash for xattr (user.mmfs.tags) associated with [1919251317 1718447406 0x61742e73 UNKNOWN]
#       also elsewhere, but consistent like this:
#       _mmfs_show after setfattr -n user.mmfs.tags -v fort_boyard valerieperez13082005collage49i.jpg
