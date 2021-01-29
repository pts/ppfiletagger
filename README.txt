ppfiletagger: file tagging and search by tag for Unix
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
ppfiletagger lets you tag your files and then search for filenames matching
the tags you specify. Most functionality (tagging, search and full index
building) is implemented as Perl and Python scripts which run Linux, macOS,
FreeBSD, NetBSD and Solaris. A filesystem which supports extended attributes
(xattr) is needed, because tags are stored there. Slow search (mature) works
by doing a recursive file and directory scan, reading and comparing extended
attributes. Full index building (mature) works by doing a recursive file and
directory scan, and adding filenames and extended attributes to an SQLite
database tables with full-text index (FTS3). Fast search (mature) works by
querying the database using full-text search on tags. Incremental, online
index update (alpha, unmaintained, legacy, abandonware, obsolete) needs a
custom Linux 2.6 kernel module and an i386 kernel; it works by getting the
filesystem notification events from the kernel module.

System requirements
~~~~~~~~~~~~~~~~~~~
If you are new to ppfiletagger, don't worry about the requirements, but jump
to the next section (``How to use ppfiletagger'').

The basic functionality of ppfiletagger (tagging and slow search) needs:

* A Linux system running kernel 2.4 or later (known to work with 2.4.32 --
  5.9.12.), or macOS: Mac OS X 10.5 or later, or FreeBSD >=5.0, or
  NetBSD >=4.0, or Solaris >=10. Windows is not supported.
* A filesystem which supports extended attributes. On Linux, ext2, ext3,
  ext4, ZFS, Btrfs, JFS, XFS etc. On macOS, HFS+ and APFS. On Windows, NTFS.
  Unfortunately, FAT, VFAT, FAT32 and exFAT don't support extended
  attributes.
* On Linux, user.* extended attributes enabled. Do it for / like this:
  sudo mount -o remount,user_xattr /
* For ppfiletagger_shell_functions.sh, Perl >= 5.8.2 (2003-11-05). Such a
  Perl is usually installed on Linux and macOS by default. (Test it with:
  `perl -edie' should print `Died at -e line 1.').
* For ppfiletagger_shell_functions.sh, on FreeBSD, NetBSD and Solaris only,
  the https://metacpan.org/pod/File::ExtAttr Perl module installed (i.e. the
  `perl -mFile::ExtAttr -edie' command should print `Died at -e line 1.').
  On Linux and macOS, this Perl module is not needed, it's functionality is
  built in.

Fast search (building the full index (rmtimescan) and doing fast searches
(rmtimequery)) needs:

* A Linux system running kernel 2.4 or later (known to work with 2.4.32 --
  5.9.12.). It may also work on macOS: Mac OS X 10.5 or later, but it is
  not tested.
* Python 2.4, 2.5, 2.6 or 2.7. Python 3.x won't work.
  * To run ppfiletagger on a modern Linux system, just run it.
    That's because the system will typically have Python 2.7. Python 2.5, 2.6
    and 2.7 contain the ctypes module (for reading extended attributes),
    and they contain the sqlite3 module (for writing and querying SQLite
    database files).
  * To run ppfiletagger on an old Linux i386 or amd64 system with Python 2.4,
    it is recommended to use the precompiled Python package dependencies
    (pyxattr and pysqlite). Download
    https://github.com/pts/ppfiletagger/releases/download/python2.4bin/ppfiletagger_py24_linux_packages.tar.gz
    and extract it to the directory containing the file rmtimescan.
  * On any other system, see below for Python package dependencies.

* The same filesystem requirements as of the basic functionality.

Python package dependencies of fast search (relevant only for non-Linux
systems and also relevant for Python 2.4 on other than Linux i386 and Linux
amd64):

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

How to use ppfiletagger
~~~~~~~~~~~~~~~~~~~~~~~
Tagging and slow search
"""""""""""""""""""""""
Open a terminal window, decide about which files to add tags to (in the
example it will be files in /media/big/my/album etc.). If unsure, copy some
.jpgs file from your ~/Downloads or ~/Pictures directory to /tmp , and add
some dummy tags there.

Start adding tags (and other metadata) with the setfattr command (without
typing the leading `$'):

  $ setfattr -n user.mmfs.tags -v '2009 nature Europe' /media/big/my/a/*.jpg
  $ setfattr -n user.mmfs.tags -v 'calendar 2009' /media/big2/calendar09.txt

The actual tags are within the single quotes, e.g. in the example above the
tags are 2009, nature, Europe and calendar.

If setfattr fails with ``command not found'':

* On Linux, install the relevant package, e.g. with

    $ sudo apt-get install attr

* On macOS, use xattr instead of setfattr:

    $ xattr -w user.mmfs.tags '2009 nature Europe' /media/big/my/a/*.jpg
    $ xattr -w user.mmfs.tags 'calendar 2009' /media/big2/calendar09.txt

If setfattr (or getfattr) fails with ``Operation not supported'' above on
Linux, then:

* Remount the corresponding filesystem with the user_xattr option:

    $ df -P /media/big/my/album | awk '{x=$6}END{print x}' |
      xargs -d '\n' sudo mount -o remount,user_xattr --

* If the remount fails, then your filesystem probably doesn't support
  extended attributes (and thus ppfiletagger won't work). Try another
  filesystem (e.g. in /tmp), or look at the ``System requirements'' section
  for more information.

* Try the setfattr or getfattr command again.

Add non-tag metadata to your files' extended attributes. For example:

  $ setfattr -n user.xattr1 -v value1 /media/big/my/album/photo01.jpg

Use getfattr to dump all extended attributes recursively:

  $ getfattr -dR /media/big/my/album

Please note that the extended attribute `user.mmfs.tags' has special
significance: it is the whitespace-separated list of tags (keywords)
associated to the file.  You can use the characters a-zA-Z0-9_: in tag
names. Tag names are case preserving, tag search is case sensitive.
See more information about tag syntax later.

Download https://github.com/pts/ppfiletagger/archive/master.zip , extract
it, and cd into the ppfiletagger-master directory:

  $ wget -nv -O ppfiletagger-master.zip https://github.com/pts/ppfiletagger/archive/master.zip
  $ tar xzf ppfiletagger-master.zip
  $ cd ppfiletagger-master

Use ppfiletagger_shell_functions.sh (`_mmfs tag') to add and remove tags:

  $ eval "$(./ppfiletagger_shell_functions.sh --load)"
  $ (echo 2009; echo 2010; echo nature; echo Europe; echo calendar) >
    ~/.ppfiletagger_tags
  $ _mmfs tag '2010 nature' /media/big/my/a/*.jpg
  $ _mmfs tag '2009 -2010 Europe' /media/big/my/a/*.jpg
  $ _mmfs tag 'calendar 2009' /media/big2/calendar09.txt

The configuration file ~/.ppfiletagger_tags contains a whitelist of tags
(one in each line) you are allowed to use for tagging. (The `_mmfs tag'
command reports an error if you attempt to add a tag missing from the
whitelist to a file.) This is to prevent typos and synonyms in added tags.

As seen above, specifying a tag after `_mmfs tag' adds it, and specifying a
tag with the `-' prefix removes it. It's possible to overwrite tags (i.e.
to remove all previous tags of the file first), and there are some other
tagging modes, see details and syntax here:
https://github.com/pts/locfileorg/blob/master/doc/tagging.md

Add some tags for all files you want to search for. Specify them using
`_mmfs tag' or `setfattr -n user.mmfs.tags -v ...', as
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
needing 4 disk seeks per file. (It can be fast enough on SSD with less than
10000 files to scan.) See below for fast search, as an alternative.

`_mmfs find' and rmtimequery implement a sophisticated search query language
with operators like `-', `|` and `ext:`, see details and syntax here:
https://github.com/pts/locfileorg/blob/master/doc/search.md

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

Extended attribute storage in the index
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The index in the tags.sqlite database contains all extended attributes
starting with `user.', but only user.mmfs.tags is searchable by rmtimequery.

Here is an example of extended attributes actually stored for a real filesystem:

  $ ./sqlite3-3.6.7.bin /media/data/tags.sqlite "SELECT DISTINCT xattr FROM fileattrs INDEXED BY fileattrs_xattr ORDER BY xattr" | perl -pe 's@^@user.@'
  user.com.dropbox.attributes
  user.com.dropbox.attrs
  user.mmfs.tags
  user.xdg.origin.url
  user.xdg.referrer.url

Compatibility notes
~~~~~~~~~~~~~~~~~~~
* ppfiletagger works with weird filenames: all bytes except for NUL, slash
  (/) and newline (\x0a) are allowed. Even invalid UTF-8 is supported (and
  bytes are kept intact).
* The _mmfs shell function (after --load) works with arbitrarily long
  filenames and an unlimited number of files in most shells (e.g. bash, zsh,
  ksh, pdksh, lksh, mksh and busybox sh (since about 1.17.3 in 2010)), but
  it doesn't work in dash. dash users on Linux will get the ``Argument list
  too long'' error if the command-line is long (after expansion of `*' etc.).
* Midnight Command integration works with arbitrarily long filenames and an
  unlimited number of files.

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

Speed
~~~~~
Speed of `_mmfs find' reading from a `--format=mfi' tagfile on a slow
computer:

* Commands:

    $ time perl -x ~/zsh/ppfiletagger_shell_functions.sh find --stdin-tagfile test <mscan.out >/dev/null
    info: found tags of 10560 of 1564334 files
    real    2m32.510s; user    2m28.456s; sys     0m3.624s
    $ time wc -l mscan.out
    1564334 /home/pts/m/mandel/torrent/dl_mscan.out
    real    0m2.470s; user    0m0.308s; sys     0m0.716s
    $ time perl -ne 'die if !s@ f=(.*\n)@@; my $fnn = $1; if (m@ tags=(\S+)@) { my $tags = ",$1,"; print $fnn if $tags =~ m@\Q,test,@ }' <mscan.out | wc -l
    10560
    real    0m45.952s; user    0m44.896s; sys     0m0.952s

* Thus in user time, the `find' command is ~3.307 times slower than a
  hard-coded Perl script, for matching on a single tag only.

* Thus the theoretical maximum speed on this computer is ~34843 lines
  --format=mfi lines per second.

`rmtimequery' should take less than 1 second in most use cases, and a few
seconds for complicated, long queries (e.g. `* -ext:rare000').

The speed of `rmtimequery --slow' depends on the medium (HDD or SSD),
filesystem, SQLite version and CPU (for interpreting Python code). It may
take a few minutes or a few hours. Example speed test:

* Input size:

  * Lenovo T400 laptop, ext4 fileststem on an SSD.
  * Python 2.7, Ubuntu 14.04, SQLite 3.8.2.
  * 679960 files, 56508 files with tags, 13099 directories on filesystem.
  * 158694 -- why are there so many insertions? Because of hard links?

* Measuring the speed of first `rmtimescan --slow' on an empty tags.sqlite.

* Time results: real 0m39.079s, user 0m24.802s, sys 0m9.604s.

* Commands:
    $ time ./rmtimescan --slow
    ...
    [1611314087.168284] INFO scan done, dirscan_count=13099 dirskip_count=0 update_count=0 insert_count=158694 delete_count=0
    real    0m39.079s
    user    0m24.802s
    sys     0m9.604s
    $ find /media/data -type f | wc -l
    679960
    $ find /media/data -type d | wc -l
    13099
    $ ./sqlite3-3.6.7.bin /media/data/tags.sqlite "SELECT COUNT(*) FROM filewords"
    56508
    $ ./sqlite3-3.6.7.bin /media/data/tags.sqlite "SELECT COUNT(*) FROM fileattrs"
    100588

Developer info
~~~~~~~~~~~~~~
Command-line tools:

* Linux has the command-line tools setfattr(1) and getfattr(1). on
  Debian and Ubuntu, get them with `sudo apt-get install attr'.

* macOS has the command-line tool xattr(1). Documentation:
  https://www.unix.com/man-page/mojave/1/xattr

* Linux has a partial and slow (to start up) reimplentation of the macOS
  command xattr(1) in Python. On Debian and Ubuntu, get it with
  `sudo apt-get install xattr' or (if the previous one can't find the
  package), `sudo apt-get install python-xattr'.

TODO
~~~~
# rmtimequery:
# TODO: add only tags (no other extended attributes) to the database
# TODO: implement --format=name, --format=tuple, --format=mclist in
#       ppfiletagger_shell_functions.sh
# TODO: ppfiletagger_shell_functions.sh fnq should quote empty string
# TODO: ppfiletagger_shell_functions.sh shouldn't follow symlinks to directories
# TODO: ppfiletagger_shell_functions.sh tag ---meta don't recognize flag
# TODO: add Midnight Commander integration for search
# rmtimescan:
# TODO: add scanning of specified directories (with tags.sqlite) only
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
