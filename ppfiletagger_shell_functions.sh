#
# ppfiletagger_shell_functions.sh for bash and zsh
# by pts@fazekas.hu at Sat Jan 20 22:29:43 CET 2007
#

#** @example _mmfs_tag 'tag1 tag2 ...' file1 file2 ...
function _mmfs_tag() {
	# Midnight Commander menu for movemetafs
	# Dat: works for weird filenames (containing e.g. " " or "\n"), too
	# Imp: better mc menus
	# Imp: make this a default option
        # SUXX: prompt questions may not contain macros
        # SUXX: no way to signal an error
	perl -w -- - "$@" <<'END'
use Cwd;
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
require "syscall.ph"; my $SYS_setxattr=&SYS_setxattr;
my($tags)=shift(@ARGV);
$tags="" if !defined $tags;
# vvv Dat: menu item is not run on a very empty string
if ($tags!~/\S/) { print STDERR "no tags specified ($tags)\n"; exit 2 }
print "to these files:\n";
my $mmdir="$ENV{HOME}/mmfs/root/";
my $C=0;
my $EC=0;
for my $fn0 (@ARGV) {
  my $fn=Cwd::abs_path($fn0);
  substr($fn,0,0)=$mmdir if substr($fn,0,length$mmdir)ne$mmdir;
  print "  $fn\n";
  # vvv Imp: move, not setfattr
  my $key="user.mmfs.tags.modify"; # Dat: must be in $var
  my $got=syscall($SYS_setxattr, $fn, $key, $tags,
    length($tags), 0);
  if (!defined $got or $got<0) {
    if ("$!" eq "Cannot assign requested address") {
      print "\007bad tags ($tags), skipping other files\n"; exit
    } else { print "    error: $!\n"; $EC++ }
  } else { $C++ }
}
print "\007error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
print "modified tags of $C file@{[$C==1?q():q(s)]}: $tags\n"
END
}

#** @example _mmfs_show file1 file2 ...
function _mmfs_show() {
	# Midnight Commander menu for movemetafs
	# Dat: works for weird filenames (containing e.g. " " or "\n"), too
	# Imp: better mc menus
	# Imp: make this a default option
        # SUXX: prompt questions may not contain macros
        # SUXX: no way to signal an error
	perl -w -- - "$@" <<'END'
use Cwd;
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
require "syscall.ph"; my $SYS_getxattr=&SYS_getxattr;
print "to these files:\n";
my $mmdir="$ENV{HOME}/mmfs/root/";
my $C=0;  my $EC=0;  my $HC=0;
for my $fn0 (@ARGV) {
  my $fn=Cwd::abs_path($fn0);
  substr($fn,0,1)=$mmdir if substr($fn,0,length$mmdir)ne$mmdir;
  print "  $fn\n";
  # vvv Imp: move, not setfattr
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn, $key, $tags,
    length($tags), 0);
  if (!defined $got or $got<0) {
    print "    error: $!\n"; $EC++
  } else {
    $tags=~s@\0.*@@s;
    if ($tags ne"") { $HC++ } else { $tags=":none" }
    print "    $tags\n";  $C++;
  }
}
print "\007error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
print "shown tags of $HC of $C file@{[$C==1?q():q(s)]}\n"
END
}

#** @example ls | _mmfs_grep '+foo -bar'
function _mmfs_grep() {
	perl -w -e '
use Cwd;
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
require "syscall.ph"; my $SYS_getxattr=&SYS_getxattr;
die "_mmfs_grep: grep spec expected\n" if 1!=@ARGV;
my %needplus;
my %needminus;
my $spec=$ARGV[0];
while ($spec=~/-(\S+)|[+]?(\S+)/g) { # Imp: more strict in syntax
  if (defined $1) { $needminus{$1}=1 }
  elsif (defined $2) { $needplus{$2}=1 }
}
die "_mmfs_grep: empty spec\n" if !%needplus and !%needminus;
my $mmdir="$ENV{HOME}/mmfs/root/";
my $C=0;  my $EC=0;  my $HC=0;
my $fn0;
while (defined($fn0=<STDIN>)) {
  chomp $fn0;
  my $fn=Cwd::abs_path($fn0);
  substr($fn,0,1)=$mmdir if substr($fn,0,length$mmdir)ne$mmdir;
  #print "  $fn\n";
  # vvv Imp: move, not setfattr
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn, $key, $tags,
    length($tags), 0);
  if (!defined $got or $got<0) {
    print STDERR "tag error: $fn: $!\n"; $EC++
  } else {
    $tags=~s@\0.*@@s;
    my $ok_p=1;
    my %N=%needplus;
    #print "($tags)\n";
    while ($tags=~/(\S+)/g) {
      my $tag=$1;
      delete $N{$tag};
      if ($needminus{$tag}) { $ok_p=0; last }
    }
    $ok_p=0 if %N;
    print "$fn0\n" if $ok_p;
  }
}
print STDERR "warning: had error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
' "$@"
}

#** @example _mmfs_dump [--printfn=...] file1 file2 ...
#** @example _copyattr() { _mmfs_dump --printfn="$2" -- "$1"; }; duprm.pl . | perl -ne 'print if s@^rm -f @_copyattr @ and s@ #, keep @ @' >_d.sh; source _d.sh | sh
function _mmfs_dump() {
	# Midnight Commander menu for movemetafs
	# Dat: works for weird filenames (containing e.g. " " or "\n"), too
	# Imp: better mc menus
	# Imp: make this a default option
        # SUXX: prompt questions may not contain macros
        # SUXX: no way to signal an error
	perl -w -- - "$@" <<'END'
use Cwd;
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
sub fnq($) {
  #return $_[0] if substr($_[0],0,1)ne'-'
  return $_[0] if $_[0]!~m@[^-_/.0-9a-zA-Z]@;
  my $S=$_[0];
  $S=~s@'@'\\''@g;
  "'$S'"
}
my $printfn;
if (@ARGV and $ARGV[0]=~/\A--printfn=(.*)/s) { $printfn=$1; shift @ARGV }
if (@ARGV and $ARGV[0] eq '--') { shift @ARGV }
require "syscall.ph"; my $SYS_getxattr=&SYS_getxattr;
#print "to these files:\n";
my $mmdir="$ENV{HOME}/mmfs/root/";
my $C=0;  my $EC=0;  my $HC=0;
if (defined $printfn) {
  $printfn=Cwd::abs_path($printfn);
  substr($printfn,0,1)=$mmdir if substr($printfn,0,length$mmdir)ne$mmdir;
}
for my $fn0 (@ARGV) {
  my $fn=Cwd::abs_path($fn0);
  substr($fn,0,1)=$mmdir if substr($fn,0,length$mmdir)ne$mmdir;
  #print "  $fn\n";
  # vvv Imp: move, not setfattr
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn, $key, $tags,
    length($tags), 0);
  if (!defined $got or $got<0) {
    print "    error: $!\n"; $EC++
  } else {
    $tags=~s@\0.*@@s;
    if ($tags ne"") {
      $HC++;
      print "setfattr -n user.mmfs.tags.modify -v ".fnq($tags)." ".
        fnq(defined$printfn ? $printfn : $fn)."\n";
    } else { $tags=":none" }
    #print "    $tags\n";
    $C++;
  }
}
print "# \007error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
print "# shown tags of $HC of $C file@{[$C==1?q():q(s)]}\n"
END
}

#** @example _mmfs_fixprincipal file1 file2 ...
function _mmfs_fixprincipal() {
	# Midnight Commander menu for movemetafs
	# Dat: works for weird filenames (containing e.g. " " or "\n"), too
	# Imp: better mc menus
	# Imp: make this a default option
        # SUXX: prompt questions may not contain macros
        # SUXX: no way to signal an error
	perl -w -- - "$@" <<'END'
use Cwd;
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
require "syscall.ph"; my $SYS_getxattr=&SYS_getxattr;
print "to these files:\n";
my $mmdir0="$ENV{HOME}/mmfs/";
my $mmdir="${mmdir0}root/";
my $C=0;  my $EC=0;  my $HC=0;
for my $fn0 (@ARGV) {
  my $fn=Cwd::abs_path($fn0);
  substr($fn,0,0)=$mmdir if substr($fn,0,length$mmdir)ne$mmdir;
  print "  $fn\n";
  # vvv Imp: move, not setfattr
  if (!rename($fn,$mmdir0."adm/fixprincipal/:any")) {
    print "    error: $!\n"; $EC++
  } else { $C++ }
}
print "\007error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
print "fixed principal of $HC of $C file@{[$C==1?q():q(s)]}\n"
END
}
