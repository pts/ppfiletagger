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

#** Makes both files have the union of the tags.
#** Imp: also unify the descriptions.
#** SUXX: needed 2 runs: modified 32, then 4, then 0 files (maybe because of
#**   equivalence classes)
#** @example _mmfs_unify_tags file1 file2
#** @example echo "... 'file1' ... 'file2' ..." ... | _mmfs_unify_tags --stdin
function _mmfs_unify_tags() {
	perl -we '
use Cwd;
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
require "syscall.ph";
my $SYS_setxattr=&SYS_setxattr;
my $SYS_getxattr=&SYS_getxattr;
my $mmdir="$ENV{HOME}/mmfs/root/";
my $C=0;  my $EC=0;
$0="_mmfs_unify_tags";
die "Usage: $0 <file1> <file2>
     or echo \"... \x27file1\x27 ... \x27file2\x27 ...\" ... | $0 --stdin\n" if
     @ARGV!=2 and @ARGV!=1;
print "unifying tags\n";

#** @return :String, may be empty
sub get_tags($) {
  my $fn=Cwd::abs_path($_[0]);
  substr($fn,0,1)=$mmdir if substr($fn,0,length$mmdir)ne$mmdir;
  #print "  $fn\n";
  # vvv Imp: move, not setfattr
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn, $key, $tags,
    length($tags), 0);
  if (!defined $got or $got<0) {
    print "    error: $fn: $!\n"; $EC++;
    return "";
  } else {
    $tags=~s@\0.*@@s;
    return $tags;
  }
}

sub add_tags($$) {
  my($fn0,$tags)=@_;
  my $fn=Cwd::abs_path($fn0);
  substr($fn,0,0)=$mmdir if substr($fn,0,length$mmdir)ne$mmdir;
  #print "  $fn\n";
  my $key="user.mmfs.tags.modify"; # Dat: must be in $var
  my $got=syscall($SYS_setxattr, $fn, $key, $tags,
    length($tags), 0);
  if (!defined $got or $got<0) {
    if ("$!" eq "Cannot assign requested address") {
      print "\007bad tags ($tags)\n"; $EC++;
    } else { print "add-error: $fn: $!\n"; $EC++ }
  } else { $C++ }
}


sub unify_tags($$) {
  my($fn0,$fn1)=@_;
  my $tags0=get_tags($fn0);
  my $tags1=get_tags($fn1);
  if ($tags0 eq $tags1) {
    if ($tags0 eq "") {
      print "neither: ($fn0) ($fn1)\n";
      return -1
    }
    print "both ($tags0): ($fn0) ($fn1)\n";
    return -2
  }
  #print "$tags0; $tags1\n";
  add_tags($fn0, $tags1) if $tags1 ne "";
  add_tags($fn1, $tags0) if $tags0 ne "";
  
  my $tags0b=get_tags($fn0);
  my $tags1b=get_tags($fn1);
  if ($tags0b eq $tags1b) {
    print "unified ($tags0b): ($fn0) ($fn1)\n";
  } else {
    print "\007failed to unify: ($fn0):($tags0b), ($fn1):($tags1b)\n";
    $EC++;
    return -3;
  }
  return 0;
}

if (@ARGV==2) {
  unify_tags($ARGV[0], $ARGV[1]);
} else {
  die "error: supply filename pairs in STDIN (not a TTY)\n" if -t STDIN;
  while (<STDIN>) {
    next if !/\S/ or /^\s*#/;
    my @L;
    while (/\x27((?:[^\x27]+|\x27\\\x27\x27)*)\x27/g) {
      push @L, $1;
      $L[-1]=~s@\x27\\\x27\x27@\x27@g;
    }
    if (@L!=2) { chomp; print "not two: $_\n"; $EC++; next }
    #print "($L[0]) ($L[1])\n";
    unify_tags($L[0], $L[1]);
  }
}

print "\007error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
print "modified tags of $C file@{[$C==1?q():q(s)]}\n";
exit 1 if $EC;
' -- "$@"
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

#** @example ls | _mmfs_grep '+foo -bar baz'  # anything with foo and baz, but without bar
#** @example ls | _mmfs_grep '* -2004'        # anything with at least one tag, but without 2004
#** @example ls | _mmfs_grep '*-foo *-bar'    # anything with at least one tag, which is not foo or bar
#** @example ls | _mmfs_grep '-*'             # anything without tags
function _mmfs_grep() {
	perl -w -e '
use Cwd;
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
require "syscall.ph"; my $SYS_getxattr=&SYS_getxattr;
die "_mmfs_grep: grep spec expected\n" if 1!=@ARGV;
my %needplus;
my %needminus;
my %ignore;
my $spec=$ARGV[0];
while ($spec=~/(\S+)/g) {
  my $word = $1;
  if ($word =~ s@^-@@) {
    $needminus{$word} = 1;
  } elsif ($word =~ s@^[*]-@@) {
    $ignore{$word} = 1;
    $needplus{"*"} = 1;
  } else {
    $needplus{$word} = 1;
  }
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
    my $tagc=0;
    while ($tags=~/(\S+)/g) {
      my $tag=$1;
      $tagc++ if !$ignore{$tag};
      delete $N{$tag};
      if ($needminus{$tag} or $needminus{"*"}) { $ok_p=0; last }
    }
    delete $N{"*"} if $tagc>0;
    $ok_p=0 if %N;
    print "$fn0\n" if $ok_p;
  }
}
print STDERR "warning: had error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
' -- "$@"
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
