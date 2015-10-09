#
# ppfiletagger_shell_functions.sh for bash and zsh
# by pts@fazekas.hu at Sat Jan 20 22:29:43 CET 2007
#

#** Adds or removes or sets tags.
#** @example _mmfs_tag 'tag1 -tag2 ...' file1 file2 ...    # keep tag3
function _mmfs_tag() {
	# Midnight Commander menu for movemetafs
	# Dat: works for weird filenames (containing e.g. " " or "\n"), too
	# Imp: better mc menus
	# Imp: make this a default option
        # SUXX: prompt questions may not contain macros
        # SUXX: no way to signal an error
	perl -w -- - "$@" 3>&0 <<'END'
use Cwd;
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
require "syscall.ph"; my $SYS_setxattr=&SYS_setxattr;
my $SYS_getxattr=&SYS_getxattr;
# Simple superset of UTF-8 words.
my $tagchar_re = qr/(?:\w| [\xC2-\xDF] [\x80-\xBF] |
                           [\xE0-\xEF] [\x80-\xBF]{2} |
                           [\xF0-\xF4] [\x80-\xBF]{3}) /xo;
my $key0 = "user.mmfs.tags";

# Read the tag list file (of lines <tag> or <tag>:<description> or
# <space><comment> or #<comment>).
sub read_tags_file($) {
  my $tags_fn = $_[0];
  my $F;
  die "$0: error opening $tags_fn: $!\n" if !open $F, "<", $tags_fn;
  my $lineno = 0;
  my $tags = {};
  for my $line (<$F>) {
    ++$lineno;
    next if $line !~ /^([^\s#][^:\s]*)([\n:]*)/;
    my $tag = $1;
    if (!length($2)) {
      print "\007syntax error in $tags_fn:$.: missing colon or newline\n"; exit 4;
    }
    if ($tag !~ /\A(?:$tagchar_re)+\Z(?!\n)/) {
      # TODO(pts): Support -* here.
      print "\007syntax error in $tags_fn:$lineno: bad tag syntax: $tag\n";
      exit 5;
    }
    if (exists $tags->{$tag}) {
      print "\007syntax error in $tags_fn:$lineno: duplicate tag: $tag\n";
      exit 6;
    }
    $tags->{$tag} = 1;
  }
  die unless close $F;
  $tags
}

my $known_tags = read_tags_file("$ENV{HOME}/.ppfiletagger_tags");
my ($C, $KC, $EC) = 0;

sub do_tag($$$) {
  my ($tags, $filenames, $is_verbose) = @_;
  my $pmtag_re = qr/(---|[-+]?)((?:$tagchar_re)+)/o;
  # Same as WORDDATA_SPLIT_WORD_RE in ppfiletagger/base.py.
  my $split_word_re = qr/[^\s?!.,;\[\](){}<>"\x27]+/o;
  $tags="" if !defined $tags;
  $tags=~ s@^[.]/@@;  # Prepended my Midnight Commander.
  # Parse the +tag and -tag specification in the command line
  my @ptags;
  my @mtags;
  my @unknown_tags;
  my $is_overwrite = 0;
  $is_overwrite = 1 if $tags =~ s@\A\s*[.](?:\s+|\Z)@@;
  for my $pmitem (split/\s+/,$tags) {
    if ($pmitem !~ /\A$pmtag_re\Z(?!\n)/) {
      # TODO(pts): Report this later.
      print "\007bad tag syntax ($pmitem), skipping files\n"; exit 3;
    }
    my $tag = $2;
    if ($is_overwrite and 0 != length($1)) {
      print "\007unexpected sign ($pmitem), skipping files\n"; exit 9;
    }
    if ($1 eq "---") {  # Use triple negation it is to remove unknown tags.
      push @mtags, $tag
    } elsif (!exists $known_tags->{$tag}) {
      push @unknown_tags, $tag
    } elsif ($1 eq "-") {
      push @mtags, $tag
    } else {
      push @ptags, $tag
    }
  }
  if (@unknown_tags) {
    @unknown_tags = sort @unknown_tags;
    print "\007unknown tags (@unknown_tags), skipping files\n"; exit 7;
  }
  { my %ptags_hash = map { $_ => 1 } @ptags;
    my @intersection_tags;
    for my $tag (@mtags) {
      push @intersection_tags, $tag if exists $ptags_hash{$tag};
    }
    if (@intersection_tags) {
      @intersection_tags = sort @intersection_tags;
      print "\007plus and minus tags (@intersection_tags), skipping files\n";
      exit 8;
    }
  }
  # vvv Dat: menu item is not run on a very empty string
  if (!@ptags and !@mtags and !$is_overwrite) {
    print STDERR "no tags specified ($tags)\n"; exit 2
  }

  # Read file xattrs, apply updates, write file xattrs.
  #my $mmdir="$ENV{HOME}/mmfs/root/";
  my $mmdir="/";
  for my $fn0 (@$filenames) {
    my $fn=Cwd::abs_path($fn0);
    if (!defined $fn) {
      print "  $fn0\n";
      print "    error: not found\n";
      $EC++;
      next
    }
    substr($fn,0,0)=$mmdir if substr($fn,0,length$mmdir)ne$mmdir;
    print "  $fn\n";
    if (not -f $fn) {
      print "    error: not a file\n"; $EC++; next
    }

    my $key = $key0; # Dat: must be in $var
    my $got;
    my %old_tags_hash;
    my @old_tags;
    my $old_tags_str = "";

    {
      my $oldtags="\0"x65535;
      $got = syscall($SYS_getxattr, $fn, $key, $oldtags,
        length($oldtags), 0);
      if ((!defined $got or $got<0) and !$!{ENODATA}) {
        print "    error getting: $!\n"; $EC++; next
      }
      $oldtags=~s@\0.*@@s;
      $old_tags_str = $oldtags;
      $oldtags =~ s/($split_word_re)/ $old_tags_hash{$1} = @old_tags;
                                      push @old_tags, $1 /ge;
    }

    my @new_tags = $is_overwrite ? () : @old_tags;
    my %new_tags_hash = $is_overwrite ? () : %old_tags_hash;
    # Keep the original word order while updating.
    for my $tag (@ptags) {
      if (!exists $new_tags_hash{$tag}) {
        $new_tags_hash{$tag} = @new_tags;
        push @new_tags, $tag;
      }
    }
    for my $tag (@mtags) {
      if (exists $new_tags_hash{$tag}) {
        $new_tags[$new_tags_hash{$tag}] = undef;
      }
    }
    @new_tags = grep { defined $_ } @new_tags;
    #print "@new_tags;;@old_tags\n"; next;
    if (join("\0", @old_tags) eq join("\0", @new_tags)) {
      print "    unchanged by tagspec: $tags\n" if $is_verbose;
      $KC++; next
    }
    my $set_tags = join(" ", @new_tags);
    $key=$key0;
    # Setting $set_tags to the empty string removes $key on reiserfs3. Good.
    #die "SET $set_tags\n";
    #print "($set_tags)\n($old_tags_str)\n";
    if (length($set_tags) > 0 and length($set_tags) < length($old_tags_str)) {
      # There is a reiserfs bug on Linux 2.6.31: cannot reliably set the
      # extended attribute to a shorter value. Workaround: set it to the empty
      # value (or remove it) first.
      my $empty = "";  # Perl needs this so $empty is writable.
      $got=syscall($SYS_setxattr, $fn, $key, $empty, 0, 0);
      if (!defined $got or $got<0) {
        print "    error: $!\n"; $EC++;
        # Try to restore the original value;
        syscall($SYS_setxattr, $fn, $key, $old_tags_str, len($old_tags_str), 0);
        next;
      }
    }
    $got = syscall($SYS_setxattr, $fn, $key, $set_tags,
        length($set_tags), 0);
    if (!defined $got or $got<0) {
      if ("$!" eq "Cannot assign requested address") {
        print "\007bad tags ($tags), skipping other files\n"; exit
      } else { print "    error: $!\n"; $EC++ }
    } else {
      print "    applied tagspec: $tags\n" if $is_verbose;
      $C++
    }
  }
}

die "Usage: $0 \x27tagspec\x27 filename1 ...
     or echo \"tagspec :: filename\" ... | $0 --stdin\n" if
     !@ARGV or $ARGV[0] eq "--help";
my $tags_to_log = "...";
print "to these files:\n";
if (@ARGV and $ARGV[0] eq "--stdin") {
  my ($line, $cfilename, $lineno);
  my $f;
  die if !open($f, "<&3");
  while (defined($line = <$f>)) {
    $lineno = $.;
    if ($line =~ m@^# file: (.*)$@) {
      # Output format of: getfattr -hR -e text -n user.mmfs.tags
      $cfilename = $1
    } elsif ($line =~ /^([^#\n=]+)="(.*?)"$/) {
      # Output format of: getfattr -hR -e text -n user.mmfs.tags
      my ($key, $value) = ($1, $2);
      die "$0: bad key: $key ($lineno)\n" if $key =~ /["\\]/;
      die "$0: missing filename for key: $key ($lineno)\n" if
           !defined($cfilename);
      do_tag($value, [$cfilename], 1) if $key eq $key0;
    } elsif ($line =~ m@(.*?):: (.*?)$@) {
      my ($tagspec, $filename) = ($1, $2);
      $tagspec =~ s@\A\s+@@;
      $tagspec =~ s@\s+\Z(?!\n)@@;
      do_tag($tagspec, [$filename], 1);
    } elsif ($line !~ m@\S@) {
      $cfilename = undef
    } else {
      die "Unexpected input line ($lineno): $line";
    }
  }
  die if !close($f);
} else {
  my $tags = shift(@ARGV);
  $tags_to_log = $tags;
  do_tag($tags, \@ARGV, 0);
}
print "\007error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
print "kept tags of $KC file@{[$C==1?q():q(s)]}: $tags_to_log\n" if $KC;
print "modified tags of $C file@{[$C==1?q():q(s)]}: $tags_to_log\n";
exit 1 if $EC;
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
#my $mmdir="$ENV{HOME}/mmfs/root/";
my $mmdir="/";
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
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn, $key, $tags,
    length($tags), 0);
  if ((!defined $got or $got<0) and !$!{ENODATA}) {
    print "    error: $fn: $!\n"; $EC++;
    return "";
  } else {
    $tags=~s@\0.*@@s;
    return $tags;
  }
}

sub add_tags($$) {
  my($fn0,$tags)=@_;
  die "error: bad add-tags syntax: $tags\n" if $tags =~ /[+-]/;
  my $fn=Cwd::abs_path($fn0);
  substr($fn,0,0)=$mmdir if substr($fn,0,length$mmdir)ne$mmdir;
  #print "  $fn\n";
  my $key="user.mmfs.tags"; # Dat: must be in $var

  my $tags0="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn, $key, $tags0,
    length($tags0), 0);
  if ((!defined $got or $got<0) and !$!{ENODATA}) {
    print "add-get-error: $fn: $!\n"; $EC++;
  }
  $tags0=~s@\0.*@@s;
  my %tags0_hash = map { $_ => 1 } split(/\s+/, $tags0);
  my $tags1 = $tags0;
  for my $tag (split(/\s+/, $tags)) {
    $tags1 .= " $tag" if not exists $tags0_hash{$tag};
  }
  $tags1 =~ s@\A\s+@@;
  die if length($tags1) < length($tags);  # fail on reiserfs length problem
  $got = syscall($SYS_setxattr, $fn, $key, $tags1,
    length($tags1), 0);
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

  my $tags0b=join " ", sort split /\s+/, get_tags($fn0);
  my $tags1b=join " ", sort split /\s+/, get_tags($fn1);
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
#my $mmdir="$ENV{HOME}/mmfs/root/";
my $mmdir="/";
my $C=0;  my $EC=0;  my $HC=0;
my $do_show_abs_path = 0;
my $do_readdir = 0;
sub process_file($) {
  my $fn0 = $_[0];
  $fn0 =~ s@\A(?:[.]/)+@@;
  my $fn = Cwd::abs_path($fn0);
  # TODO(pts): What if !defined($fn)?
  substr($fn,0,1)=$mmdir if substr($fn,0,length$mmdir)ne$mmdir;
  print "  " . ($do_show_abs_path ? $fn : $fn0) . "\n";
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn, $key, $tags,
    length($tags), 0);
  if ((!defined $got or $got<0) and !$!{ENODATA}) {
    print "    error: $!\n"; $EC++
  } else {
    $tags=~s@\0.*@@s;
    if ($tags ne"") { $HC++ } else { $tags=":none" }
    print "    $tags\n";  $C++;
  }
}
if (@ARGV and $ARGV[0] eq '--abspath') { $do_show_abs_path = 1; shift @ARGV }
if (@ARGV and $ARGV[0] eq '--readdir') { $do_readdir = 1; shift @ARGV }
if ($do_readdir) {
  for my $arg (@ARGV) {
    if (-d $arg) {
      my $d;
      die if !opendir $d, $arg;
      #my $entry;
      #while (defined($entry = readdir($d))) {
      for my $entry (sort readdir($d)) {
        next if $entry eq "." or $entry eq "..";
        process_file("$arg/$entry");
      }
      die if !closedir $d;
    } else {
      process_file($arg);
    }
  }
} else {
  for my $fn0 (@ARGV) { process_file($fn0) }
}
print "\007error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
print "shown tags of $HC of $C file@{[$C==1?q():q(s)]}\n"
END
}

#** Like _mmfs_show, but only one file, and without extras. Suitable for
#** scripting.
#** @example _mmfs_get_tags file1
function _mmfs_get_tags() {
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
#my $mmdir="$ENV{HOME}/mmfs/root/";
my $mmdir="/";
die "error: not a single filename specified\n" if @ARGV != 1;
for my $fn0 (@ARGV) {
  my $fn=Cwd::abs_path($fn0);
  substr($fn,0,1)=$mmdir if substr($fn,0,length$mmdir)ne$mmdir;
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn, $key, $tags,
    length($tags), 0);
  if ((!defined $got or $got<0) and !$!{ENODATA}) {
    print STDERR "error: $fn0: $!\n";
    exit(2);
  } else {
    $tags=~s@\0.*@@s;
    exit(1) if 0 == length($tags);
    print "$tags\n";
    exit;
  }
}
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
my @orterms;
my %needplus;
my %needminus;
my %ignore;
# Query language:
# * "foo bar | -baz" means ((foo AND bar) OR NOT baz).
# * Special words: * -* and *-foo
my $orspec = $ARGV[0];
for my $spec (split /\|/, $orspec) {
  pos($spec) = 0;
  my ($needplus, $needminus, $ignore) = ({}, {}, {});
  while ($spec=~/(\S+)/g) {
    my $word = $1;
    if ($word =~ s@^-@@) {
      $needminus->{$word} = 1;
    } elsif ($word =~ s@^[*]-@@) {
      $ignore->{$word} = 1;
      $needplus->{"*"} = 1;
    } else {
      $needplus->{$word} = 1;
    }
  }
  die "_mmfs_grep: empty spec: $spec\n" if !%$needplus and !%$needminus;
  push @orterms, [$needplus, $needminus, $ignore];
}
die "_mmfs_grep: empty query\n" if !@orterms;
#my $mmdir="$ENV{HOME}/mmfs/root/";
my $mmdir="/";
my $C=0;  my $EC=0;  my $HC=0;
my $fn0;
while (defined($fn0=<STDIN>)) {
  chomp $fn0;
  my $fn=Cwd::abs_path($fn0);
  substr($fn,0,1)=$mmdir if substr($fn,0,length$mmdir)ne$mmdir;
  #print "  $fn\n";
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn, $key, $tags,
    length($tags), 0);
  if ((!defined $got or $got<0) and !$!{ENODATA}) {
    print STDERR "tag error: $fn: $!\n"; $EC++
  } else {
    $tags=~s@\0.*@@s;
    my $ok_p = 0;
    for my $term (@orterms) {
      my ($needplus, $needminus, $ignore) = @$term;
      my %N=%$needplus;
      #print "($tags)\n";
      my $tagc=0;
      pos($tags) = 0;
      while ($tags=~/(\S+)/g) {
        my $tag=$1;
        $tagc++ if !$ignore->{$tag};
        delete $N{$tag};
        if ($needminus->{$tag} or $needminus->{"*"}) { %N = (1 => 1); last }
      }
      delete $N{"*"} if $tagc>0;
      if (!%N) { $ok_p = 1; last }
    }
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
#my $mmdir="$ENV{HOME}/mmfs/root/";
my $mmdir="/";
my $C=0;  my $EC=0;  my $HC=0;
if (defined $printfn) {
  $printfn=Cwd::abs_path($printfn);
  substr($printfn,0,1)=$mmdir if substr($printfn,0,length$mmdir)ne$mmdir;
}
for my $fn0 (@ARGV) {
  my $fn=Cwd::abs_path($fn0);
  substr($fn,0,1)=$mmdir if substr($fn,0,length$mmdir)ne$mmdir;
  #print "  $fn\n";
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn, $key, $tags,
    length($tags), 0);
  if ((!defined $got or $got<0) and !$!{ENODATA}) {
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
  echo "$0: error: _mmfs_fixprincipal not supported with ppfiletagger" >&2
  return 1
}

#** Displays all known tags whose prefix is $1, displaying at most $2 tags.
#** @example _mmfs_expand_tag ta
function _mmfs_expand_tag() {
	perl -w -- - "$@" <<'END'
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
# Simple superset of UTF-8 words.
my $tagchar_re = qr/(?:\w| [\xC2-\xDF] [\x80-\xBF] |
                           [\xE0-\xEF] [\x80-\xBF]{2} |
                           [\xF0-\xF4] [\x80-\xBF]{3}) /x;
# Read the tag list file (of lines <tag> or <tag>:<description> or
# <space><comment> or #<comment>).
my $F;
my $tags_fn = "$ENV{HOME}/.ppfiletagger_tags";
die "$0: error opening $tags_fn: $!\n" if !open $F, "<", $tags_fn;
my $lineno = 0;
my %known_tags;
for my $line (<$F>) {
  ++$lineno;
  next if $line !~ /^([^\s#][^:\s]*)([\n:]*)/;
  my $tag = $1;
  if (!length($2)) {
    print "\007syntax error in $tags_fn:$.: missing colon or newline\n"; exit 4;
  }
  if ($tag !~ /\A(?:$tagchar_re)+\Z(?!\n)/) {
    # TODO(pts): Support -* here.
    print "\007syntax error in $tags_fn:$lineno: bad tag syntax: $tag\n";
    exit 5;
  }
  if (exists $known_tags{$tag}) {
    print "\007syntax error in $tags_fn:$lineno: duplicate tag: $tag\n";
    exit 6;
  }
  $known_tags{$tag} = 1;
}
die unless close $F;

my @tags = sort keys %known_tags;
my $sign = '';
my $prefix = @ARGV ? $ARGV[0] : "";
$sign = $1 if $prefix =~ s@^([-+]+)@@;
my $limit = @ARGV > 1 ? 0 + $ARGV[1] : 10;
my @found_tags = grep { substr($_, 0, length($prefix)) eq $prefix } @tags;
if ($limit > 0 and @found_tags > $limit) {
  splice @found_tags, $limit - 1, @found_tags, '...';
}
print map { "$sign$_\n" } @found_tags;
exit(@found_tags > 1 ? 2 : @found_tags ? 1 : 0);
END
}