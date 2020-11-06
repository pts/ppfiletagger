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
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
sub get_archname() {
  # This is still slow: return (eval { require Config; die if !%Config::Config; $Config::Config{archname} } or "");
  for my $dir (@INC) { my $fn = "$dir/Config.pm"; if (open(my($f), "<", $fn)) { my $S = join("", <$f>); close($f); return $1 if $S =~ m@\n[ \t]+archname[ \t]*=>[ \t]*[\x27"]([^-\x27"\\]+-)@; last } } ""
}
sub get_xattr_syscalls() {
  if ($^O eq "linux") {
    my $archname = get_archname();
    if ($archname =~ m@\A(?:x86_64|amd64)-@) {
      return (191, 197, 188);
    } elsif ($archname =~ m@\Ai[3-6]86-@) {
      return (229, 235, 226);
    }
  }
  # This works on Linux, but `require "syscall.ph" is quite slow.
  my @result = eval { package syscall; require "syscall.ph"; &syscall::SYS_getxattr, &syscall::SYS_removexattr, &syscall::SYS_setxattr };
  die "fatal: setxattr and other syscalls not available\n" if @result != 3;
  @result
}
my($SYS_getxattr, $SYS_removexattr, $SYS_setxattr) = get_xattr_syscalls();
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
    $tags->{"v:$tag"} = 1;  # Vetted.
  }
  die unless close $F;
  $tags
}

my $known_tags = read_tags_file("$ENV{HOME}/.ppfiletagger_tags");
my ($C, $KC, $EC, $do_overwrite) = (0, 0, 0, 0);

sub do_tag($$$) {
  my ($tags, $filenames, $is_verbose) = @_;
  my $pmtag_re = qr/(---|[-+]?)((?:v:)?(?:$tagchar_re)+)/o;
  $tags="" if !defined $tags;
  $tags=~ s@^[.]/@@;  # Prepended my Midnight Commander.
  # Parse the +tag and -tag specification in the command line
  my @ptags;
  my @mtags;
  my @unknown_tags;
  my %fmtags_hash;
  $do_overwrite = 0;
  # Overwrite tags if starts with a dot. Used by qiv-command.
  $do_overwrite = 1 if $tags =~ s@\A\s*[.](?:[\s,]|\Z)@@;
  my @tags = split(/[\s,]+/, $tags);
  if (@tags == 1 and $do_overwrite and $tags[0] eq ":none") {
    shift @tags;
    $do_overwrite = 1;
  } elsif (@tags and $tags[0] eq "-*") {
    shift @tags;
    $do_overwrite = 1;
  }
  for my $pmitem (@tags) {
    if ($pmitem !~ /\A$pmtag_re\Z(?!\n)/) {
      # TODO(pts): Report this later.
      print "\007bad tag item syntax ($pmitem), skipping files\n"; exit 3;
    }
    my $tag = $2;
    if ($do_overwrite and $1 eq "-") {
      print "\007unexpected sign ($pmitem), skipping files\n"; exit 9;
    }
    # Use triple negation to remove unknown tags or to remove a tag even if
    # it is specified as a positive tag. (In the latter case, remove takes
    # precedence, no matter the order in $tags.)
    if ($1 eq "---") {
      push @mtags, $tag;  # Force remove, don't check %known_tags.
      $fmtags_hash{$tag} = 1;
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
  { @ptags = grep { !exists($fmtags_hash{$_}) } @ptags if %fmtags_hash;
    my %ptags_hash = map { $_ => 1 } @ptags;
    my @intersection_tags = grep { exists($ptags_hash{$_}) } @mtags;
    if (@intersection_tags) {
      @intersection_tags = sort @intersection_tags;
      print "\007plus and minus tags (@intersection_tags), skipping files\n";
      exit 8;
    }
  }
  # vvv Dat: menu item is not run on a very empty string
  my $is_nop = (!@ptags and !@mtags and !$do_overwrite);
  if ($is_nop) {
    print STDERR "warning: no tags specified ($tags)\n";
    # exit 2;
  }

  # Read file xattrs, apply updates, write file xattrs.
  for my $fn0 (@$filenames) {
    print "  $fn0\n";
    if ($is_nop) {
      print "    unchanged by tagspec: $tags\n" if $is_verbose;
      $KC++; next
    }
    if (not -f $fn0) {
      print "    error: not a file\n"; $EC++; next
    }

    my $key = $key0; # Dat: must be in $var
    my $got;
    my %old_tags_hash;
    my @old_tags;
    my $old_tags_str = "";

    # Populates $old_tags_str %old_tags_hash and $old_tags.
    {
      my $oldtags="\0"x65535;
      $got = syscall($SYS_getxattr, $fn0, $key, $oldtags,
        length($oldtags), 0);
      if ((!defined $got or $got<0) and !$!{ENODATA}) {
        my $is_eio = $!{EIO};
        print "    error getting: $!\n"; $EC++;
        next if !$is_eio or !$do_overwrite;
        $oldtags = $old_tags_str = "?";
        $old_tags_hash{"?"} = 1;
        push @old_tags, "?";
      } else {
        $oldtags=~s@\0.*@@s;
        $old_tags_str = $oldtags;
        $oldtags =~ s/(\S+)/ $old_tags_hash{$1} = @old_tags;
                             push @old_tags, $1 /ge;
      }
    }

    my @new_tags = $do_overwrite ? () : @old_tags;
    my %new_tags_hash = $do_overwrite ? () : %old_tags_hash;
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
    #die "SET ($old_tags_str) ($set_tags)\n";
    #print "($set_tags)\n($old_tags_str)\n";
    if (length($set_tags) > 0 and length($set_tags) < length($old_tags_str)) {
      # There is a reiserfs bug on Linux 2.6.31: cannot reliably set the
      # extended attribute to a shorter value. Workaround: set it to the empty
      # value (or remove it) first.
      my $empty = "";  # Perl needs this so $empty is writable.
      $got=syscall($SYS_setxattr, $fn0, $key, $empty, 0, 0);
      if (!defined $got or $got<0) {
        print "    error: $!\n"; $EC++;
        # Try to restore the original value;
        syscall($SYS_setxattr, $fn0, $key, $old_tags_str,
                length($old_tags_str), 0);
        next;
      }
    }
    $got = length($set_tags) == 0 ?
        syscall($SYS_removexattr, $fn0, $key) :
        syscall($SYS_setxattr, $fn0, $key, $set_tags, length($set_tags), 0);
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
my $action = "modified";
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
  do_tag($tags, \@ARGV, 0);
  $action = "overwritten" if $do_overwrite;
  $tags_to_log = $tags;
  $tags_to_log =~ s@^[.]/@@;  # Prepended my Midnight Commander.
  $tags_to_log =~ s@[,\s]+@ @g;
  $tags_to_log =~ s@^[.]\s+@@ if $do_overwrite;
}
print "\007error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
print "kept tags of $KC file@{[$KC==1?q():q(s)]}\n" if $KC;
print "$action tags of $C file@{[$C==1?q():q(s)]}: $tags_to_log\n";
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
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
require "syscall.ph";
sub get_archname() {
  # This is still slow: return (eval { require Config; die if !%Config::Config; $Config::Config{archname} } or "");
  for my $dir (@INC) { my $fn = "$dir/Config.pm"; if (open(my($f), "<", $fn)) { my $S = join("", <$f>); close($f); return $1 if $S =~ m@\n[ \t]+archname[ \t]*=>[ \t]*[\x27"]([^-\x27"\\]+-)@; last } } ""
}
sub get_xattr_syscalls() {
  if ($^O eq "linux") {
    my $archname = get_archname();
    if ($archname =~ m@\A(?:x86_64|amd64)-@) {
      return (191, 197, 188);
    } elsif ($archname =~ m@\Ai[3-6]86-@) {
      return (229, 235, 226);
    }
  }
  # This works on Linux, but `require "syscall.ph" is quite slow.
  my @result = eval { package syscall; require "syscall.ph"; &syscall::SYS_getxattr, &syscall::SYS_removexattr, &syscall::SYS_setxattr };
  die "fatal: setxattr and other syscalls not available\n" if @result != 3;
  @result
}
my($SYS_getxattr, $SYS_removexattr, $SYS_setxattr) = get_xattr_syscalls();
my $C=0;  my $EC=0;
$0="_mmfs_unify_tags";
die "Usage: $0 <file1> <file2>
     or echo \"... \x27file1\x27 ... \x27file2\x27 ...\" ... | $0 --stdin\n" if
     @ARGV!=2 and @ARGV!=1;
print "unifying tags\n";

#** @return :String, may be empty
sub get_tags($) {
  my $fn0 = $_[0];
  #print "  $fn0\n";
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn0, $key, $tags,
    length($tags), 0);
  if ((!defined $got or $got<0) and !$!{ENODATA}) {
    print "  get-error: $fn0: $!\n"; $EC++;
    return undef;
  } else {
    $tags=~s@\0.*@@s;
    return $tags;
  }
}

sub set_tags($$;$) {
  my($fn0,$tags1,$do_count)=@_;
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $got = syscall($SYS_setxattr, $fn0, $key, $tags1,
    length($tags1), 0);
  if (!defined $got or $got<0) {
    if ("$!" eq "Cannot assign requested address") {
      print "\007bad tags ($tags1)\n"; $EC++; return 1
    } else {
      print "  set-error: $fn0: $!\n"; $EC++; return 1
    }
  } else {
    $C++ if !defined($do_count) or $do_count;
    return 0
  }
}

sub add_tags($$;$) {
  my($fn0,$tags,$rmtags)=@_;
  my %rmtags;
  %rmtags=map { $_ => 1 } split(/\s+/, $rmtags) if defined $rmtags;
  die "error: bad add-tags syntax: $tags\n" if $tags =~ /[+-]/;
  return 0 if $tags !~ /\S/ and !%rmtags;
  #print "  $fn0\n";
  my $key="user.mmfs.tags"; # Dat: must be in $var

  my $tags0="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn0, $key, $tags0,
    length($tags0), 0);
  if ((!defined $got or $got<0) and !$!{ENODATA}) {
    print "  add-get-error: $fn0: $!\n"; $EC++; return 1
  }
  $tags0=~s@\0.*@@s;
  my %tags0_hash = map { $_ => 1 } split(/\s+/, $tags0);
  my $tags1 = $tags0;
  for my $tag (split(/\s+/, $tags)) {
    $tags1 .= " $tag" if not exists $tags0_hash{$tag};
  }
  if (%rmtags) {
    my @both_tags = grep { exists $rmtags{$_} } split(/\s+/, $tags);
    die "error: tags both added and removed: @both_tags\n" if @both_tags;
    my $has_rmtag = grep { exists $rmtags{$_} } split(/\s+/, $tags1);
    if ($has_rmtag) {
      $tags1 = join(" ", grep { !exists $rmtags{$_} } split(/\s+/, $tags1));
    }
  }
  $tags1 =~ s@\A\s+@@;
  die if !%rmtags and length($tags1) < length($tags);  # fail on reiserfs length problem
  return ($tags1 eq $tags0) ? 0 : set_tags($fn0, $tags1);
}

sub unify_tags($$) {
  my($fn0,$fn1)=@_;
  {
    my $tags0=get_tags($fn0);
    return -4 if !defined($tags0);
    my $tags1=get_tags($fn1);
    return -5 if !defined($tags1);
    if ($tags0 eq $tags1) {
      if ($tags0 eq "") {
        print "  neither: ($fn0) ($fn1)\n";
        return -1
      }
      print "  both ($tags0): ($fn0) ($fn1)\n";
      return -2
    }
    my @tags0a=split /\s+/, get_tags($fn0);  # \S+
    my @tags1a=split /\s+/, get_tags($fn1);  # \S+
    my %tags0ah=map { $_ => 1 } @tags0a;
    my %tags1ah=map { $_ => 1 } @tags1a;
    my @rmtags = (grep { exists $tags1ah{"v:$_"} and !exists $tags1ah{$_} } @tags0a), (grep { exists $tags0ah{"v:$_"} and !exists $tags0ah{$_} } @tags1a);
    @tags0a = grep { !exists $tags1ah{"v:$_"} or exists $tags1ah{$_} } @tags0a;
    @tags1a = grep { !exists $tags0ah{"v:$_"} or exists $tags0ah{$_} } @tags1a;
    add_tags($fn0, "@tags1a", "@rmtags") if @tags1a or @rmtags;
    add_tags($fn1, "@tags0a", "@rmtags") if @tags0a or @rmtags;
  }

  my $tags0b=get_tags($fn0);
  my $tags1b=get_tags($fn1);
  my @tags0l=sort split /\s+/, $tags0b;  # \S+
  my @tags1l=sort split /\s+/, $tags1b;  # \S+
  my $tags0c=join " ", @tags0l;
  my $tags1c=join " ", @tags1l;
  if ($tags0c eq $tags1c) {
    if ($tags0b ne $tags1b) {
      set_tags($fn0, $tags1b, 0);  # Copy (order of) tags from $fn1 to $fn0.
    }
    print "  unified ($tags0c): ($fn0) ($fn1)\n";
  } else {
    my @common_tags = grep { my $tag = $_; grep { $tag eq $_ } @tags1l } @tags0l;
    my @tags0ol = grep { my $tag = $_; !grep { $tag eq $_ } @common_tags } @tags0l;
    my @tags1ol = grep { my $tag = $_; !grep { $tag eq $_ } @common_tags } @tags1l;
    print "\007  failed to unify: common:(@common_tags), ($fn0):(@tags0ol), ($fn1):(@tags1ol)\n";
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
sub get_archname() {
  # This is still slow: return (eval { require Config; die if !%Config::Config; $Config::Config{archname} } or "");
  for my $dir (@INC) { my $fn = "$dir/Config.pm"; if (open(my($f), "<", $fn)) { my $S = join("", <$f>); close($f); return $1 if $S =~ m@\n[ \t]+archname[ \t]*=>[ \t]*[\x27"]([^-\x27"\\]+-)@; last } } ""
}
sub get_xattr_syscalls() {
  if ($^O eq "linux") {
    my $archname = get_archname();
    if ($archname =~ m@\A(?:x86_64|amd64)-@) {
      return (191, 197, 188);
    } elsif ($archname =~ m@\Ai[3-6]86-@) {
      return (229, 235, 226);
    }
  }
  # This works on Linux, but `require "syscall.ph" is quite slow.
  my @result = eval { package syscall; require "syscall.ph"; &syscall::SYS_getxattr, &syscall::SYS_removexattr, &syscall::SYS_setxattr };
  die "fatal: setxattr and other syscalls not available\n" if @result != 3;
  @result
}
my($SYS_getxattr, $SYS_removexattr, $SYS_setxattr) = get_xattr_syscalls();
my $C=0;  my $EC=0;  my $HC=0;
my $do_show_abs_path = 0;
my $do_readdir = 0;
sub process_file($) {
  my $fn0 = $_[0];
  $fn0 =~ s@\A(?:[.]/)+@@;
  if ($do_show_abs_path) {
    my $fn = Cwd::abs_path($fn0);
    # This usually happens when $fn0 is a symlink pointing to a nonexisting
    # file.
    if (!defined $fn) {
      print "  $fn0\n    error: abs not found: $!\n"; $EC++; return
    }
    print "  $fn\n";
  } else {
    print "  $fn0\n";
  }
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn0, $key, $tags,
    length($tags), 0);
  if ((!defined $got or $got<0) and !$!{ENODATA}) {
    print "    error: $!\n"; $EC++
  } else {
    $tags=~s@\0.*@@s;
    my @tags = split/\s+/, $tags;
    my @n_tags = grep { !/^v:/ } @tags;
    my @v_tags = grep { /^v:/  } @tags;
    if ($tags ne"") { $HC++ } else { @n_tags=(":none") }
    print "    @n_tags\n";  $C++;
    print "    @v_tags\n" if @v_tags;
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
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
sub get_archname() {
  # This is still slow: return (eval { require Config; die if !%Config::Config; $Config::Config{archname} } or "");
  for my $dir (@INC) { my $fn = "$dir/Config.pm"; if (open(my($f), "<", $fn)) { my $S = join("", <$f>); close($f); return $1 if $S =~ m@\n[ \t]+archname[ \t]*=>[ \t]*[\x27"]([^-\x27"\\]+-)@; last } } ""
}
sub get_xattr_syscalls() {
  if ($^O eq "linux") {
    my $archname = get_archname();
    if ($archname =~ m@\A(?:x86_64|amd64)-@) {
      return (191, 197, 188);
    } elsif ($archname =~ m@\Ai[3-6]86-@) {
      return (229, 235, 226);
    }
  }
  # This works on Linux, but `require "syscall.ph" is quite slow.
  my @result = eval { package syscall; require "syscall.ph"; &syscall::SYS_getxattr, &syscall::SYS_removexattr, &syscall::SYS_setxattr };
  die "fatal: setxattr and other syscalls not available\n" if @result != 3;
  @result
}
my($SYS_getxattr, $SYS_removexattr, $SYS_setxattr) = get_xattr_syscalls();
die "error: not a single filename specified\n" if @ARGV != 1;
for my $fn0 (@ARGV) {
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn0, $key, $tags,
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
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
sub get_archname() {
  # This is still slow: return (eval { require Config; die if !%Config::Config; $Config::Config{archname} } or "");
  for my $dir (@INC) { my $fn = "$dir/Config.pm"; if (open(my($f), "<", $fn)) { my $S = join("", <$f>); close($f); return $1 if $S =~ m@\n[ \t]+archname[ \t]*=>[ \t]*[\x27"]([^-\x27"\\]+-)@; last } } ""
}
sub get_xattr_syscalls() {
  if ($^O eq "linux") {
    my $archname = get_archname();
    if ($archname =~ m@\A(?:x86_64|amd64)-@) {
      return (191, 197, 188);
    } elsif ($archname =~ m@\Ai[3-6]86-@) {
      return (229, 235, 226);
    }
  }
  # This works on Linux, but `require "syscall.ph" is quite slow.
  my @result = eval { package syscall; require "syscall.ph"; &syscall::SYS_getxattr, &syscall::SYS_removexattr, &syscall::SYS_setxattr };
  die "fatal: setxattr and other syscalls not available\n" if @result != 3;
  @result
}
my($SYS_getxattr, $SYS_removexattr, $SYS_setxattr) = get_xattr_syscalls();
die "_mmfs_grep: query expected\n" if 1!=@ARGV;
# Simple superset of UTF-8 words.
my $tagchar_re = qr/(?:\w| [\xC2-\xDF] [\x80-\xBF] |
                           [\xE0-\xEF] [\x80-\xBF]{2} |
                           [\xF0-\xF4] [\x80-\xBF]{3}) /xo;
my @orterms;
my %needplus;
my %needminus;
my %ignore;
# Query language:
# * "foo bar | -baz" means ((foo AND bar) OR NOT baz).
# * Special words: * -* and *-foo
my $query = $ARGV[0];
die "_mmfs_grep: parentheses not supported in query: $query\n" if $query =~ m@[()]@;
for my $spec (split /\|/, $query) {
  pos($spec) = 0;
  my ($needplus, $needminus, $ignore) = ({}, {}, {});
  while ($spec=~/(\S+)/g) {
    my $tagv = $1;
    if ($tagv =~ s@^-@@) {
      $needminus->{$tagv} = 1;
      next if $tagv eq "*";
    } elsif ($tagv =~ s@^[*]-@@) {
      $ignore->{$tagv} = 1;
      $needplus->{"*"} = 1;
    } else {
      $needplus->{$tagv} = 1;
      next if $tagv eq "*";
    }
    die "_mmfs_grep: invalid tagv syntax: $tagv\n" if $tagv !~ m@\A(?:v:)?(?:$tagchar_re)+\Z(?!\n)@;
  }
  die "_mmfs_grep: empty spec in query: $spec\n" if !%$needplus and !%$needminus;
  #print STDERR "info: query spec needplus=(@{[sort keys%$needplus]}) needminus=(@{[sort keys%$needminus]}) ignore=(@{[sort keys%$ignore]})\n";
  push @orterms, [$needplus, $needminus, $ignore];
}
die "_mmfs_grep: empty query\n" if !@orterms;
my $C=0;  my $EC=0;  my $HC=0;
my $fn0;
while (defined($fn0=<STDIN>)) {
  chomp $fn0;
  #print "  $fn0\n";
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn0, $key, $tags,
    length($tags), 0);
  if ((!defined $got or $got<0) and !$!{ENODATA}) {
    print STDERR "error: $fn0: $!\n"; $EC++
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

#** Output format: setfattr -n user.mmfs.tags.modify -v TAGS FILENAME
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
sub get_archname() {
  # This is still slow: return (eval { require Config; die if !%Config::Config; $Config::Config{archname} } or "");
  for my $dir (@INC) { my $fn = "$dir/Config.pm"; if (open(my($f), "<", $fn)) { my $S = join("", <$f>); close($f); return $1 if $S =~ m@\n[ \t]+archname[ \t]*=>[ \t]*[\x27"]([^-\x27"\\]+-)@; last } } ""
}
sub get_xattr_syscalls() {
  if ($^O eq "linux") {
    my $archname = get_archname();
    if ($archname =~ m@\A(?:x86_64|amd64)-@) {
      return (191, 197, 188);
    } elsif ($archname =~ m@\Ai[3-6]86-@) {
      return (229, 235, 226);
    }
  }
  # This works on Linux, but `require "syscall.ph" is quite slow.
  my @result = eval { package syscall; require "syscall.ph"; &syscall::SYS_getxattr, &syscall::SYS_removexattr, &syscall::SYS_setxattr };
  die "fatal: setxattr and other syscalls not available\n" if @result != 3;
  @result
}
my($SYS_getxattr, $SYS_removexattr, $SYS_setxattr) = get_xattr_syscalls();
#print "to these files:\n";
my $C=0;  my $EC=0;  my $HC=0;
for my $fn0 (@ARGV) {
  #print "  $fn0\n";
  my $key="user.mmfs.tags"; # Dat: must be in $var
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn0, $key, $tags,
    length($tags), 0);
  if ((!defined $got or $got<0) and !$!{ENODATA}) {
    print "error: $fn0: $!\n"; $EC++
  } else {
    $tags=~s@\0.*@@s;
    if ($tags ne"") {
      $HC++;
      print "setfattr -n user.mmfs.tags -v ".fnq($tags)." ".
        fnq(defined$printfn ? $printfn : $fn0)."\n";
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
