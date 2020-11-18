#
# ppfiletagger_shell_functions.sh for bash and zsh
# by pts@fazekas.hu at Sat Jan 20 22:29:43 CET 2007
#

#** Adds or removes tags on files.
#** @example _mmfs_tag 'tag1 -tag2 ...' file1 file2 ...    # keep tag3
function _mmfs_tag() {
	# Midnight Commander menu action implementation for movemetafs (mmfs).
	# It works for weird filenames (containing e.g. " " or "\n"), too.
        # SUXX: prompt questions may not contain macros
        # SUXX: no way to signal an error
	perl -w -- - _mmfs_tag "$@" 3>&0 <<'END'
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
$0 = shift(@ARGV);
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

# Reads the tag list file (of lines <tag> or <tag>:<description> or
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
my($C, $KC, $EC) = (0, 0, 0);
my $pmtag_re = qr/(---|[-+]?)((?:v:)?(?:$tagchar_re)+)/o;

sub apply_tagspec($$$$) {
  my($tagspec, $mode, $filenames, $is_verbose) = @_;
  # Parse $tagspec (<tagpec>).
  $tagspec = "" if !defined($tagspec);
  $tagspec =~ s@^[.]/@@;  # Prepended my Midnight Commander.
  $mode = "++" if !defined($mode) or !length($mode);
  die "fatal: bad mode: $mode\n" if $mode ne "." and $mode ne "+" and $mode ne "++";
  my @ptags;
  my @mtags;
  my @unknown_tags;
  my %fmtags_hash;
  # Overwrite tags if starts with a dot. Used by qiv-command.
  $mode = $1 if $tagspec =~ s@\A\s*([.]|[+]|[+][+])(?:[\s,]+|\Z)@@;
  my $tag_mode = $mode eq "." ? "overwrite" : $mode eq "+" ? "merge" : "change";
  my $do_overwrite = ($mode eq ".") + 0;
  my $do_merge = ($mode eq "+") + 0;
  my @tags = split(/[\s,]+/, $tagspec);
  my $tagspecmsg = $mode eq "++" ? "@tags" : "$mode @tags";
  if (@tags == 1 and $do_overwrite and $tags[0] eq ":none") {
    shift @tags;
  } elsif (@tags and $tags[0] eq "-*") {
    shift @tags;
    $do_overwrite = 1; $do_merge = 0;
  }
  for my $pmtag (@tags) {
    if ($pmtag !~ /\A$pmtag_re\Z(?!\n)/) {
      # TODO(pts): Report this later.
      print "\007bad tag item syntax ($pmtag), skipping files\n"; exit 3;
    }
    my $tag = $2;
    if ($do_overwrite and $1 eq "-") {
      print "\007unexpected sign ($pmtag), skipping files\n"; exit 9;
    }
    # Use triple negation to remove unknown tags or to remove a tag even if
    # it is specified as a positive tag. (In the latter case, remove takes
    # precedence, no matter the order in $tagspec.)
    if ($1 eq "---") {
      push @mtags, $tag;  # Force remove, do not check %known_tags.
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
  my %new_vtags;
  %new_vtags = map { m@\Av:(.*)@s ? ($1 => 1) : () } @ptags if $do_merge;
  my %new_pmvtags;
  %new_pmvtags = map { m@\Av:(.*)@s ? ($1 => 1) : () } (@ptags, @mtags) if $do_merge;
  my $is_nop = (!@ptags and !@mtags and !$do_overwrite);
  if ($is_nop and !$is_verbose) {
    print STDERR "warning: no tags specified ($tagspecmsg)\n";
    # exit 2;
    # We continue so that we can report file I/O errors.
  }

  # Read file xattrs, apply updates from @ptags, @mtags and %new_vtags,
  # write file xattrs.
  FN0: for my $fn0 (@$filenames) {
    print "  $fn0\n";
    if ($is_nop) {
      print "    unchanged by tagspec: $tagspecmsg\n" if $is_verbose;
      $KC++; next FN0
    }
    if (not -f $fn0) {
      print "    error: not a file\n"; $EC++; next FN0
    }

    my $key = $key0;
    my $got;
    my %old_tags_hash;
    my @old_tags;
    my $old_tags_str = "";
    my($ptags_ref, $mtags_ref) = (\@ptags, \@mtags);

    # Populates $old_tags_str, %old_tags_hash, @old_tags, maybe modifies
    # $ptags_ref and $mtags_ref.
    {
      my $oldtags="\0"x65535;
      # $key must be a variable, it cannot be a read-only literal.
      $got = syscall($SYS_getxattr, $fn0, $key, $oldtags,
        length($oldtags), 0);
      if ((!defined $got or $got<0) and !$!{ENODATA}) {
        my $is_eio = $!{EIO};
        print "    error getting: $!\n"; $EC++;
        next FN0 if !($is_eio and $do_overwrite);
        $oldtags = $old_tags_str = "?";
        $old_tags_hash{"?"} = 1;
        push @old_tags, "?";
      } else {
        $oldtags =~ s@\0.*@@s;
        $old_tags_str = $oldtags;
        for my $tag (split(/\s+/, $oldtags)) {
          if (!exists($old_tags_hash{$tag})) {
            $old_tags_hash{$tag} = @old_tags;
            push @old_tags, $tag;
          }
        }
      }
      if ($do_merge) {  # Maybe modifies $ptags_ref and $mtags_ref.
        my %old_vtags = map { m@\Av:(.*)@s ? ($1 => 1) : () } @old_tags;
        my %both_vtags = map { exists($old_vtags{$_}) ? ($_ => 1) : () } keys %new_vtags;
        my %ptags = map { $_ => 1 } @ptags;
        my %mtags = map { $_ => 1 } @mtags;
        if (%both_vtags) {
          my @conflicting_tags = sort grep { exists($old_tags_hash{$_}) ? (!exists($ptags{$_}) and !exists($mtags{$_})) : exists($ptags{$_}) } keys(%both_vtags);
          if (@conflicting_tags) {
            print "    error merging tags: @conflicting_tags\n"; $EC++; next FN0
          }
        }
        $ptags_ref = [grep { (!exists($old_vtags{$_}) or exists($new_pmvtags{$_})) and !exists($old_tags_hash{$_}) } @$ptags_ref];
        $mtags_ref = [grep { (!exists($old_vtags{$_}) or exists($new_pmvtags{$_})) and  exists($old_tags_hash{$_}) } @$mtags_ref];
        push @$mtags_ref, sort grep { !exists($ptags{$_}) and !exists($mtags{$_}) and exists($old_tags_hash{$_}) } keys(%new_vtags);
        #print "    merge old_tags=(@old_tags) ptags=(@$ptags_ref) mtags=(@$mtags_ref)\n";
        if (!@$ptags_ref and !@$mtags_ref) {  # Just a speed optimization, we also check below.
          print "    unchanged by tagspec: $tagspecmsg\n" if $is_verbose;
          $KC++; next FN0
        }
      }
    }
    my @new_tags = $do_overwrite ? () : @old_tags;
    my %new_tags_hash = $do_overwrite ? () : %old_tags_hash;
    # Keep the original word order while updating.
    for my $tag (@$ptags_ref) {
      if (!exists($new_tags_hash{$tag})) {
        $new_tags_hash{$tag} = @new_tags;
        push @new_tags, $tag;
      }
    }
    for my $tag (@$mtags_ref) {
      if (exists($new_tags_hash{$tag})) {
        $new_tags[$new_tags_hash{$tag}] = undef;
      }
    }
    @new_tags = grep { defined $_ } @new_tags;
    #print "@new_tags;;@old_tags\n"; next FN0;
    if (join("\0", @old_tags) eq join("\0", @new_tags)) {
      print "    unchanged by tagspec: $tagspecmsg\n" if $is_verbose;
      $KC++; next FN0
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
        # FYI: We get EOPNOTSUPP (Operation not supported) if $key does not
        # start with "user." (without the quotes).
        # Try to restore the original value;
        syscall($SYS_setxattr, $fn0, $key, $old_tags_str,
                length($old_tags_str), 0);
        next FN0;
      }
    }
    $got = length($set_tags) == 0 ?
        syscall($SYS_removexattr, $fn0, $key) :
        syscall($SYS_setxattr, $fn0, $key, $set_tags, length($set_tags), 0);
    if (!defined $got or $got<0) {
      if ($!{EADDRNOTAVAIL} or "$!" eq "Cannot assign requested address") {  # This does not happen with ppfiletagger.
        print "\007bad tags ($tagspecmsg), skipping other files\n"; exit
      } else { print "    error: $!\n"; $EC++ }
    } else {
      print "    applied tagspec: $tagspecmsg\n" if $is_verbose;
      $C++
    }
  }
  ($tag_mode, $tagspecmsg)
}

sub apply_to_multiple($$) {
  my($tagspec, $filenames) = @_;
  my($tag_mode, $tagspecmsg) = apply_tagspec($tagspec, "++", $filenames, 0);
  my $action = $tag_mode eq "overwrite" ? "overwritten" : $tag_mode eq "merge" ? "merged" : "changed";
  ($action, $tagspecmsg)
}

die "$0: adds or removes tags on files
Usage: $0 \x27tagspec\x27 filename1 ...
    or ls | $0 --stdin <tagspec>
    or $0 --stdin [<flag> ...] < <tagfile>
<tagfile> contains:
* Empty lines and comments starting with # + whitespace.
* Lines of the colon form: <tagspec> :: <filename>
* Lines of the setfattr form: setfattr -n user.mmfs.tags -v \x27<tags>\x27 \x27<filename>\x27
* Lines of the setfattr form: setfattr -x user.mmfs.tags \x27<filename>\x27
* Lines of the mediafileinfo form: format=... ... tags=<tags> ... f=<filename>
* Output of: getfattr -hR -e text -n user.mmfs.tags --absolute-names <path>
Valid modes for --stdin:
* --mode=change is like --prefix=++
* --mode=overwrite == --mode=set == --set is like --prefix=.
* --mode=merge == --merge is like --prefix=+
The default for setfattr and getfattr is --set, otherwise --mode=change.
" if !@ARGV or $ARGV[0] eq "--help";
my $tagspecmsg = "...";
print "to these files:\n";
my $action = "modified";
if (@ARGV == 2 and $ARGV[0] eq "--stdin" and $ARGV[1] ne "-" and substr($ARGV[1], 0, 2) ne "--") {
  # Read filenames from stdin, apply tags in $ARGV[1];
  my $f;
  die if !open($f, "<&3");
  my($tagspec, $filenames) = ($ARGV[1], [<$f>]);
  die if !close($f);
  for my $fn0 (@$filenames) { chomp($fn0); }
  ($action, $tagspecmsg) = apply_to_multiple($tagspec, $filenames);
} elsif (!(@ARGV and $ARGV[0] eq "--stdin")) {
  my($tagspec, $filenames) = (shift(@ARGV), \@ARGV);
  ($action, $tagspecmsg) = apply_to_multiple($tagspec, $filenames);
} else {
  my $mode;
  my $tagspec_prefix = "";
  my $i = 0;
  while ($i < @ARGV) {
    my $arg = $ARGV[$i++];
    if ($arg eq "-" or substr($arg, 0, 1) ne "-") { --$i; last }
    elsif ($arg eq "--") { last }
    elsif ($arg eq "--stdin") {}
    elsif ($arg eq "--mode=change" or $arg eq "--mode=++") { $mode = "++" }
    elsif ($arg eq "--mode=overwrite" or $arg eq "--mode=set" or $arg eq "--mode=++" or $arg eq "-overwrite" or $arg eq "--set") { $mode = "." }
    elsif ($arg eq "--mode=merge" or $arg eq "--mode=+" or $arg eq "--merge") { $mode = "+" }
    elsif ($arg =~ m@\A--mode=@) { die "$0: fatal: unknown flag value: $arg\n" }
    elsif ($arg =~ m@\A--prefix=(.*)@s) { $tagspec_prefix = "$1 " }
    else { die "$0: fatal: unknown flag: $arg\n" }
  }
  die "$0: fatal: too many command-line arguments\n" if $i != @ARGV;
  my $sharg_re = qr@[^\s()\\\x27"`;&<>*?\[\]$|#]+|\x27(?:[^\x27]++|\x27\\\x27\x27)*+\x27@;
  my $sharg_decode = sub { my $s = $_[0]; $s =~ s@\x27\\\x27\x27@\x27@g if $s =~ s@\A\x27(.*)\x27@$1@s; $s };
  my($line, $cfilename, $lineno);
  my $f;
  die if !open($f, "<&3");
  while (defined($line = <$f>)) {
    $lineno = $.;
    if ($line =~ m@^# file: (.*)$@) {  # Output of getfattr.
      $cfilename = $1
    } elsif ($line =~ /^([^#\n=:"]+)(?:="(.*?)")?$/) {  # Output of getfattr.
      my($key, $value) = ($1, $2);
      die "$0: bad key: $key ($lineno)\n" if $key =~ /["\\]/;
      die "$0: missing filename for key: $key ($lineno)\n" if
           !defined($cfilename);
      $value = "" if !defined($value);
      apply_tagspec($tagspec_prefix . $value, ($mode or "."), [$cfilename], 1) if $key eq $key0;
    } elsif ($line =~ m@(.*?):: (.*?)$@) {
      my($tagspec, $filename) = ($1, $2);
      $tagspec =~ s@\A\s+@@;
      $tagspec =~ s@\s+\Z(?!\n)@@;
      apply_tagspec($tagspec_prefix . $tagspec, $mode, [$filename], 1);
    } elsif ($line =~ m@^#@) {  # Comment.
    } elsif ($line =~ m@^setfattr[ \t]+-x[ \t]+user.mmfs.tags[ \t]+(?:--[ \t]+)?($sharg_re)[ \t]*$@o) {
      my $filename = $sharg_decode->($1);
      apply_tagspec($tagspec_prefix, ($mode or "."), [$filename], 1);
    } elsif ($line =~ m@^setfattr[ \t]+-n[ \t]+user.mmfs.tags[ \t]+-v[ \t]+($sharg_re)[ \t]+(?:--[ \t]+)?($sharg_re)[ \t]*$@o) {
      my($tagspec, $filename) = ($sharg_decode->($1), $sharg_decode->($2));
      apply_tagspec($tagspec_prefix . $tagspec, ($mode or "."), [$filename], 1);
    } elsif ($line =~ m@^format=(?:[^ ]+)(?= )(.*?) f=(.*)$@) {  # mediafileinfo form.
      my $filename = $2;
      $line = $1;
      my $tagspec = $line =~ m@ tags=([^ ]+)@ ? $1 : "";
      apply_tagspec($tagspec_prefix . $tagspec, $mode, [$filename], 1);
    } elsif ($line !~ m@\S@) {
      $cfilename = undef
    } else {
      die "$0: fatal: bad tagfile line ($lineno): $line";
    }
  }
  die if !close($f);
}
print "\007error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
print "kept tags of $KC file@{[$KC==1?q():q(s)]}\n" if $KC;
print "$action tags of $C file@{[$C==1?q():q(s)]}: $tagspecmsg\n";
exit 1 if $EC;
END
}

#** Makes both files have the union of the tags.
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
die "$0: makes both files have to union of tags
Usage: $0 <file1> <file2>
     or echo \"... \x27file1\x27 ... \x27file2\x27 ...\" ... | $0 --stdin\n" if
     @ARGV!=2 and @ARGV!=1;
print "unifying tags\n";

#** @return :String, may be empty
sub get_tags($) {
  my $fn0 = $_[0];
  #print "  $fn0\n";
  my $key="user.mmfs.tags";
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
  my $key="user.mmfs.tags";
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
  my $key="user.mmfs.tags";

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
	# Midnight Commander menu action implementation for movemetafs (mmfs).
	# It works for weird filenames (containing e.g. " " or "\n"), too
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
  my $key="user.mmfs.tags";
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
if (@ARGV and $ARGV[0] eq "--abspath") { $do_show_abs_path = 1; shift @ARGV }
if (@ARGV and $ARGV[0] eq "--readdir") { $do_readdir = 1; shift @ARGV }
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
	# It works for weird filenames (containing e.g. " " or "\n"), too.
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
  my $key="user.mmfs.tags";
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
  my $key="user.mmfs.tags";
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

#** @example _mmfs_dump [--printfn=...] file1 file2 ...
#** @example _copyattr() { _mmfs_dump --printfn="$2" -- "$1"; }; duprm.pl . | perl -ne 'print if s@^rm -f @_copyattr @ and s@ #, keep @ @' >_d.sh; source _d.sh | sh
function _mmfs_dump() {
	# It works for weird filenames (containing e.g. " " or "\n"), too.
        # SUXX: prompt questions may not contain macros
        # SUXX: no way to signal an error
	perl -w -- - _mmfs_dump "$@" 3>&0 <<'END'
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
$0 = shift(@ARGV);
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

sub fnq($) {
  #return $_[0] if substr($_[0],0,1)ne"-";
  return $_[0] if $_[0]!~m@[^-_/.0-9a-zA-Z]@;
  my $S=$_[0];
  $S=~s@\x27@\x27\\\x27\x27@g;
  "\x27$S\x27"
}

sub gfaq($) {
  my $S = $_[0];
  $S =~ s@(["\\])@\\$1@g;
  $S =~ s@([\r\n])@ sprintf("\\%03o", ord($1)) @ge;
  # No need to escape [\x80-\xff] , `getfattr -e text` does not do it either.
  qq("$S")
}

die "$0: dumps tags on files to stdout
Usage: $0 [<flag> ...] <filename> [...] > <tagfile>
Flags:
--printfn=<filename> : In the output, print the specified filename instead.
--print-empty=yes (default) : Print files without tags.
--print-empty=no : Hide files without tags.
--format=sh (default) : Print a series of setfattr commands.
--format=colon: Print in the colon format: <tags> :: <filename>
--format=getfattr : Print the same output as: getfattr -e text
--format=mfi : Print in the mediafileinfo format.
--stdin : Get filenames from stdin rather than command-line.
--recursive=yes (default) : Dump directories, recursively.
--recursive=no : Dump files only.
To apply tags in <tagfile> printed by $0 (any --format=...), run:
  _mmfs_tag --stdin --mode=change < <tagfile>
It follows symlinks.
" if !@ARGV or $ARGV[0] eq "--help";
my($printfn);
my $format = "sh";
my $do_print_empty = 1;
my $is_stdin = 0;
my $is_recursive = 1;
my $i = 0;
while ($i < @ARGV) {
  my $arg = $ARGV[$i++];
  if ($arg eq "-" or substr($arg, 0, 1) ne "-") { --$i; last }
  elsif ($arg eq "--") { last }
  elsif ($arg eq "--stdin") { $is_stdin = 1 }
  elsif ($arg eq "--format=sh" or $arg eq "--format=setfattr" or $arg eq "--sh") { $format = "sh" }
  elsif ($arg eq "--format=colon" or $arg eq "--colon") { $format = "colon" }
  elsif ($arg eq "--format=getfattr" or $arg eq "--getfattr") { $format = "getfattr" }
  elsif ($arg eq "--format=mfi" or $arg eq "--format=mediafileinfo" or $arg eq "--format=mscan" or $arg eq "--mfi" or $arg eq "--mscan") { $format = "mfi" }
  elsif ($arg =~ m@\A--format=@) { die "$0: fatal: unknown flag value: $arg\n" }
  elsif ($arg eq "--print-empty=yes") { $do_print_empty = 1 }
  elsif ($arg eq "--print-empty=no") { $do_print_empty = 0 }
  elsif ($arg eq "--recursive=yes") { $is_recursive = 1 }
  elsif ($arg eq "--recursive=no") { $is_recursive = 0 }
  elsif ($arg =~ m@\A--print-empty=@) { die "$0: fatal: unknown flag value: $arg\n" }
  elsif ($arg =~ m@\A--printfn=(.*)@s) { $printfn = $1 }
  else { die "$0: fatal: unknown flag: $arg\n" }
}
if ($is_stdin) {
  die "$0: fatal: too many command-line arguments\n" if $i != @ARGV;
} else {
  splice(@ARGV, 0, $i);
}

my $dump_func =
    ($format eq "sh") ? sub {
      my($tags, $filename) = @_;
      length($tags) ?
          "setfattr -n user.mmfs.tags -v " . fnq($tags) . " -- " . fnq($filename) . "\n" :
          "setfattr -x user.mmfs.tags -- " . fnq($filename) . "\n"
    } : ($format eq "colon") ? sub {
      my($tags, $filename) = @_;
      "$tags :: $filename\n"
    } : ($format eq "getfattr") ? sub {
      my($tags, $filename) = @_;
      # getfattr always omits files without tags (i.e. without the
      # user.mmfs.tags extended attribute). Use _mmfs_dump --print-empty=no
      # to get this behavior.
      "# file: $filename\nuser.mmfs.tags=" . gfaq($tags). "\n\n"
    } : ($format eq "mfi") ? sub {
      my($tags, $filename) = @_;
      my $tagsc = $tags;
      $tagsc =~ s@[\s,]+@,@g;
      $tagsc =~ s@%@%25@g;
      $tagsc =~ s@\A,+@@; $tagsc =~ s@,+\Z(?!\n)@@;
      my @st = stat($filename);
      @st ? "format=?-no-try mtime=$st[9] size=$st[7] tags=$tagsc f=$filename\n"
          : "format=?-no-try tags=$tagsc f=$filename\n"
    } : undef;
die "assert: unknown format: $format\n" if !defined($dump_func);

#print "to these files:\n";
my $C=0;  my $EC=0;  my $HC=0;
sub dumpf($) {
  my $fn0 = $_[0];
  #print "  $fn0\n";
  return if !-f($fn0);
  if ($fn0 =~ y@\n@@) {
    print STDERR "error: newline in filename: " . fnq($fn0) . "\n"; $EC++; return
  }
  my $key="user.mmfs.tags";
  my $tags="\0"x65535;
  my $got=syscall($SYS_getxattr, $fn0, $key, $tags,
    length($tags), 0);
  if ((!defined $got or $got<0) and !$!{ENODATA}) {
    print STDERR "error: $fn0: $!\n"; $EC++; return
  }
  $tags =~ s@\0.*@@s;
  $tags =~ s@[\s,]+@ @g;  # E.g. get rid of newlines for --format=colon.
  $tags =~ s@\A +@@; $tags =~ s@ +\Z(?!\n)@@;
  ++$C;
  if (length($tags) or $do_print_empty) {
    ++$HC if length($tags);
    print $dump_func->($tags, defined($printfn) ? $printfn : $fn0);
    #$tags = ":none" if !length($tags); print "    $tags\n";
  }
}

sub dumpr($) {
  my $path = $_[0];
  if (-d($path)) {
    require File::Find;  # Standard Perl module.
    File::Find::find(
        {
          wanted => sub { dumpf($_) },
          no_chdir => 1,
        }, $path);
  } else {
    dumpf($path);
  }
}

my $dumpp_func = $is_recursive ? \&dumpr : \&dumpf;
if ($is_stdin) {
  my $f;
  die if !open($f, "<&3");
  my $fn0;
  while (defined($fn0 = <$f>)) {
    chomp($fn0);
    $dumpp_func->($fn0);
  }
  die if !close($f);
} else {
  for my $fn0 (@ARGV) {
    $dumpp_func->($fn0);
  }
}

# We print these messages to STDERR (rather than STDOUT starting with `# `),
# because some tools do not support extra lines, e.g. `setfattr --restore
# <tagfile>`, which restores based on `_mmfs_dump --forgat=getfattr ... >
# <tagfile>` does not support comments starting with `# `.
print STDERR "\007error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
print STDERR "info: shown tags of $HC of $C file@{[$C==1?q():q(s)]}\n";
exit 1 if $EC;
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
	perl -w -- - _mmfs_expand_tag "$@" <<'END'
$ENV{LC_MESSAGES}=$ENV{LANGUAGE}="C"; # Make $! English
use integer; use strict;  $|=1;
$0 = shift(@ARGV);
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
my $sign = "";
my $prefix = @ARGV ? $ARGV[0] : "";
$sign = $1 if $prefix =~ s@^([-+]+)@@;
my $limit = @ARGV > 1 ? 0 + $ARGV[1] : 10;
my @found_tags = grep { substr($_, 0, length($prefix)) eq $prefix } @tags;
if ($limit > 0 and @found_tags > $limit) {
  splice @found_tags, $limit - 1, @found_tags, "...";
}
print map { "$sign$_\n" } @found_tags;
exit(@found_tags > 1 ? 2 : @found_tags ? 1 : 0);
END
}
