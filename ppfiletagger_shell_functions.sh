#!/bin/sh --
unset _mmfs_PERLCODE; _mmfs_PERLCODE='
#!perl  # http://pts.github.io/Long.Perl.Header/
$0="_mmfs";eval("\n\n\n\n".<<'__END__');die$@if$@;__END__
BEGIN { $^W = 1; $| = 1 } use integer; use strict;
BEGIN { $ENV{LC_MESSAGES} = $ENV{LANGUAGE} = "C" }  # Make $! English.
my($C, $KC, $EC, $HC) = (0, 0, 0, 0);
$_ = "\n\n\n\n\n\n\n\n" . <<'END';

#
# ppfiletagger_shell_functions.sh for bash and zsh
# by pts@fazekas.hu at Sat Jan 20 22:29:43 CET 2007
#
# TODO(pts): Make it work on macOS.
#

# Simple superset of UTF-8 words.
my $tagchar_re = qr/(?:\w| [\xC2-\xDF] [\x80-\xBF] |
                           [\xE0-\xEF] [\x80-\xBF]{2} |
                           [\xF0-\xF4] [\x80-\xBF]{3}) /xo;

# --- xattr
#
# The xattr API is a hashref $attr_api:
#
# * $xattr_api->{getxattr}->($filename, $key):
#   On success, returns the value. On error, returns undef and sets $!, e.g.
#   $!{$ENOATTR} if the file does not have $key as extended attribute. It
#   fails with $!{EOPNOTSUPP} (Operation not supported) if $key does not
#   start with "user." (without the quotes) on Linux.
# * $xattr_api->{removexattr}->($filename, $key);
#   On success, returns the 1. On error, returns undef and sets $!, e.g.
#   $!{$ENOATTR} if the file did not have $key as extended attribute. It
#   fails with $!{EOPNOTSUPP} (Operation not supported) if $key does not
#   start with "user." (without the quotes) on Linux.
# * $xattr_api->{setxattr}->($filename, $key, $value);
#   On success, returns the 1. On error, returns undef and sets $!, e.g.
#   $!{$ENOATTR} if the file did not have $key as extended attribute. It
#   fails with $!{EOPNOTSUPP} (Operation not supported) if $key does not
#   start with "user." (without the quotes) on Linux.
#

sub get_archname() {
  # This is still slow: return (eval { require Config; die if !%Config::Config; $Config::Config{archname} } or "");
  for my $dir (@INC) {
    my $fn = "$dir/Config.pm";
    if (open(my($f), "<", $fn)) {
      my $S = join("", <$f>);
      close($f);
      return lc($1) if $S =~ m@\n[ \t]+archname[ \t]*=>[ \t]*[\x27"]([^-\x27"\\]+-)@;
      last
    }
  }
  ""
}

sub get_linux_xattr_syscalls() {
  my $archname = get_archname();
  # https://syscalls.w3challs.com/
  if ($archname =~ m@\A(?:x86_64|amd64)-@) {
    return (191, 197, 188, 63);
  } elsif ($archname =~ m@\A(?:i[3-6]86-|arm(?!64))@) {
    # i386 also has $SYS_olduname == 109, which does not have the domainname
    # field. Linux 2.0 already has the newest uname.
    return (229, 235, 226, 122);
  } elsif ($archname =~ m@\A(?:arm|aarch)64@) {
    return (8, 14, 5, 160)
  } elsif ($archname =~ m@\Asparc@) {  # Same for sparc and sparc64.
    return (172, 181, 169, 189)
  }
  # This works on Linux, but `require "syscall.ph" is quite slow.
  # It does not work in FreeBSD, because FreeBSD has extattr_set_file(2) etc.
  my @result = eval { package syscall; require "syscall.ph"; &syscall::SYS_getxattr, &syscall::SYS_removexattr, &syscall::SYS_setxattr, &syscall::SYS_uname };
  die "fatal: setxattr or similar syscalls not available\n" if @result != 4;
  @result
}

# FreeBSD and macOS have ENOATTR, Linux has ENODATA.
my $ENOATTR = exists($!{ENOATTR}) ? "ENOATTR" : "ENODATA";

sub get_xattr_api() {
  my $xattr_api = {};
  if ($^O eq "linux") {
    my($SYS_getxattr, $SYS_removexattr, $SYS_setxattr, $SYS_uname) = get_linux_xattr_syscalls();
    $xattr_api->{getxattr} = sub {  # ($$).
      my($filename, $key) = @_;
      my $result = "\0" x 65535;
      # For syscall, $key must be a variable, it cannot be a read-only literal.
      my $got = syscall($SYS_getxattr, $filename, $key, $result, length($result), 0);
      if (defined($got) and $got >= 0) {
        substr($result, $got) = "";
        #$result =~ s@\0.*@@s;  # Not needed anymore.
        $result
      } else {
        undef
      }
    };
    $xattr_api->{removexattr} = sub {  # ($$).
      my($filename, $key) = @_;
      my $got = syscall($SYS_removexattr, $filename, $key);
      (defined($got) and $got == 0) ? 1 : undef
    };
    $xattr_api->{setxattr} = sub {  # ($$$).
      my($filename, $key, $value) = @_;
      my $got = syscall($SYS_setxattr, $filename, $key, $value, length($value), 0);
      (defined($got) and $got == 0) ? 1 : undef
    };
    my $utsname = "\0" x 390;
    my $got = syscall($SYS_uname, $utsname);
    die "fatal: uname: $!\n" if !defined($got) or $got != 0;
    # my($sys, $node, $release, $version, $machine, $domain) = unpack("Z65Z65Z65Z65Z65Z65", $utsname);
    # die "($sys)($node)($release)($version)($machine)($domain)\n";
    # Typical $release is: 4.9.0-6-amd64.
    my $release = unpack("x65x65Z65", $utsname);
    # There is a reiserfs bug on Linux 2.6.31: cannot reliably set the
    # extended attribute to a shorter value. Workaround: set it to the empty
    # value (or remove it) first. Workaround is enabled for Linux <3.x.
    $xattr_api->{need_setxattrw} = 1 if $release !~ m@\A(\d+)[.]@ or $1 < 3;
  } else {
    eval { require File::ExtAttr };  # https://metacpan.org/pod/File::ExtAttr
    die "fatal: please install Perl module File::ExtAttr\n" if $@;
    if (!defined(&File::ExtAttr::openhandle)) {  # Bugfix for File::ExtAttr 1.09.
      eval { package File::ExtAttr; use Scalar::Util qw(openhandle) };
      die $@ if $@;
    }
    my $fix_key = sub {
      my $key = $_[1];
      die "fatal: invalid xattr key, must start with user.: $key\n" if
          $key !~ s@\A\Quser.@@;
      splice @_, 1, 1, $key;
      @_
    };
    $xattr_api->{getxattr} =    sub { File::ExtAttr::getfattr($fix_key->(@_)) } if defined(&File::ExtAttr::getfattr);
    $xattr_api->{removexattr} = sub { File::ExtAttr::delfattr($fix_key->(@_)) } if defined(&File::ExtAttr::delfattr);
    $xattr_api->{setxattr} =    sub { File::ExtAttr::setfattr($fix_key->(@_)) } if defined(&File::ExtAttr::setfattr);
    $xattr_api->{need_setxattrw} = 1 if $^O eq "linux";
  }
  die "fatal: xattr not available\n" if
      !defined($xattr_api->{getxattr}) or !defined($xattr_api->{removexattr}) or !defined($xattr_api->{setxattr});
  $xattr_api
}

my $xattr_api = get_xattr_api();

sub setxattr_safe($$$$$) {
  my($filename, $key, $old_value, $value, $do_remove_if_empty) = @_;
  die "$0: assert: undefined old value for xattr key: $key\n" if !defined($old_value);
  die "$0: assert: undefined value for xattr key: $key\n" if !defined($value);
  return $xattr_api->{removexattr}->($filename, $key) if $do_remove_if_empty and !length($value);
  if ($xattr_api->{need_setxattrw}) {
    if (length($value) > 0 and !defined($old_value)) {
      return undef if !defined($old_value = $xattr_api->{getxattr}->($filename, $key));
    }
    if (length($value) > 0 and length($value) < length($old_value)) {
      if (!$xattr_api->{setxattr}->($filename, $key, "")) {
        $xattr_api->{setxattr}->($filename, $key, $old_value);  # Try to restore the old value.
        return undef;
      }
    }
  }
  return 1 if defined($old_value) and $old_value eq $value;
  $xattr_api->{setxattr}->($filename, $key, $value)
}

my $key0 = "user.mmfs.tags";

# --- read_tags_file

#** Reads the tag list file (of lines <tag> or <tag>:<description> or
#** <space><comment> or #<comment>).
#** @return {$tagv => 1, ...}.
sub read_tags_file(;$) {
  my $tags_fn = $_[0];
  $tags_fn = "$ENV{HOME}/.ppfiletagger_tags" if !defined($tags_fn);
  my $F;
  die "$0: fatal: error opening tags file: $tags_fn: $!\n" if
      !open($F, "<", $tags_fn);
  my $lineno = 0;
  my $tags = {};
  for my $line (<$F>) {
    ++$lineno;
    next if $line !~ /^([^\s#][^:\s]*)([\n:]*)/;
    my $tag = $1;
    if (!length($2)) {
      print STDERR "syntax error in $tags_fn:$.: missing colon or newline\n"; exit 4;
    }
    if ($tag !~ /\A(?:$tagchar_re)+\Z(?!\n)/) {
      # TODO(pts): Support -* here.
      print STDERR "syntax error in $tags_fn:$lineno: bad tag syntax: $tag\n";
      exit 5;
    }
    if (exists $tags->{$tag}) {
      print STDERR "syntax error in $tags_fn:$lineno: duplicate tag: $tag\n";
      exit 6;
    }
    $tags->{$tag} = 1;
    $tags->{"v:$tag"} = 1;  # Vetted.
  }
  die unless close $F;
  $tags
}

# --- _mmfs_tag : xattr read_tags_file

my $known_tags = read_tags_file();
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
      print "bad tag item syntax ($pmtag), skipping files\n"; exit 3;
    }
    my $tag = $2;
    if ($do_overwrite and $1 eq "-") {
      print "unexpected sign ($pmtag), skipping files\n"; exit 9;
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
    print "unknown tags (@unknown_tags), skipping files\n"; exit 7;
  }
  { @ptags = grep { !exists($fmtags_hash{$_}) } @ptags if %fmtags_hash;
    my %ptags_hash = map { $_ => 1 } @ptags;
    my @intersection_tags = grep { exists($ptags_hash{$_}) } @mtags;
    if (@intersection_tags) {
      @intersection_tags = sort @intersection_tags;
      print "plus and minus tags (@intersection_tags), skipping files\n";
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

    my $got;
    my %old_tags_hash;
    my @old_tags;
    my $old_tags_str = "";
    my($ptags_ref, $mtags_ref) = (\@ptags, \@mtags);

    # Populates $old_tags_str, %old_tags_hash, @old_tags, maybe modifies
    # $ptags_ref and $mtags_ref.
    {
      $old_tags_str = $xattr_api->{getxattr}->($fn0, $key0);
      if (!defined($old_tags_str) and !$!{$ENOATTR}) {
        my $is_eio = $!{EIO};
        print "    error getting: $!\n"; $EC++;
        next FN0 if !($is_eio and $do_overwrite);
        $old_tags_str = "?";
        $old_tags_hash{"?"} = 1;
        push @old_tags, "?";
      } else {
        $old_tags_str = "" if !defined($old_tags_str);
        for my $tag (split(/\s+/, $old_tags_str)) {
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
    if (!setxattr_safe($fn0, $key0, $old_tags_str, join(" ", @new_tags), 1)) {
      print "    error: $!\n"; $EC++
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

#** Adds or removes tags on files.
#** Midnight Commander menu action implementation for movemetafs (mmfs).
#** It works for weird filenames (containing e.g. " " or "\n"), too.
#** SUXX: prompt questions may not contain macros
#** SUXX: no way to signal an error
#** @example _mmfs_tag "tag1 -tag2 ..." file1 file2 ...    # keep tag3
sub _mmfs_tag {
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
    my($tagspec, $filenames) = ($ARGV[1], [<STDIN>]);
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
    while (defined($line = <STDIN>)) {
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
  }
  print "error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
  print "kept tags of $KC file@{[$KC==1?q():q(s)]}\n" if $KC;
  print "$action tags of $C file@{[$C==1?q():q(s)]}: $tagspecmsg\n";
}

# --- _mmfs_unify_tags : xattr

#** Makes both files have the union of the tags.
#** SUXX: needed 2 runs: modified 32, then 4, then 0 files (maybe because of
#**   equivalence classes)
#** @example _mmfs_unify_tags file1 file2
#** @example echo "... 'file1' ... 'file2' ..." ... | _mmfs_unify_tags --stdin
sub _mmfs_unify_tags {
  $0="_mmfs_unify_tags";
  die "$0: makes both files have to union of tags
Usage: $0 <file1> <file2>
    or echo \"... \x27file1\x27 ... \x27file2\x27 ...\" ... | $0 --stdin
" if @ARGV!=2 and @ARGV!=1;
  print "unifying tags\n";

  #** @return :String, may be empty
  sub get_tags($) {
    my $fn0 = $_[0];
    #print "  $fn0\n";
    my $tags = $xattr_api->{getxattr}->($fn0, $key0);
    if (!defined($tags) and !$!{$ENOATTR}) {
      print "  get-error: $fn0: $!\n"; $EC++;
      return undef;
    } else {
      return defined($tags) ? $tags : "";
    }
  }

  sub add_tags($$;$) {
    my($fn0,$tags,$rmtags)=@_;
    my %rmtags;
    %rmtags=map { $_ => 1 } split(/\s+/, $rmtags) if defined $rmtags;
    die "error: bad add-tags syntax: $tags\n" if $tags =~ /[+-]/;
    return if $tags !~ /\S/ and !%rmtags;
    #print "  $fn0\n";
    my $tags0 = $xattr_api->{getxattr}->($fn0, $key0);
    if (!defined($tags0) and !$!{$ENOATTR}) {
      print "  add-get-error: $fn0: $!\n"; $EC++; return
    }
    $tags0 = "" if !defined($tags0);
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
    if ($tags0 eq $tags1) {
    } elsif (setxattr_safe($fn0, $key0, $tags0, $tags1, 1)) {
      $C++;
    } else {
      print "  set-error: $fn0: $!\n"; $EC++;
    }
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
    if ($tags0c eq $tags1c) {  # Copy (order of) tags from $fn1 to $fn0. No $C++.
      if (!setxattr_safe($fn0, $key0, $tags0b, $tags1b, 1)) {
        print "  order-set-error: $fn0: $!\n"; $EC++;
      }
      print "  unified ($tags0c): ($fn0) ($fn1)\n";
    } else {
      my @common_tags = grep { my $tag = $_; grep { $tag eq $_ } @tags1l } @tags0l;
      my @tags0ol = grep { my $tag = $_; !grep { $tag eq $_ } @common_tags } @tags0l;
      my @tags1ol = grep { my $tag = $_; !grep { $tag eq $_ } @common_tags } @tags1l;
      print "  failed to unify: common:(@common_tags), ($fn0):(@tags0ol), ($fn1):(@tags1ol)\n";
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

  print "error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
  print "modified tags of $C file@{[$C==1?q():q(s)]}\n";
}

# --- _mmfs_show : xattr

#** Midnight Commander menu action implementation for movemetafs (mmfs).
#** It works for weird filenames (containing e.g. " " or "\n"), too
#** SUXX: prompt questions may not contain macros
#** SUXX: no way to signal an error
#** @example _mmfs_show file1 file2 ...
sub _mmfs_show {
  use Cwd;
  my $do_show_abs_path = 0;
  my $do_readdir = 0;
  my $process_file = sub {  # ($)
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
    my $tags = $xattr_api->{getxattr}->($fn0, $key0);
    if (!defined($tags) and !$!{$ENOATTR}) {
      print "    error: $!\n"; $EC++
    } else {
      $tags = "" if !defined($tags);
      my @tags = split/\s+/, $tags;
      my @n_tags = grep { !/^v:/ } @tags;
      my @v_tags = grep { /^v:/  } @tags;
      if ($tags ne"") { $HC++ } else { @n_tags=(":none") }
      print "    @n_tags\n";  $C++;
      print "    @v_tags\n" if @v_tags;
    }
  };
  if (@ARGV and $ARGV[0] eq "--abspath") { $do_show_abs_path = 1; shift @ARGV }
  if (@ARGV and $ARGV[0] eq "--readdir") { $do_readdir = 1; shift @ARGV }
  if ($do_readdir) {
    for my $arg (@ARGV) {
      if (-d $arg) {
        my $d;
        die if !opendir $d, $arg;
        #my $entry;
        #while (defined($entry = readdir($d))) {...}
        for my $entry (sort readdir($d)) {
          next if $entry eq "." or $entry eq "..";
          $process_file->("$arg/$entry");
        }
        die if !closedir $d;
      } else {
        $process_file->($arg);
      }
    }
  } else {
    for my $fn0 (@ARGV) { $process_file->($fn0) }
  }
  print "error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
  print "shown tags of $HC of $C file@{[$C==1?q():q(s)]}\n";
}

# --- _mmfs_get_tags : xattr

#** Like _mmfs_show, but only one file, and without extras. Suitable for
#** scripting.
#** It works for weird filenames (containing e.g. " " or "\n"), too.
#** @example _mmfs_get_tags file1
sub _mmfs_get_tags {
  die "error: not a single filename specified\n" if @ARGV != 1;
  my $fn0 = $ARGV[0];
  my $tags = $xattr_api->{getxattr}->($fn0, $key0);
  if (defined($tags)) {
    exit(1) if 0 == length($tags);
    print "$tags\n";
  } elsif ($!{$ENOATTR}) {
    exit(1);
  } else {
    print STDERR "error: $fn0: $!\n";
    exit(2);
  }
}

# --- _mmfs_grep : xattr

#** @example ls | _mmfs_grep "+foo -bar baz"  # anything with foo and baz, but without bar
#** @example ls | _mmfs_grep "* -2004"        # anything with at least one tag, but without 2004
#** @example ls | _mmfs_grep "*-foo *-bar"    # anything with at least one tag, which is not foo or bar
#** @example ls | _mmfs_grep "-*"             # anything without tags
sub _mmfs_grep {
  die "Usage: $0 <tagquery>\n" if 1!=@ARGV;
  my @orterms;
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
  my $fn0;
  while (defined($fn0=<STDIN>)) {
    chomp $fn0;
    #print "  $fn0\n";
    my $tags = $xattr_api->{getxattr}->($fn0, $key0);
    if (!defined($tags) and !$!{$ENOATTR}) {
      print STDERR "error: $fn0: $!\n"; $EC++
    } else {
      $tags = "" if !defined($tags);
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
}

# --- _mmfs_dump : xattr

#** @example _copyattr() { _mmfs_dump --printfn="$2" -- "$1"; }; duprm.pl . | perl -ne "print if s@^rm -f @_copyattr @ and s@ #, keep @ @" >_d.sh; source _d.sh | sh
sub _mmfs_dump {
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
            "setfattr -n $key0 -v " . fnq($tags) . " -- " . fnq($filename) . "\n" :
            "setfattr -x $key0 -- " . fnq($filename) . "\n"
      } : ($format eq "colon") ? sub {
        my($tags, $filename) = @_;
        "$tags :: $filename\n"
      } : ($format eq "getfattr") ? sub {
        my($tags, $filename) = @_;
        # getfattr always omits files without tags (i.e. without the
        # $key0 extended attribute). Use _mmfs_dump --print-empty=no
        # to get this behavior.
        "# file: $filename\n$key0=" . gfaq($tags). "\n\n"
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
  die "$0: assert: unknown format: $format\n" if !defined($dump_func);

  #print "to these files:\n";
  my $dumpf = sub {  # ($)
    my $fn0 = $_[0];
    #print "  $fn0\n";
    return if !-f($fn0);
    if ($fn0 =~ y@\n@@) {
      print STDERR "error: newline in filename: " . fnq($fn0) . "\n"; $EC++; return
    }
    my $tags = $xattr_api->{getxattr}->($fn0, $key0);
    if (!defined($tags) and !$!{$ENOATTR}) {
      print STDERR "error: $fn0: $!\n"; $EC++; return
    }
    $tags = "" if !defined($tags);
    $tags =~ s@[\s,]+@ @g;  # E.g. get rid of newlines for --format=colon.
    $tags =~ s@\A +@@; $tags =~ s@ +\Z(?!\n)@@;
    ++$C;
    if (length($tags) or $do_print_empty) {
      ++$HC if length($tags);
      print $dump_func->($tags, defined($printfn) ? $printfn : $fn0);
      #$tags = ":none" if !length($tags); print "    $tags\n";
    }
  };

  my $dumpr = sub {  # ($)
    my $path = $_[0];
    if (-d($path)) {
      require File::Find;  # Standard Perl module.
      # Prints a 2-line error message to stderr for bad directories.
      # TODO(pts): Better print error, propagate it as exit code.
      File::Find::find(
          {
            wanted => sub { $dumpf->($_) },
            no_chdir => 1,
          }, $path);
    } else {
      $dumpf->($path);
    }
  };

  my $dumpp_func = $is_recursive ? $dumpr : $dumpf;
  if ($is_stdin) {
    my $f;
    my $fn0;
    while (defined($fn0 = <STDIN>)) {
      chomp($fn0);
      $dumpp_func->($fn0);
    }
  } else {
    for my $fn0 (@ARGV) {
      $dumpp_func->($fn0);
    }
  }

  # We print these messages to STDERR (rather than STDOUT starting with `# `),
  # because some tools do not support extra lines, e.g. `setfattr --restore
  # <tagfile>`, which restores based on `_mmfs_dump --forgat=getfattr ... >
  # <tagfile>` does not support comments starting with `# `.
  print STDERR "error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
  print STDERR "info: shown tags of $HC of $C file@{[$C==1?q():q(s)]}\n";
}

# --- _mmfs_fixprincipal

#** @example _mmfs_fixprincipal file1 file2 ...
sub _mmfs_fixprincipal# Hide from <command> list.
{
  die "$0: fatal: not supported with ppfiletagger\n";
}

# --- _mmfs_expand_tag : read_tags_file

#** Displays all known tags whose prefix is $1, displaying at most $2 tags.
#** @example _mmfs_expand_tag ta
sub _mmfs_expand_tag {
  my @tags = sort(keys(%{read_tags_file()}));
  my $sign = "";
  my $prefix = @ARGV ? $ARGV[0] : "";
  $sign = $1 if $prefix =~ s@^([-+]+)@@;
  my $limit = @ARGV > 1 ? 0 + $ARGV[1] : 10;
  my @found_tags =
      $prefix =~ m@\Av(?!:)@ ?  # Hide v:... if prefix doess not start with v:
      grep { substr($_, 0, length($prefix)) eq $prefix and substr($_, 0, 2) ne "v:" } @tags :
      grep { substr($_, 0, length($prefix)) eq $prefix } @tags;
  if ($limit > 0 and @found_tags > $limit) {
    splice @found_tags, $limit - 1, @found_tags, "...";
  }
  print map { "$sign$_\n" } @found_tags;
  exit(@found_tags > 1 ? 2 : @found_tags ? 1 : 0);
}

# --- end
END
my %parts;
my @partps;
while (m@\n# ---([ \t]*(\w+)(?: :[ \t]*([\w \t]*)|[ \t]*)(?=\n))?@g) {
  die "$0: assert bad part separator\n" if !defined($1);
  my $part = $2;
  push @partps, $part, pos($_) - length($1) - 6;
  my @deps = split(/\s+/, defined($3) ? $3 : "");
  die "$0: assert: duplicate part: $part\n" if exists($parts{$part});
  $parts{$part} = \@deps;
}
# This also includes fixprincipal.
# my @cmds = map { m@^_mmfs_(.*)@ and $1  ? ($1) : () } keys(%parts);
my @cmds;
while (m@\nsub[ \t]+(_mmfs_(\w+))[ \t({]@g) { push @cmds, $2 if exists($parts{$1}) }

sub exit_usage() {
  print STDERR "$0: file tagging and search-by-tag tool\n" .
      "Usage: _mmfs <command> [<arg> ...]\n" .
      "Supported <command>s: @cmds\n";
  exit(1);
}

if (!@ARGV or $ARGV[0] eq "--help") {
  exit_usage();
#} elsif ($ARGV[0] eq "--load") {
} elsif ($ARGV[0] eq "--shfn") {
  for my $cmd (@cmds) {
    print "_mmfs_$cmd() { _mmfs $cmd \"\$@\"; }\n";
  }
} else {
  my $is_mcmenu = $ARGV[0] eq "--mcmenu";
  if ($is_mcmenu) {
    shift(@ARGV);
    exit_usage() if !@ARGV;
  }
  my $cmd = shift(@ARGV);
  if ($cmd eq "help") {
    exit_usage() if !@ARGV;
    if (@ARGV == 1) { $cmd = shift(@ARGV); push @ARGV, "--help" }
  }
  {
    my $cmdp = "_mmfs_$cmd";
    die "fatal: no $0 <command>: $cmd\n" if !exists($parts{$cmdp});
    my %done;
    my @todo = ($cmdp);
    for my $part (@todo) {  # Figure out which parts are used.
      if (!exists($done{$part})) {
        $done{$part} = 1;
        for my $part2 (@{$parts{$part}}) {
          die "$0: assert: missing dep: $part2\n" if !exists($parts{$part2});
          push @todo, $part2;
        }
      }
    }
    my @src = (substr($_, 0, $partps[1]));
    for (my $i = 2; $i < @partps; $i += 2) {  # Prepare only used code parts.
      my ($part, $pos, $endpos) = ($partps[$i - 2], $partps[$i - 1], $partps[$i + 1]);
      my $partsrc = substr($_, $pos, $endpos - $pos);
      $partsrc =~ y@\n@@cd if !exists($done{$part});
      push @src, $partsrc;
    }
    $_ = join("", @src);
  }
  eval; die $@ if $@;  # Delayed and partial parsing of actual Perl code.
  my $func; { no strict qw(vars); $func = \&{__PACKAGE__ . "::_mmfs_$cmd" } }
  if (!defined(&$func)) {
    print STDERR "$0: assert: no command func: $cmd\n";
    exit(1);
  }
  $0 .= " $cmd";
  if ($is_mcmenu) {
    # Use fork to catch fatal signals etc.
    my $pid = fork();
    die "fatal: fork(): $!\n" if !defined($pid);
    if ($pid) {  # Parent.
      die "fatal: waitpid(): !\n" if $pid != waitpid($pid, 0);
      my $exit_code = ($? & 255) | ($? >> 8);
      print STDERR "\007see error $exit_code above\n" if $exit_code;
      { my $f = select(STDERR); $| = 1; select($f); }
      print STDERR "Press <Enter> to return to mc.";  # No trailin \n
      <STDIN>;
      exit($exit_code);
    }
  }
  $func->(@ARGV);
  exit 1 if $EC;
}

__END__
'  # Trailer of http://pts.github.io/Long.Perl.Header/
case "$(exec 2>&1; set -x; : "a b")" in  # Avoid E2BIG with long argv.
*" : 'a b'") unset _ARGV_PERLCODE; _ARGV_PERLCODE='
  local $_ = ""; while (read(STDIN, $_, 65536, length)) {}
  die "fatal: missing stdin-ARGV\n" if !m@\A(.*? : -)[ \n]@;
  pos($_) = length($1);
  while (m@\G(?:\n\Z(?!\n)|\ \x27((?:[^\x27]+|\x27\\\x27\x27)*)\x27
           (\\\x27(?=[\ \n]))?|\ ([^\x27"\$\\\ \n]+))@gcx) {
    if (defined($1)) { push @ARGV, $1; $ARGV[-1] =~ s@\x27\\\x27\x27@\x27@g;
      $ARGV[-1] .= $2 if defined($2) }
    elsif (defined($3)) { push @ARGV, $3 }
  }
  die "fatal: bad stdin-ARGV\n" if pos($_) != length($_);
  if (open(my($fd9), "<&=9")) { open(STDIN, "<&9"); close($fd9) }
'; _mmfs() {
  (exec 9>&0; (exec 2>&1; set -x; : - "$@") |
  (export _ARGV_PERLCODE; export _mmfs_PERLCODE
   exec perl -e '$0="_mmfs";
   eval$ENV{_ARGV_PERLCODE};die$@if$@;$_=$ENV{_mmfs_PERLCODE};
   s@^.*?;__END__\n@undef\$_;\n\n\n\n@s;
   s@<<([A-Z]\w*)@<<\x27$1\x27@g;eval;die$@if$@'))
} ;;
*) _mmfs() {
  (export _mmfs_PERLCODE; exec perl -e '$0="_mmfs";
   $_=$ENV{_mmfs_PERLCODE};s@^.*?;__END__\n@undef\$_;\n\n\n\n@s;
   s@<<([A-Z]\w*)@<<\x27$1\x27@g;eval;die$@if$@' -- "$@")
} ;;
esac
if test "$1" = --load; then
  eval "$(_mmfs --shfn || echo false)"  # Create more shell functions.
else
  _mmfs "$@"
fi
