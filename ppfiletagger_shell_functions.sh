#!/bin/sh --
eval 'PERL_BADLANG=x;export PERL_BADLANG;exec perl -x "$0" "$@";exit 1'
#!perl  # Start marker used by perl -x.
+0 if 0;eval("\n\n\n\n".<<'__END__');die$@if$@;__END__
BEGIN { $^W = 1; $| = 1 } use integer; use strict;
BEGIN { $ENV{LC_MESSAGES} = $ENV{LANGUAGE} = "C" }  # Make $! English.
my($C, $KC, $EC, $HC) = (0, 0, 0, 0);
$_ = "\n\n\n\n\n\n\n\n" . <<'END';

#
# ppfiletagger_shell_functions.sh: command-line tool for file tag manipulation and search
# by pts@fazekas.hu at Sat Jan 20 22:29:43 CET 2007
#
# For unlimited argv support, load the shell functions as:
# eval "$(perl -x .../ppfiletagger_shell_functions.sh --load)"
# , and then call lfo etc. interactively.
#
# TODO(pts): Add an option reject invalid tagvs to _cmd_grep etc.
# TODO(pts): Add descript.ion support as a fallback for e.g. FAT32 and exFAT filesystems.
#

# Simple superset of UTF-8 words.
my $tagchar_re = qr/(?:\w| [\xC2-\xDF] [\x80-\xBF] |
                           [\xE0-\xEF] [\x80-\xBF]{2} |
                           [\xF0-\xF4] [\x80-\xBF]{3}) /x;

my $key0 = ($0 eq "_mmfs" or $0 eq "mmfs" or $0 eq "ppfiletagger") ?
    "user.mmfs.tags" :  # Legacy.
    "user.mmfs.tags";

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

#** Supports Linux (linux) and macOS (darwin) only.
sub get_xattr_syscalls() {
  # https://opensource.apple.com/source/xnu/xnu-4570.41.2/bsd/kern/syscalls.master.auto.html
  return (234, 238, 236, undef) if $^O eq "darwin";
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
  # It does not work on FreeBSD, because FreeBSD has extattr_set_file(2) etc.
  my @result = eval { package syscall; require "syscall.ph"; &syscall::SYS_getxattr, &syscall::SYS_removexattr, &syscall::SYS_setxattr, &syscall::SYS_uname };
  die1 "$0: fatal: setxattr or similar syscalls not available\n" if @result != 4;
  @result
}

# FreeBSD and macOS have ENOATTR, Linux has ENODATA.
my $ENOATTR = exists($!{ENOATTR}) ? "ENOATTR" : "ENODATA";

sub get_xattr_api() {
  my $xattr_api = {};
  if ($^O eq "linux" or $^O eq "darwin") {
    my($SYS_getxattr, $SYS_removexattr, $SYS_setxattr, $SYS_uname) = get_xattr_syscalls();
    $xattr_api->{getxattr} = sub {  # ($$).
      my($filename, $key) = @_;
      my $result = "\0" x 65535;
      # For syscall, $key must be a variable, it cannot be a read-only literal.
      # macOS ("darwin") requires the extra 0 argument.
      my $got = syscall($SYS_getxattr, $filename, $key, $result, length($result), 0, 0);
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
      my $got = syscall($SYS_removexattr, $filename, $key, 0);
      (defined($got) and $got == 0) ? 1 : undef
    };
    $xattr_api->{setxattr} = sub {  # ($$$).
      my($filename, $key, $value) = @_;
      my $got = syscall($SYS_setxattr, $filename, $key, $value, length($value), 0, 0);
      (defined($got) and $got == 0) ? 1 : undef
    };
    if ($^O eq "linux") {
      my $utsname = "\0" x 390;
      my $got = syscall($SYS_uname, $utsname);
      die1 "$0: fatal: uname: $!\n" if !defined($got) or $got != 0;
      # my($sys, $node, $release, $version, $machine, $domain) = unpack("Z65Z65Z65Z65Z65Z65", $utsname);
      # die1 "($sys)($node)($release)($version)($machine)($domain)\n";
      # Typical $release is: 4.9.0-6-amd64.
      my $release = unpack("x65x65Z65", $utsname);
      # There is a reiserfs bug on Linux 2.6.31: cannot reliably set the
      # extended attribute to a shorter value. Workaround: set it to the empty
      # value (or remove it) first. Workaround is enabled for Linux <3.x.
      $xattr_api->{need_setxattrw} = 1 if $release !~ m@\A(\d+)[.]@ or $1 < 3;
    }
  } else {
    eval { require File::ExtAttr };  # https://metacpan.org/pod/File::ExtAttr
    die1 "$0: fatal: please install Perl module File::ExtAttr\n" if $@;
    my $fix_key = sub {
      my $key = $_[1];
      die1 "$0: fatal: invalid xattr key, must start with user.: $key\n" if
          $key !~ s@\A\Quser.@@;
      splice @_, 1, 1, $key;
      @_
    };
    $xattr_api->{getxattr} =    sub { File::ExtAttr::getfattr($fix_key->(@_)) } if defined(&File::ExtAttr::getfattr);
    $xattr_api->{removexattr} = sub { File::ExtAttr::delfattr($fix_key->(@_)) } if defined(&File::ExtAttr::delfattr);
    $xattr_api->{setxattr} =    sub { File::ExtAttr::setfattr($fix_key->(@_)) } if defined(&File::ExtAttr::setfattr);
    $xattr_api->{need_setxattrw} = 1 if $^O eq "linux";
  }
  die1 "$0: fatal: xattr not available\n" if
      !defined($xattr_api->{getxattr}) or !defined($xattr_api->{removexattr}) or !defined($xattr_api->{setxattr});
  $xattr_api
}

my $xattr_api = get_xattr_api();

sub setxattr_safe($$$$$) {
  my($filename, $key, $old_value, $value, $do_remove_if_empty) = @_;
  die1 "$0: assert: undefined old value for xattr key: $key\n" if !defined($old_value);
  die1 "$0: assert: undefined value for xattr key: $key\n" if !defined($value);
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

# --- read_tags_file

#** Reads the tag list file (of lines <tag> or <tag>:<description> or
#** <space><comment> or #<comment>).
#** @return {$tagv => 1, ...}.
sub read_tags_file(;$) {
  my $tags_fn = $_[0];
  $tags_fn = "$ENV{HOME}/.ppfiletagger_tags" if !defined($tags_fn);
  my $F;
  die1 "$0: fatal: error opening tags file: $tags_fn: $!\n" if
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
    if ($tag !~ /\A(?:$tagchar_re)+\Z(?!\n)/o) {
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

# --- parse_dump

#** Reads and parses a dump file, and calls $process_func->($filename,
#** $tags, $default_mode) for filename--tagvs pair found. Autodetects the
#** input as the concatenation of any of the following formats: sh, colon,
#** getfattr, mfi. See get_format_func for generating files in these
#** formats.
sub parse_dump($$) {
  my($fh, $process_func) = @_;
  my $sharg_re = qr@[^\s()\\\x27"`;&<>*?\[\]$|#]+|\x27(?:[^\x27]++|\x27\\\x27\x27)*+\x27@;
  my $sharg_decode = sub { my $s = $_[0]; $s =~ s@\x27\\\x27\x27@\x27@g if $s =~ s@\A\x27(.*)\x27@$1@s; $s };
  my($line, $cfilename, $lineno);
  while (defined($line = <STDIN>)) {
    $lineno = $.;
    if ($line =~ m@^# file: (.*)\n@) {  # Output of getfattr.
      $cfilename = $1
    } elsif ($line =~ m@^([^#\n=:"\s]+)(?:="(.*?)")?\n@) {  # Output of getfattr.
      my($key, $value) = ($1, $2);
      die1 "$0: fatal: bad key: $key ($lineno)\n" if $key =~ m@["\\]@;
      die1 "$0: fatal: missing filename for key: $key ($lineno)\n" if
          !defined($cfilename);
      $process_func->($cfilename, $value, ".") if $key eq $key0;
    } elsif ($line =~ m@(.*?) :: (.*?)\n@) {
      my($tagspec, $filename) = ($1, $2);
      $process_func->($filename, $tagspec, undef);
    } elsif ($line =~ m@^#@) {  # Comment.
    } elsif ($line =~ m@^(?:setfattr[ \t]+-x|xattr[ \t]+-d)[ \t]+\Q$key0\E[ \t]+(?:--[ \t]+)?($sharg_re)[ \t]*\n@o) {
      my $filename = $sharg_decode->($1);
      $process_func->($filename, "", ".");
    } elsif ($line =~ m@^(?:setfattr[ \t]+-n|xattr[ \t]+-w)[ \t]+\Q$key0\E[ \t]+(?:-v[ \t]+)?($sharg_re)[ \t]+(?:--[ \t]+)?($sharg_re)[ \t]*\n@o) {
      my($tags, $filename) = ($sharg_decode->($1), $sharg_decode->($2));
      $process_func->($filename, $tags, ".");
    } elsif ($line =~ m@^format=(?:[^ ]+)(?= )(.*?) f=(.*)\n@) {  # mediafileinfo form.
      my $filename = $2;
      $line = $1;
      my $tags = $line =~ m@ tags=([^ ]+)@ ? $1 : "";
      $process_func->($filename, $tags, undef);
    } elsif ($line eq "\n") {
      $cfilename = undef
    } else {
      die1 "$0: fatal: incomplete tagfile line ($lineno): $line\n" if !chomp($line);
      die1 "$0: fatal: bad tagfile line ($lineno): $line\n";
    }
  }
}

# --- _cmd_tag : xattr read_tags_file parse_dump

my $known_tags;
my $pmtag_re = qr/(---|[-+]?)((?:v:)?(?:$tagchar_re)+)/o;

sub apply_tagspec($$$$) {
  my($tagspec, $mode, $get_filenames_func, $is_verbose) = @_;
  # Parse $tagspec (<tagpec>).
  $tagspec = "" if !defined($tagspec);
  $tagspec =~ s@\A\s+@@;
  $mode = "++" if !defined($mode) or !length($mode);
  die1 "$0: fatal: bad mode: $mode\n" if $mode ne "." and $mode ne "+" and $mode ne "++";
  my @ptags;
  my @mtags;
  my @unknown_tags;
  my %fmtags_hash;
  # Overwrite tags if starts with a dot. Used by qiv-command.
  $mode = $1 if $tagspec =~ s@\A([.]|[+]|[+][+])(?:[\s,]+|\Z)@@;
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
    } elsif (defined($known_tags) and !exists($known_tags->{$tag})) {
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
  FN0: for my $fn0 (@{$get_filenames_func->()}) {
    print "  $fn0\n";
    if ($is_nop) {
      print "    unchanged by tagspec: $tagspecmsg\n" if $is_verbose;
      $KC++; next FN0
    }
    if (!-f($fn0)) {
      if (!-e(_)) {
        print "    error: missing\n";
      } else {
        print "    error: not a file\n";
      }
      $EC++; next FN0
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
  $tagspec =~ s@\A\Q./@@;  # Prepended by Midnight Commander (mc).
  # For a long list of files, it's faster to pass the reference ($filenames).
  my $get_filenames_func = sub { print "to these files:\n"; $filenames };
  my($tag_mode, $tagspecmsg) = apply_tagspec($tagspec, "++", $get_filenames_func, 0);
  my $action = $tag_mode eq "overwrite" ? "overwritten" : $tag_mode eq "merge" ? "merged" : "changed";
  ($action, $tagspecmsg)
}

#** See docs for using this command from Midnight Commander (mc) menu.
#** FYI No way to signal an error to Midight Commander without pausing.
#** Example: _cmd_tag "tag1 -tag2 ..." file1 file2 ...    # keep tag3
sub _cmd_tag {
  if (!@ARGV or $ARGV[0] eq "--help") {
    print STDERR "$0: adds or removes tags on files
Usage: $0 [--] \x27<tagspec>\x27 [<filename> ...]
    or ls | $0 --stdin [--] \x27<tagspec>\x27
    or $0 [<flag> ...] < <tagfile>
<tagfile> contains:
* Empty lines and comments starting with # + whitespace.
* Lines of the colon form: <tagspec> :: <filename>
* Lines of the setfattr form: setfattr -n $key0 -v \x27<tags>\x27 \x27<filename>\x27
* Lines of the setfattr form: setfattr -x $key0 \x27<filename>\x27
* Lines of the xattr form: xattr -w $key0 \x27<tags>\x27 \x27<filename>\x27
* Lines of the xattr form: xattr -d $key0 \x27<filename>\x27
* Lines of the mediafileinfo form: format=... ... tags=<tags> ... f=<filename>
* Output of: getfattr -hR -e text -n $key0 --absolute-names <path>
Flags:
--stdin : If <tagspec> is specified, then get filenames from stdin rather
  than command-line. Otherwise same as --stdin-tagfile.
--stdin-tagfile : Read <tagfile> from stdin.
--any-tag-ok : Do not read the known-tags file, accept any tag.
--prefix=<prefix> : Add prefix in front of each <tagspec> .
--mode=change : Use change mode, like --prefix=++
--mode=overwrite | --mode=set | --set : Use overwrite mode, like --prefix=.
--mode=merge | --merge : Use merge mode, like --prefix=+ and unify_tags.
The default for setfattr and getfattr is --set, otherwise --mode=change.
";
    exit(!@ARGV);
  }
  my $tagspecmsg = "...";
  my $action = "modified";
  if ((@ARGV == 2 and $ARGV[0] eq "--stdin" and $ARGV[1] ne "-" and substr($ARGV[1], 0, 2) ne "--") or
      (@ARGV == 3 and $ARGV[0] eq "--stdin" and $ARGV[1] eq "--" and $ARGV[2] ne "-" and substr($ARGV[2], 0, 2) ne "--")) {
    # Read filenames from stdin, apply tags in $ARGV[1];
    my($tagspec, $filenames) = ($ARGV[-1], [<STDIN>]);
    for my $fn0 (@$filenames) { die1 "$0: fatal: incomplete line in filename: $fn0\n" if !chomp($fn0); }
    $known_tags = read_tags_file();
    ($action, $tagspecmsg) = apply_to_multiple($tagspec, $filenames);
  } elsif (@ARGV and (($ARGV[0] eq "--" and @ARGV > 1) or $ARGV[0] !~ m@\A--(?:[^-]|\Z(?!\n))@)) {
    # Apply tags in $ARGV[0] to the files with filenames in @ARGV[1..].
    shift(@ARGV) if @ARGV and $ARGV[0] eq "--";
    # Midnight Commander (mc) prepends ./ to @ARGV elements starting with -.
    my($tagspec, $filenames) = (shift(@ARGV), \@ARGV);
    $known_tags = read_tags_file();
    ($action, $tagspecmsg) = apply_to_multiple($tagspec, $filenames);
  } else {  # Read <tagfile> (containing filename--tags pairs) from stdin, apply those tags.
    my $mode;
    my $tagspec_prefix = "";
    my $stdin_mode = 0;
    my $do_read_tags_file = 1;
    my $i = 0;
    while ($i < @ARGV) {
      my $arg = $ARGV[$i++];
      if ($arg eq "-" or substr($arg, 0, 1) ne "-") { --$i; last }
      elsif ($arg eq "--") { last }
      elsif ($arg eq "--stdin" or $arg eq "--stdin-tagfile" or $arg eq "--stdin-dump") { $stdin_mode = 2 }
      elsif ($arg eq "--mode=change" or $arg eq "--mode=++") { $mode = "++" }
      elsif ($arg eq "--mode=overwrite" or $arg eq "--mode=set" or $arg eq "--mode=++" or $arg eq "-overwrite" or $arg eq "--set") { $mode = "." }
      elsif ($arg eq "--mode=merge" or $arg eq "--mode=+" or $arg eq "--merge") { $mode = "+" }
      elsif ($arg =~ m@\A--mode=@) { die1 "$0: fatal: unknown flag value: $arg\n" }
      elsif ($arg =~ m@\A--prefix=(.*)@s) { $tagspec_prefix = "$1 " }
      elsif ($arg eq "--any-tag-ok") { $do_read_tags_file = 0 }
      else { die1 "$0: fatal: unknown flag: $arg\n" }
    }
    die1 "$0: fatal: too many command-line arguments\n" if $i != @ARGV;
    die1 "$0: fatal: expected --stdin-tagfile because of other flags\n" if $stdin_mode != 2;
    my $process_func = sub {
      my($filename, $tags, $default_mode) = @_;
      apply_tagspec($tagspec_prefix . $tags, ($mode or $default_mode), sub { [$filename] }, 1);
    };
    $known_tags = read_tags_file() if $do_read_tags_file;
    parse_dump(\*STDIN, $process_func);
  }
  print "error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
  print "kept tags of $KC file@{[$KC==1?q():q(s)]}\n" if $KC;
  print "$action tags of $C file@{[$C==1?q():q(s)]}: $tagspecmsg\n";
}

# --- _cmd_unify_tags : xattr

#** TODO(pts): Unify more than 2 files to prevent the needed for 2 runs on
#**            d.sh: modified 32, then 4, then 0 files.
sub _cmd_unify_tags {
  die1 "$0: makes both files have to union of tags
Usage: $0 <filename1> <filename2>
    or echo \"... \x27filename1\x27 ... \x27filename2\x27 ...\" ... | $0 --stdin
See above for the format of --stdin.
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
    die1 "$0: error: bad add-tags syntax: $tags\n" if $tags =~ /[+-]/;
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
      die1 "$0: error: tags both added and removed: @both_tags\n" if @both_tags;
      my $has_rmtag = grep { exists $rmtags{$_} } split(/\s+/, $tags1);
      if ($has_rmtag) {
        $tags1 = join(" ", grep { !exists $rmtags{$_} } split(/\s+/, $tags1));
      }
    }
    $tags1 =~ s@\A\s+@@;
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
    die1 "$0: fatal: supply filename pairs in STDIN (not a TTY)\n" if -t STDIN;
    while (<STDIN>) {
      die1 "$0: fatal: incomplete line in unify line: $_\n" if !chomp($_);
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

# --- _cmd_show : xattr

#** See docs for using this command from Midnight Commander (mc) menu.
sub _cmd_show {
  if (!@ARGV or $ARGV[0] eq "--help") {
    print STDERR "$0: shows tags the specified files have, interactively
Usage: $0 [<flag> ...] [<filename> ...]
Flags:
--abspath : Display absolute pathname of each matching file.
--tagquery=<tagquerym> : Print files with tags like this. Default: :any
--print-empty=yes | --any : Same as --tagquery=:any
--print-empty=no | --tagged : Same as --tagquery=:tagged
--untagged : Same as --tagquery=:none , prints files without tags.
--recursive=yes : Show contents of directories, recursively.
--recursive=no (default) : Show files only.
--recursive=one : Show contents of specified directories (not recursive).
--readdir : Legacy alias for --recursive=one
--stdin : Get filenames from stdin rather than command-line.
Supported <tagquerym> values: :any :tagged :none
It follows symlinks to files and to the top dir with --recursive=one.
";
    exit(!@ARGV);
  }
  my $print_mode = 0;
  my $recursive_mode = 0;
  my $do_show_abs_path = 0;
  my $stdin_mode = 0;
  my $i = 0;
  while ($i < @ARGV) {
    my $arg = $ARGV[$i++];
    if ($arg eq "-" or substr($arg, 0, 1) ne "-") { --$i; last }
    elsif ($arg eq "--") { last }
    elsif ($arg eq "--stdin") { $stdin_mode = 1 }
    elsif ($arg eq "--abspath") { $do_show_abs_path = 1 }
    elsif ($arg eq "--recursive=yes") { $recursive_mode = 2 }
    elsif ($arg eq "--recursive=no") { $recursive_mode = 0 }
    elsif ($arg eq "--recursive=one" or $arg eq "--readdir") { $recursive_mode = 1 }
    elsif ($arg =~ m@\A--recursive=@) { die1 "$0: fatal: unknown flag value: $arg\n" }
    elsif ($arg eq "--print-empty=yes" or $arg eq "--tagquery=:any" or $arg eq "--any") { $print_mode = 0 }
    elsif ($arg eq "--print-empty=no" or $arg eq "--tagquery=:tagged" or $arg eq "--tagquery=*" or $arg eq "--tagged") { $print_mode = 1 }
    elsif ($arg eq "--tagquery=:none" or $arg eq "--tagquery=-*" or $arg eq "--untagged") { $print_mode = -1 }
    elsif ($arg =~ m@\A--print-empty=@) { die1 "$0: fatal: unknown flag value: $arg\n" }
    elsif ($arg =~ m@\A--tagquery=@) { die1 "$0: fatal: unsupported flag value, use find instead: $arg\n" }
    else { die1 "$0: fatal: unknown flag: $arg\n" }
  }
  if ($stdin_mode) {
    die1 "$0: fatal: too many command-line arguments\n" if $i != @ARGV;
  } else {
    splice(@ARGV, 0, $i);
  }
  require Cwd if $do_show_abs_path;
  my $process_file = sub {  # ($)
    my($fn0, $no_symlink_to_file2) = @_;
    $fn0 =~ s@\A(?:[.]/)+@@;
    my $ignore_cond = (!lstat($fn0) or (-l(_) ? ($no_symlink_to_file2 or !-f($fn0)) : !-f(_)));
    if ($ignore_cond) {
      if ($ignore_cond <= 1) {  # Omit symlinks to files.
        my $msg = -e(_) ? "not a file" : "missing";
        print "  $fn0\n    error: $msg\n"; $EC++;
      }
      return;
    }
    my $fn = $fn0;
    if ($do_show_abs_path) {
      $fn = Cwd::abs_path($fn0);
      # This usually happens when $fn0 is a symlink pointing to a nonexisting
      # file.
      if (!defined $fn) {
        print "  $fn0\n    error: abs not found: $!\n"; $EC++; return
      }
    }
    my $tags = $xattr_api->{getxattr}->($fn0, $key0);
    if (!defined($tags) and !$!{$ENOATTR}) {
      print "  $fn\n    error: $!\n"; $EC++
    } else {
      $tags = "" if !defined($tags);
      # TODO(pts): Strip leading spaces, everywhere.
      my @tags = split/\s+/, $tags;
      $HC++ if @tags;
      $C++;
      if (!$print_mode or ($print_mode > 0 ? scalar(@tags) : !@tags)) {
        my @n_tags = grep { !/^v:/ } @tags;
        my @v_tags = grep { /^v:/  } @tags;
        @n_tags=(":none") if !@n_tags;
        print "  $fn\n    @n_tags\n";
        print "    @v_tags\n" if @v_tags;
      }
    }
  };
  my $process_dir; $process_dir = sub {  # ($).
    my $fn0 = $_[0];
    my $d;
    if (!opendir($d, $fn0)) {
      print "  $fn0\n    error: opendir: $!\n"; $EC++; return
    }
    # It doesn't follow symlinks to non-files. It follows symlinks to files
    # iff .nosymfile doesn't exist in the directory.
    my $no_symlink_to_file2 = -e("$fn0/.nosymfile") ? 2 : 0;
    for my $entry (sort(readdir($d))) {
      next if $entry eq "." or $entry eq "..";
      my $fn = "$fn0/$entry";
      (($recursive_mode == 2 and lstat($fn) and -d(_)) ?
          $process_dir : $process_file)->($fn, $no_symlink_to_file2);
    }
    die if !closedir($d);
  };
  my $process_xdir = sub {  # ($).
    my $fn0 = $_[0];
    ((($recursive_mode == 2 and lstat($fn0) and -d(_)) or
      ($recursive_mode == 1 and -d($fn0))) ?
     $process_dir : $process_file)->($fn0);
  };
  my $process_func = $recursive_mode ? $process_xdir : $process_file;  # For speed.
  if ($stdin_mode) {
    my $fn0;
    while (defined($fn0 = <STDIN>)) {
      die1 "$0: fatal: incomplete line in filename: $fn0\n" if !chomp($fn0);
      $process_xdir->($fn0);
    }
  } else {
    for my $fn0 (@ARGV) {
      $process_xdir->($fn0);
    }
  }
  print "error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
  print "shown tags of $HC of $C file@{[$C==1?q():q(s)]}\n";
}

# --- _cmd_get_tags : xattr

#** Like _cmd_show, but only one file, and without extras. Suitable for
#** scripting.
#** It works for weird filenames (containing e.g. " " or "\n"), too.
sub _cmd_get_tags {
  die1 "$0: displays tags a single file has
Usage: $0 <filename>\n" if @ARGV != 1;
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

# --- tagquery

my @VIDEO_EXTS = qw(avi wmv mpg mpe mpeg mov rm webm ram flv mp4 ts iso vob fli asf asx divx qt flc ogm mkv img vid m2ts original rmvb mp2 mpa m4v tp m1v m2v m3v tvt 3gp dv flv8 flv9);
my @IMAGE_EXTS = qw(png jpeg jpg jpe gif tif tiff pcx bmp xcf pnm pbm pgm ppm xwd xpm pam psd miff webp heif heifs heic heics avci avcs avif avifs mng apng ico jxr wdp hdp jp2 j2k jpf jpm jpg2 j2c jpc jpx mj2);
my @AUDIO_EXTS = qw(wav au mp3 mp2 ogg m4a opus flac aac ac3 dts ape vorbis speex ra mid midi mov s3m it xt sid ralf aiff aifc);
my %EXT_TERMS = (
    ':vid' => \@VIDEO_EXTS, ':video' => \@VIDEO_EXTS, ':film' => \@VIDEO_EXTS, ':movie' => \@VIDEO_EXTS,
    ':pic' => \@IMAGE_EXTS, ':picture' => \@IMAGE_EXTS, ':img' => \@IMAGE_EXTS, ':image' => \@IMAGE_EXTS, ':photo', => \@IMAGE_EXTS,
    ':aud' => \@AUDIO_EXTS, ':audio' => \@AUDIO_EXTS, ':snd' => \@AUDIO_EXTS, ':sound' => \@AUDIO_EXTS,
);

#** <tagquery> language:
#** * "foo bar | -baz" means ((foo AND bar) OR NOT baz).
#** * Special words: * -* and *-foo
#** * +foo -bar baz"  : anything with foo and baz, but without bar
#** * * -2004"        : anything with at least one tag, but without 2004
#** * *-foo *-bar"    : anything with at least one tag, which is not foo or bar
#** * -*"             : anything without tags
#** * See docs for more info.
#** @param $_[0] $tagquery String containing a <tagquery>.
#** @return \@orterms, a list of [$needplus, $needminus, $needother, $extplus, $extminus].
sub parse_tagquery($) {
  my $tagquery = $_[0];
  my @orterms;
  # TODO(pts): Build it faster if only positive tags ($tagv) + \s+ .
  die1 "$0: fatal: parentheses not supported in <tagquery>: $tagquery\n" if $tagquery =~ m@[()]@;
  die1 "$0: fatal: quotes not supported in <tagquery>: $tagquery\n" if $tagquery =~ m@[\x27"]@;
  my @termlists = split(/\|/, $tagquery);
  die1 "$0: fatal: empty <tagquery>\n" if !@termlists;
  my($has_tagged, $has_none) = (0, 0);
  for my $termlist (@termlists) {
    pos($termlist) = 0;
    my(%needplus, %needminus, %needother, $extmode, %extplus, %extminus);
    my $had_any = 0;
    my $update_exts = sub {
      my($exth, $tagv, $term) = @_;
      if (!ref($tagv)) {
        die1 "$0: fatal: invalid ext: term syntax: $term\n" if
            $tagv !~ m@\A(?:$tagchar_re|/)*\Z(?!\n)@o;
        $tagv = [split(m@/+@, lc($tagv))];
      }
      if ($exth == \%extplus and $extmode) {
        %extplus = map { (length($1) and exists($extplus{$1})) ? ($1 => 1) : () } @$tagv;  # Intersection.
      } else {
        $extmode = 1 if $exth == \%extplus;
        for my $ext (@$tagv) { $exth->{$ext} = 1 if length($ext) }  # Union.
      }
    };
    while ($termlist=~/(\S+)/g) {
      my $term = $1; my $tagv = $1;
      if ($tagv =~ s@^(-?)ext:@@) {
        $update_exts->($1 ? \%extminus : \%extplus, $tagv, $term); next
      } elsif ($tagv =~ s@^-@@) {
        $tagv = "*" if $tagv eq ":tag";
        my $exts = $EXT_TERMS{$tagv};
        if (defined($exts)) { $update_exts->(\%extminus, $exts, $term); next }
        $needminus{$tagv} = 1;
        next if $tagv eq "*";
      } elsif ($tagv =~ s@^[*]-@@) {
        $needother{$tagv} = 1;
        $needplus{"*"} = 1;
      } elsif ($tagv =~ m@^:@) {
        my $exts = $EXT_TERMS{$tagv};
        if (defined($exts)) {
          $update_exts->(\%extplus, $exts, $term); next
        } elsif ($tagv eq ":none") {
          $needminus{"*"} = 1; next
        } elsif ($tagv eq ":tagged" or $tagv eq ":tag") {
          $needplus{"*"} = 1; next
        } elsif ($tagv eq ":any") {
          # Specify :false (which does not match anything) as: * -*
          $had_any = 1; next
        }
      } else {
        $needplus{$tagv} = 1;
        next if $tagv eq "*";
      }
      if ($tagv !~ m@\A(?:v:)?(?:$tagchar_re)+\Z(?!\n)@o) {
        die1 "$0: fatal: invalid tagv ($tagv) in query term: $term\n";
      }
    }
    die1 "$0: fatal: empty termlist in <tagquery>: $termlist\n" if !($had_any or %needplus or %needminus or $extmode or %extminus);
    if (exists($needminus{"*"})) {
      next if %needplus;  # FYI %needother implies %needplus.
      %needminus = ("*" => 1);
    }
    next if grep { exists($needplus{$_}) } keys(%needminus);
    for my $tagv (keys(%needminus)) { delete $needother{$tagv} }
    %needother = () if %needother and (grep { $_ ne "*" and !exists($needother{$_}) } keys(%needplus));
    delete $needplus{"*"} if exists($needplus{"*"}) and scalar(keys(%needplus)) > 1 and !%needother;
    if (!%extplus and !%extminus) {
      $has_tagged = 1 if exists($needplus {"*"}) and scalar(keys(%needplus)) == 1 and !%needminus and !%needother;
      $has_none   = 1 if exists($needminus{"*"});
      $has_tagged = $has_none = 1 if !%needplus and !%needminus;
    }
    for my $ext (keys(%extminus)) { delete($extplus{$ext}) }
    next if $extmode and !%extplus;  # No possible extension.
    $extmode = %extplus ? 1 : %extminus ? -1 : 0;
    my $ext = %extplus ? \%extplus : \%extminus;
    #print STDERR "info: query spec needplus=(@{[sort(keys(%needplus))]}) needminus=(@{[sort(keys(%needminus))]}) needother=(@{[sort(keys(%needother))]}) extmode=$extmode ext=(@{[sort(keys(%$ext))]})\n";
    push @orterms, [\%needplus, \%needminus, \%needother, $extmode, $ext];
  }
  @orterms = ([$has_none ? {} : {"*" => 1}, {}, {}]) if $has_tagged;
  \@orterms
}

sub match_tagquery($$$) {
  my($tags, $filename, $orterms) = @_;
  my $ok_p = 0;
  my $fext;
  for my $orterm (@$orterms) {
    my($needplus, $needminus, $needother, $extmode, $ext) = @$orterm;
    my $is_nmstar = exists($needminus->{"*"});
    my %np = %$needplus;
    #print "($tags)\n";
    pos($tags) = 0;
    if (%$needother) {
      my $other_tagc = 0;
      while ($tags=~/([^\s,]+)/g) {
        my $tag = $1;
        if ($is_nmstar or exists($needminus->{$tag})) { %np = (1 => 1); last }  # Tag mismatch.
        $other_tagc++ if !exists($needother->{$tag});
        delete $np{$tag};
      }
      delete $np{"*"} if $other_tagc > 0;
    } elsif (%$needminus) {  # For speed.
      while ($tags=~/([^\s,]+)/g) {
        my $tag = $1;
        if ($is_nmstar or exists($needminus->{$tag})) { %np = (1 => 1); last }  # Tag mismatch.
        delete $np{$tag};
      }
      delete $np{"*"} if exists($np{"*"}) and $tags =~ m@[^\s,]@;
    } else {  # For speed.
      delete $np{$1} while $tags=~/([^\s,]+)/g;
      delete $np{"*"} if exists($np{"*"}) and $tags =~ m@[^\s,]@;
    }
    next if %np;  # Tag mismatch in current $orterm.
    return 1 if !$extmode;  # Found match in current $orterm.
    if (!defined($fext)) {
      $fext = "";
      my $i = rindex($filename, ".") + 1;
      if ($i) {
        pos($filename) = $i;
        $fext = lc($1) if $filename =~ m@\G([^./]+)\Z(?!\n)@gc;
      }
    }
    return 1 if ($extmode < 0) ^ exists($ext->{$fext});
  }
  0  # No match.
}

#** Returns Perl source code matching tags in $_ to $orterms (as returned by
#** parse_tagquery). Tries to do regexp matches (fast) rather than
#** match_tagquery (slow Perl code).
sub get_match_src($$) {
  my ($orterms, $is_fast) = @_;
  return q{ $_ = "" if !defined($_); if (match_tagquery($_, $fn0, $orterms)) { print "$fn0\\n"; ++$HC if m@[^\\s,]@; } } if !$is_fast;  # Unoptimized (with match_tagquery), counting.
  return q{} if !@$orterms;  # No file matches.
  my @orsrcs;
  if (!(grep { $_->[3] } @$orterms)) {  # All $extmode == 0 (no extensions specified).
    return q{ print "$fn0\\n" } if @$orterms == 1 and !%{$orterms->[0][0]} and !%{$orterms->[0][1]} and !%{$orterms->[0][2]};  # Any file matches.
    return q{ print "$fn0\\n" if  defined($_) and m@[^\\s,]@; } if @$orterms == 1 and exists($orterms->[0][0]{"*"}) and scalar(keys(%{$orterms->[0][0]})) == 1 and !%{$orterms->[0][1]} and !%{$orterms->[0][2]};  # Tagged   files match.
    return q{ print "$fn0\\n" if !defined($_) or !m@[^\\s,]@; } if @$orterms == 1 and exists($orterms->[0][1]{"*"}) and scalar(keys(%{$orterms->[0][1]})) == 1 and !%{$orterms->[0][0]} and !%{$orterms->[0][2]};  # Untagged files match.
    # Matching is slow if $tags ($_) and number of matched tags is long
    # (because of sequential rescans). If there are more than $count_limit
    # sequential scans, we fall back to match_tagquery, which is scans once
    # (but slowly). Benchmarks on files with typical (few) tags and 1 term to
    # match indicate that match_tagquery is ~3.307 times slower than fast
    # regexp matches.
    my($count, $count_limit) = (0, 5);
    for my $orterm (@$orterms) {
      my($needplus, $needminus, $needother) = @$orterm;
      if (%$needother) { @orsrcs = (); last }
      # Benchmarks indicate that it is a bit faster with \Q, and that using a
      # non-literal regexp (e.g. with `|`) would make it much slower.
      my @andsrcs = map({ $_ eq "*" ? "m([^,])" : "m(\\Q,$_,)" } sort(keys(%$needplus))),
          map({ $_ eq "*" ? "!m([^,])" : "!m(\\Q,$_,)" } sort(keys(%$needminus)));
      $count += @andsrcs;
      if ($count > $count_limit) { @orsrcs = (); last }
      push @orsrcs, join(" and ", @andsrcs);
    }
  }
  return q{ $_ = "" if !defined($_); print "$fn0\\n" if match_tagquery($_, $fn0, $orterms) } if !@orsrcs;  # Unoptimized (with match_tagquery), not counting.
  q{ $_ = "" if !defined($_); s@\s+@,@g; $_ = ",$_,"; print "$fn0\\n" if } . join(" or ", @orsrcs)  # Optimized.
}

# --- print_find_stats

sub print_find_stats($) {
  my $action = $_[0];
  # We print these messages to STDERR (rather than STDOUT starting with `# `),
  # because some tools do not support extra lines, e.g. `setfattr --restore
  # <tagfile>`, which restores based on
  # `_cmd_dump --format=getfattr ... > <tagfile>`
  # does not support comments starting with `# `.
  print STDERR "error: had error with $EC file@{[$EC==1?q():q(s)]}\n" if $EC;
  my $hcof = defined($HC) ? "$HC of " : "";
  print STDERR "info: $action tags of $hcof$C file@{[$C==1?q():q(s)]}\n";
}

# --- _cmd_grep : xattr tagquery print_find_stats

sub _cmd_grep {
  if (!@ARGV or $ARGV[0] eq "--help") {
    print STDERR "$0: keeps file names matching a tag query
Usage: $0 [<flag> ...] \x27<tagquery>\x27
Reads filenames from stdin, writes matching the <tagquery> to stdout.
Example: ls | _cmd_grep \"+foo -bar baz\"
Flags:
--stdin (default) : Get filenames from stdin rather than command-line.
--format=filename | --format=name (default) : Print filename only.
--tagquery=<tagquery> : Query to match file tags against.
--fast : Uses fast matching code, producing simplified stats.
  Replaces the <tagquery> argument.
";
    exit(!@ARGV);
  }
  my $tagquery;
  my $is_fast = 0;
  my $i = 0;
  while ($i < @ARGV) {
    my $arg = $ARGV[$i++];
    if ($arg eq "--") { last }
    elsif (substr($arg, 0, 2) ne "--") { --$i; last }
    elsif ($arg eq "--stdin") {}
    elsif ($arg eq "--fast") { $is_fast = 1 }
    elsif ($arg eq "--format=filename" or $arg eq "--format=name") {}
    elsif ($arg =~ m@\A--tagquery=(.*)@s) { $tagquery = $1 }
    else { die1 "$0: fatal: unknown flag: $arg\n" }
  }
  if (!defined($tagquery)) {
    die1 "$0: fatal: missing <tagquery> argument\n" if $i >= @ARGV;
    $tagquery = $ARGV[$i++];
  }
  die1 "$0: fatal: too many command-line arguments\n" if $i != @ARGV;
  my $orterms = parse_tagquery($tagquery);
  # printf STDERR "info: grep query: %s\n", @$orterms ? join(" | ", map { (!%{$_->[0]} and !%{$_->[1]}) ? ":any" : join(
  #     " ", sort(keys(%{$_->[0]})), map({ "-$_" } sort(keys(%{$_->[1]}))), map({ "*-$_" } sort(keys(%{$_->[2]}))))  } @$orterms) : ":false";
  my($getxattr, $key02, $ENOATTR2) = ($xattr_api->{getxattr}, $key0, $ENOATTR);
  local $_ = <<'  ENDMATCH';
    my $fn0;
    local $_;
    while (defined($fn0 = <STDIN>)) {
      die1 "$0: fatal: incomplete line in filename: $fn0\n" if !chomp($fn0);
      if (lstat($fn0) and (-l(_) ? -f($fn0) : -f(_))) {
        $_ = $getxattr->($fn0, $key02);  # $tags.
        if (!defined($_) and !$!{$ENOATTR2}) {
          print STDERR "error: $fn0: $!\n"; $EC++
        } else {
          <MATCH>
        }
      } else {
        my $msg = -e(_) ? "not a file" : "missing";
        print STDERR "error: $msg: $fn0\n"; $EC++;
      }
    }
    $C += $. - $EC;
  ENDMATCH
  # TODO(pts): Add a flag to allow optimizing away I/O (e.g. -f and getxattr) for :any and :false.
  my $cond;
  my $match_src = get_match_src($orterms, $is_fast);
  die1 "$0: assert: <MATCH> not found\n" if !s@<MATCH>@$match_src@g;
  eval; die $@ if $@;
  $HC = undef if $is_fast;
  print_find_stats("grepped");
}

# --- format_filename

my $format_filename = sub { "$_[1]\n" };  # $filename.

# --- get_format_func

sub fnq($) {
  #return $_[0] if substr($_[0],0,1)ne"-";
  return $_[0] if length($_[0]) and $_[0] !~ m@[^-_/.0-9a-zA-Z]@;
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

my %REPR_STR = ("\t" => "\\t", "\n" => "\\n", "\r" => "\\r", "\\" => "\\\\", "\"" => "\\\"", "'" => "\\'");

#** Escapes a string just like Python 2.7 repr.
sub reprq($) {
  my $s = $_[0];
  my $has_sq = $s =~ y@'@@;
  my $has_dq = $s =~ y@"@@;
  if ($has_sq and !$has_dq) {
    $s =~ s@([\x00-\x1F\x7F-\xFF\\\"])@ $REPR_STR{$1} or sprintf("\\x%02x", ord($1)) @ge;
    qq("$s")
  } else {
    $s =~ s@([\x00-\x1F\x7F-\xFF\\\'])@ $REPR_STR{$1} or sprintf("\\x%02x", ord($1)) @ge;
    qq('$s')
  }
}

my %tagvs_encountered;

#** @returns $format_func taking ->($tags, $fn0).
sub get_format_func($;$) {
  my($format, $is_fatal) = @_;
  (!defined($format) or $format eq "sh" or $format eq "setfattr") ? sub {
    my($tags, $filename) = @_;
    length($tags) ?
        "setfattr -n $key0 -v " . fnq($tags) . " -- " . fnq($filename) . "\n" :
        "setfattr -x $key0 -- " . fnq($filename) . "\n"
  } : ($format eq "xattr") ? sub {
    my($tags, $filename) = @_;
    length($tags) ?
        "xattr -w $key0 " . fnq($tags) . " " . fnq($filename) . "\n" :
        "xattr -d $key0 " . fnq($filename) . "\n"
  } : ($format eq "colon") ? sub {
    my($tags, $filename) = @_;
    "$tags :: $filename\n"
  } : ($format eq "tags" or $format eq "tagvs") ? sub {
    my($tags, $filename) = @_;
    my $result = "";
    while ($tags=~/([^\s,]+)/g) {
      my $tagv = $1;
      if (!exists($tagvs_encountered{$tagv})) {
        $tagvs_encountered{$tagv} = 1;
        $result .= "$tagv\n";
      }
    }
    $result
  } : ($format eq "filename" or $format eq "name") ? $format_filename :
  ($format eq "getfattr") ? sub {
    my($tags, $filename) = @_;
    # getfattr always omits files without tags (i.e. without the
    # $key0 extended attribute). Use _cmd_dump --print-empty=no
    # to get this behavior.
    "# file: $filename\n$key0=" . gfaq($tags). "\n\n"
  } : ($format eq "mfi" or $format eq "mediafileinfo" or $format eq "mscan") ? sub {
    my($tags, $filename) = @_;
    my $tagsc = $tags;
    $tagsc =~ s@[\s,]+@,@g;
    $tagsc =~ s@%@%25@g;
    $tagsc =~ s@\A,+@@; $tagsc =~ s@,+\Z(?!\n)@@;
    my @st = stat($filename);  # TODO(pts): Don't call this on --stdin-tagfile except if mfi format.
    @st ? "format=?-no-try mtime=$st[9] size=$st[7] tags=$tagsc f=$filename\n"
        : "format=?-no-try tags=$tagsc f=$filename\n"
  } : ($format eq "mclist") ? sub {  # Ignores tags.
    my($tags, $filename) = @_;
    my @st = stat($filename);  # TODO(pts): Don't call this on --stdin-tagfile except if mfi format.
    my($mtime, $size, $nlink) = @st ? ($st[9], $st[7], $st[3]) : (undef, "?", "?");
    my $basename = $filename; $basename =~ s@\A.*/@@;
    my($sec, $min, $hour, $mday, $mon, $year) = localtime($mtime or 0);
    $year += 1900; ++$mon;
    sprintf("lrwxrwxrwx %s root root %s %02d/%02d/%d %02d:%02d:%02d %s -> %s\n",
            $nlink, $size, $mon, $mday, $year, $hour, $min, $sec, $basename, $filename)
  } : ($format eq "tuple") ? sub {
    my($tags, $filename) = (reprq($_[0]), reprq($_[1]));
    "($filename, $tags)\n"
  } : $is_fatal ? die1("$0: fatal: unknown output format: $format\n") : undef
}

my $format_usage =
"--format=sh (default) : Print a series of setfattr commands.
--format=xattr : Print a series of xattr commands.
--format=colon : Print in the colon format: <tags> :: <filename>
--format=getfattr : Print the same output as: getfattr -e text
--format=mfi : Print in the mediafileinfo format.
--format=filename | --format=name : Print filename only.
--format=tags : Print tags (including v:...) encountered (deduplicated).
--format=tuple : Print (filename, tags) Python tuple.
--format=mclist : Print Midnight Commander extfs file listing.";

# --- find_matches : format_filename

#** @param $_[1] $match_func taking ->($tags, $fn0), returning bool.
sub find_matches($$$$$) {
  my($format_func, $match_func, $printfn, $is_recursive, $is_stdin) = @_;
  if ($match_func == 1) {
    if ($format_func == $format_filename) {
      $HC = undef;  # Affects print_find_stats.
    } else {
      $match_func = sub { 1 };
    }
  }
  $is_recursive = $is_stdin ? 0 : 1 if !defined($is_recursive);
  my $process_file = sub {  # ($$).
    my($fn0, $no_symlink_to_file2) = @_;
    my $ignore_cond = (!lstat($fn0) or (-l(_) ? ($no_symlink_to_file2 or !-f($fn0)) : !-f(_)));
    #print "  $fn0\n";
    if ($ignore_cond) {
      if ($ignore_cond <= 1) {  # Omit symlinks to files.
        my $msg = -e(_) ? "not a file" : "missing";
        print STDERR "error: $msg: $fn0\n"; $EC++;
      }
      return;
    }
    if ($fn0 =~ y@\n@@) {
      print STDERR "error: newline in filename: " . fnq($fn0) . "\n"; $EC++; return
    }
    if ($match_func == 1) {
      ++$C;
      $fn0 = $printfn if defined($printfn);
      print "$fn0\n";
      return
    }
    my $tags = $xattr_api->{getxattr}->($fn0, $key0);
    if (!defined($tags) and !$!{$ENOATTR}) {
      print STDERR "error: $fn0: $!\n"; $EC++; return
    }
    $tags = "" if !defined($tags);
    ++$C;
    if ($match_func->($tags, $fn0)) {
      $tags =~ s@[\s,]+@ @g;  # E.g. get rid of newlines for --format=colon.
      $tags =~ s@\A +@@; $tags =~ s@ +\Z(?!\n)@@;
      ++$HC if length($tags);
      print $format_func->($tags, defined($printfn) ? $printfn : $fn0);
    }
  };
  my $process_dir; $process_dir = sub {  # ($).
    my $fn0 = $_[0];
    my $d;
    if (!opendir($d, $fn0)) {
      print STDERR "error: opendir: $fn0: $!\n"; $EC++; return
    }
    # It doesn't follow symlinks to non-files. It follows symlinks to files
    # iff .nosymfile doesn't exist in the directory.
    my $no_symlink_to_file2 = -e("$fn0/.nosymfile") ? 2 : 0;
    for my $entry (sort(readdir($d))) {
      next if $entry eq "." or $entry eq "..";
      my $fn = "$fn0/$entry";
      ((lstat($fn) and -d(_)) ?
          $process_dir : $process_file)->($fn, $no_symlink_to_file2);
    }
  };
  my $process_xdir; $process_xdir = sub {  # ($).
    my $fn0 = $_[0];
    ((lstat($fn0) and -d(_)) ? $process_dir : $process_file)->($fn0);
  };
  my $process_func = $is_recursive ? $process_xdir : $process_file;
  if ($is_stdin) {
    my $f;
    my $fn0;
    while (defined($fn0 = <STDIN>)) {
      die1 "$0: fatal: incomplete line in filename: $fn0\n" if !chomp($fn0);
      $process_func->($fn0);
    }
  } else {
    for my $fn0 (@ARGV) {
      $process_func->($fn0);
    }
  }
}

sub print_all_lines() {
  $HC = undef;
  local $_;
  while (<STDIN>) {
    die1 "$0: fatal: incomplete line in filename: $_\n" if !chomp($_);
    ++$C;
    $_ .= "\n" if substr($_, -1) ne "\n";
    print;
  }
}

# --- _cmd_dump : xattr get_format_func find_matches print_find_stats

#** Example: _copyattr() { _cmd_dump --printfn="$2" -- "$1"; }; duprm.pl . | perl -ne "print if s@^rm -f @_copyattr @ and s@ #, keep @ @" >_d.sh; source _d.sh | sh
sub _cmd_dump {
  if (!@ARGV or $ARGV[0] eq "--help") {
    print STDERR "$0: dumps tags on files to stdout
Usage: $0 [<flag> ...] <filename> [...] > <tagfile>
Flags:
--printfn=<filename> : In the output, print the specified filename instead.
--tagquery=<tagquerym> : Print files with tags like this. Default: :any
--print-empty=yes | --any : Same as --tagquery=:any
--print-empty=no | --tagged : Same as --tagquery=:tagged
--untagged : Same as --tagquery=:none , prints files without tags.
--stdin : Get filenames from stdin rather than command-line.
$format_usage
--recursive=yes (default w/o --stdin) : Dump directories, recursively.
--recursive=no : Dump files only.
Supported <tagquerym> values: :any :tagged :none
To apply tags in <tagfile> printed by $0 (multiple --format=...), run:
  $0 tag --stdin --mode=change < <tagfile>
It follows symlinks to files only.
";
    exit(!@ARGV);
  }
  my($printfn);
  my $format_func;
  my $match_func = 1;
  my $is_stdin = 0;
  my $is_recursive;
  my $i = 0;
  while ($i < @ARGV) {
    my $arg = $ARGV[$i++];
    if ($arg eq "-" or substr($arg, 0, 1) ne "-") { --$i; last }
    elsif ($arg eq "--") { last }
    elsif ($arg eq "--stdin") { $is_stdin = 1 }
    elsif ($arg eq "--sh" or $arg eq "--colon" or $arg eq "--mfi" or $arg eq "--mscan") { $format_func = get_format_func(substr($arg, 2), 1) }
    elsif ($arg =~ m@\A--format=(.*)@s) { $format_func = get_format_func($1, 1) }
    elsif ($arg eq "--print-empty=yes" or $arg eq "--tagquery=:any" or $arg eq "--any") { $match_func = 1 }
    elsif ($arg eq "--print-empty=no" or $arg eq "--tagquery=:tagged" or $arg eq "--tagquery=*" or $arg eq "--tagged") { $match_func = sub { my $tags = $_[0]; $tags =~ m@[^\s,]@ } }
    elsif ($arg eq "--tagquery=:none" or $arg eq "--tagquery=-*" or $arg eq "--untagged") { $match_func = sub { my $tags = $_[0]; $tags !~ m@[^\s,]@ } }
    elsif ($arg =~ m@\A--print-empty=@) { die1 "$0: fatal: unknown flag value: $arg\n" }
    elsif ($arg =~ m@\A--tagquery=@) { die1 "$0: fatal: unsupported flag value, use find instead: $arg\n" }
    elsif ($arg eq "--recursive=yes") { $is_recursive = 1 }
    elsif ($arg eq "--recursive=no") { $is_recursive = 0 }
    elsif ($arg =~ m@\A--recursive=@) { die1 "$0: fatal: unknown flag value: $arg\n" }
    elsif ($arg =~ m@\A--printfn=(.*)@s) { $printfn = $1 }
    else { die1 "$0: fatal: unknown flag: $arg\n" }
  }
  if ($is_stdin) {
    die1 "$0: fatal: too many command-line arguments\n" if $i != @ARGV;
  } else {
    splice(@ARGV, 0, $i);
  }
  $format_func = get_format_func($format_func, 1) if !ref($format_func);
  if ($is_stdin and $match_func == 1 and $format_func == $format_filename and !defined($printfn)) {
    print_all_lines();
  } else {
    # TODO(pts): Use fast matching if --fast, with or without --stdin.
    find_matches($format_func, $match_func, $printfn, $is_recursive, $is_stdin);
  }
  print_find_stats("dumped");
}

# --- _cmd_find : xattr get_format_func find_matches parse_dump tagquery print_find_stats

#** @returns $match_func, takes ->($tags, $fn0), returning bool.
sub tagquery_to_match_func($) {
  my $tagquery = $_[0];
  my $match_func = $tagquery eq ":any" ? 1 :
      ($tagquery eq ":tagged" or $tagquery eq "*") ? sub { my $tags = $_[0]; $tags =~ m@[^\s,]@ } :
      ($tagquery eq ":none" or $tagquery eq "-*") ? sub { my $tags = $_[0]; $tags !~ m@[^\s,]@ } :
      undef;
  if (!defined($match_func)) {
    my $orterms = parse_tagquery($tagquery);
    $match_func = sub { match_tagquery($_[0], $_[1], $orterms) };  # ($tags, $filename, $orterms).
  }
  $match_func
}

my $format_usage_for_find = $format_usage;
$format_usage_for_find =~ s@\Q (default) @ @g;
die1 "$0: assert: missing format default\n" if
    $format_usage_for_find !~ s@(\n--format=filename.*?) : @$1 (default) : @;

sub _cmd_find {
  if (!@ARGV or $ARGV[0] eq "--help") {
    print STDERR "$0: finds matching files, prints list or dump to stdout
Usage: $0 [<flag> ...] [\x27<tagquery>\x27] [<filename> ...]
Flags:
--printfn=<filename> : In the output, print the specified filename instead.
--tagquery=<tagquery> : Print files with matching tags.
--print-empty=yes | --any : Same as --tagquery=:any
--print-empty=no | --tagged : Same as --tagquery=:tagged
--untagged : Same as --tagquery=:none , prints files without tags.
--stdin : Get filenames from stdin rather than command-line.
--stdin-tagfile : Read <tagfile> from stdin.
$format_usage_for_find
--recursive=yes (default w/o --stdin) : Dump directories, recursively.
--recursive=no : Dump files only.
<tagquery> arg must be present iff --tagquery=... (or equivalent) is missing.
The find command is a generalization of grep and dump.
The grep <tagquery> command is equivalent to: find --stdin <tagquery>
The dump ... command is equivalent to: find --format=filename --any ...
It supports more --tagquery=... values and --stdin-tagfile.
It follows symlinks to files only.
";
    exit(!@ARGV);
  }
  my($printfn);
  my $format_func;
  my $match_func;
  my $stdin_mode = 0;
  my $is_recursive;
  my $i = 0;
  while ($i < @ARGV) {
    my $arg = $ARGV[$i++];
    if ($arg eq "--") { last }
    elsif (substr($arg, 0, 2) ne "--") { --$i; last }
    elsif ($arg eq "--stdin") { $stdin_mode = 1 }
    elsif ($arg eq "--stdin-tagfile" or $arg eq "--stdin-dump") { $stdin_mode = 2 }
    elsif ($arg eq "--sh" or $arg eq "--colon" or $arg eq "--mfi" or $arg eq "--mscan") { $format_func = get_format_func(substr($arg, 2), 1) }
    elsif ($arg =~ m@\A--format=(.*)@s) { $format_func = get_format_func($1, 1) }
    elsif ($arg eq "--print-empty=yes" or $arg eq "--any") { $match_func = 1 }
    elsif ($arg eq "--print-empty=no" or $arg eq "--tagged") { $match_func = tagquery_to_match_func(":tagged") }
    elsif ($arg eq "--untagged") { $match_func = tagquery_to_match_func(":none") }
    elsif ($arg =~ m@\A--print-empty=@) { die1 "$0: fatal: unknown flag value: $arg\n" }
    elsif ($arg =~ m@\A--tagquery=(.*)@s) { $match_func = tagquery_to_match_func($1); }
    elsif ($arg eq "--recursive=yes") { $is_recursive = 1 }
    elsif ($arg eq "--recursive=no") { $is_recursive = 0 }
    elsif ($arg =~ m@\A--recursive=@) { die1 "$0: fatal: unknown flag value: $arg\n" }
    elsif ($arg =~ m@\A--printfn=(.*)@s) { $printfn = $1 }
    else { die1 "$0: fatal: unknown flag: $arg\n" }
  }
  if (!defined($match_func)) {
    die1 "$0: fatal: missing <tagquery> argument\n" if $i >= @ARGV;
    $match_func = tagquery_to_match_func($ARGV[$i++]);
  }
  if ($stdin_mode) {
    die1 "$0: fatal: too many command-line arguments\n" if $i != @ARGV;
  } else {
    splice(@ARGV, 0, $i);
  }
  die1 "$0: fatal: incompatible flags: --stdin-tagfile and --recursive=yes\n" if
      $stdin_mode == 2 and $is_recursive;
  $format_func = get_format_func(($format_func or "filename"), 1) if !ref($format_func);
  if ($stdin_mode == 2) {
    my $process_func;
    if ($match_func == 1) {
      if ($format_func == $format_filename and !defined($printfn)) {
        $HC = undef;  # Affects print_find_stats.
        $process_func = sub {  # ($$$).
          my $fn0 = $_[0];
          ++$C;
          print "$fn0\n";
        }
      } else {
        $match_func = sub { 1 };
      }
    }
    # TODO(pts): Speed it up for --format=mfi input and single-tag matching.
    $process_func = sub {  # ($$$).
      my($fn0, $tags, $default_mode) = @_;
      # The following code is duplicate from find_matches.
      ++$C;
      if ($match_func->($tags, $fn0)) {
        $tags =~ s@[\s,]+@ @g;  # E.g. get rid of newlines for --format=colon.
        $tags =~ s@\A +@@; $tags =~ s@ +\Z(?!\n)@@;
        ++$HC if length($tags);
        print $format_func->($tags, defined($printfn) ? $printfn : $fn0);
      }
    } if !defined($process_func);
    parse_dump(\*STDIN, $process_func);
  } elsif ($stdin_mode == 1 and $match_func == 1 and $format_func == $format_filename and !defined($printfn)) {
    print_all_lines();
  } else {
    # TODO(pts): Use fast matching with get_match_src if --fast, with or
    #            without --stdin or --stdin-tagfile. Restrict
    #            --stdin-tagfile to an autodetected single format.
    find_matches($format_func, $match_func, $printfn, $is_recursive, $stdin_mode);
  }
  print_find_stats("found");
}

# --- _cmd_fixprincipal

#** Usage: _cmd_fixprincipal file1 file2 ...
sub _cmd_fixprincipal# Hide from <command> list.
{
  die1 "$0: fatal: not supported with ppfiletagger\n";
}

# --- _cmd_expand_tag : read_tags_file

#** @example _cmd_expand_tag ta
sub _cmd_expand_tag {
  if (!@ARGV or $ARGV[0] eq "--help") {
    print STDERR "$0: displays tags with the specified prefix
Usage: $0 <tagprefix> [<limit>]
The default limit is 10.
";
    exit(!@ARGV);
  }
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

# --- exec_prog

sub exec_prog($;$) {
  my $do_maybe = $_[1];
  prepend_path_to_argv0();
  local $_ = $argv0;
  die1 "$0: fatal: program directory not found in: $_\n" if !s@/+[^/]+\Z(?!\n)@/$_[0]@;
  if (!(-f($_) and -x($_))) {
    die1 "$0: fatal: program not found: $_\n" if !$do_maybe;
  } elsif (!exec($_, @ARGV)) {
    print STDERR "$0: fatal: exec $_: $!\n";
    exit(125);
  }
}

# --- _cmd_rmtimequery : exec_prog

sub _cmd_rmtimequery# Hide from <command> list.
{
  exec_prog("rmtimequery");
}

# --- _cmd_query : exec_prog

sub _cmd_query {
  exec_prog("rmtimequery", 1) if $topcmd eq "_mmfs";
  if (!@ARGV or $ARGV[0] eq "--help") {
    print STDERR "$0: searches in the index, prints matching files to stdout
Usage: $0 [<flag> ...] [\x27<tagquery>\x27] [<filename> ...]
Flags:
It is currently unimplemented.
It reports an error when searching for files without tags.
It follows symlinks to files only.
Without a <filename>, it searches indexes on all filesystems.
";
    exit(!@ARGV);
  }
  die1 "$0: fatal: command not implemented\n";
}

# --- _cmd_rmtimescan : exec_prog

sub _cmd_rmtimescan# Hide from <command> list.
{
  exec_prog("rmtimescan");
}

# --- _cmd_scan : exec_prog

sub _cmd_scan {
  exec_prog("rmtimescan", 1) if $topcmd eq "_mmfs";
  if (!@ARGV or $ARGV[0] eq "--help") {
    print STDERR "$0: scans all filesystems and updates search indexes
Usage: $0 [<flag> ...] [<index-directory> ...]
Flags:
It is currently unimplemented.
It follows symlinks to files only.
Without an <index-directory>, it updates indexes on all filesystems.
";
    exit(!@ARGV);
  }
  die1 "$0: fatal: command not implemented\n";
}

# --- end
END

sub die1($) {
  print STDERR $_[0];
  exit(1);
}

if (@ARGV and $ARGV[0] eq "--sa") {
  eval <<'  ENDSA'; die $@ if $@;
  shift(@ARGV);
  local $_ = ""; while (read(STDIN, $_, 65536, length)) {}
  if (m@\A(:\0\n)@) {
    pos($_) = length($1);
    push @ARGV, $1 while m@\G([^\0]+)\0\n@gc;
  } else {
    die1 "$0: fatal: missing stdin-ARGV ($_)\n" if !m@\A(.*? : -)[ \n]@;
    die1 "$0: fatal: bad stdin-ARGV ending\n" if !chomp();
    $_ .= " " if substr($_, -1) ne " ";  # Appended by Midnight commander.
    pos($_) = length($1);
    # Unescape escaped @ARGV:
    # * Bourne shell `set -x' escapes by '...' and ' -> '\'' .
    # * Midnight Commander escapes by prepending backslashes and also prepending
    #   ./ if the argument starts with -.
    while (m@\G(?:\ \Z(?!\n)|\ \x27((?:[^\x27]+|\x27\\\x27\x27)*)\x27
             (\\\x27(?=\ ))?|\ ((?:[^\x27"\$\\\ \n]+|\\[^\n])+)(?=\ ))@gcx) {
      if (defined($1)) { push @ARGV, $1; $ARGV[-1] =~ s@\x27\\\x27\x27@\x27@g;
        $ARGV[-1] .= $2 if defined($2) }
      elsif (defined($3)) { push @ARGV, $3; $ARGV[-1] =~ s@\\(.)@$1@sg; }
    }
  }
  die1 "$0: fatal: bad stdin-ARGV\n" if pos($_) != length($_);
  if (open(my($fd9), "<&=9")) { open(STDIN, "<&9"); close($fd9) }
  #for (@ARGV) { print "($_)\n" }
  ENDSA
}
if (@ARGV and $ARGV[0] eq "--mcmenu") {
  eval <<'  ENDMCMENU'; die $@ if $@;
  shift(@ARGV);
  my $pid = fork();  # Use fork to catch fatal signals etc.
  die1 "$0: fatal: fork(): $!\n" if !defined($pid);
  if ($pid) {  # Parent.
    die1 "fatal: waitpid(): !\n" if $pid != waitpid($pid, 0);
    my $exit_code = ($? & 255) | ($? >> 8);
    print STDERR "\007see error $exit_code above\n" if $exit_code;
    { my $f = select(STDERR); $| = 1; select($f); }
    print STDERR "Press <Enter> to return to mc.";  # No trailing \n.
    <STDIN>;
    exit($exit_code);
  }
  ENDMCMENU
}
if (@ARGV and $ARGV[0] =~ s@\A--cd=@@) {
  my $dir = shift(@ARGV);
  die1 "$0: fatal: chdir: $dir: $!\n" if !chdir($dir);
}

my %parts;
my @partps;
while (m@\n# ---([ \t]*(\w+)(?: :[ \t]*([\w \t]*)|[ \t]*)(?=\n))?@g) {
  die1 "$0: assert: bad part separator\n" if !defined($1);
  my $part = $2;
  push @partps, $part, pos($_) - length($1) - 6;
  my @deps = split(/\s+/, defined($3) ? $3 : "");
  die1 "$0: assert: duplicate part: $part\n" if exists($parts{$part});
  $parts{$part} = \@deps;
}
# This would include hidden commands (e.g. fixprincipal).
# my @cmds = map { m@^_cmd_(.*)@ and $1  ? ($1) : () } keys(%parts);
my @cmds;
while (m@\nsub[ \t]+(_cmd_(\w+))[ \t({]@g) { push @cmds, $2 if exists($parts{$1}) }

my $argv0 = $0;
my $topcmd = (@ARGV and $ARGV[0] =~ s@\A--0=@@) ? shift(@ARGV) : undef;
if (!defined($topcmd)) {
  $topcmd = $0;
  $topcmd =~ s@\A.*/@@;
  $topcmd =~ s@[.][^.]+\Z(?!\n)@@;
  $topcmd =~ s@_shell_functions\Z(?!\n)@@;
  $topcmd =~ s@\W@_@g;  # - is not allowed in shell function name.
  $topcmd = "lfo" if !length($topcmd) or $topcmd eq "locfileorg";
  $topcmd = "_mmfs" if $topcmd eq "ppfiletagger" or $topcmd eq "mmfs";  # Legacy.
}
my $argv0e = $ENV{"_${topcmd}_ARGV0"};  # Set by --load.
$argv0 = $argv0e if defined($argv0e) and length($argv0e);

sub exit_usage() {
  print STDERR "$0: file tagging and search-by-tag tool\n" .
      "Usage: ${topcmd} <command> [<arg> ...]\n" .
      "Supported <command>s: @cmds\n";
  exit(!@ARGV);
}

sub prepend_path_to_argv0() {
  if ($argv0 !~ m@/@) {
    for my $dir (split(m@:@, exists($ENV{PATH}) ? $ENV{PATH} : "/bin:/usr/bin")) {
      if (length($dir) and -f("$dir/$argv0")) { $argv0 = "$dir/$argv0"; last }
    }
    die1 "$0: fatal: program not found on \$PATH: $_\n" if $argv0 !~ m@/@;
  }
}

if (@ARGV == 1 and $ARGV[0] eq "--load") {
  eval <<'  ENDLOAD'; die $@ if $@;
  die1 "$0: fatal: open script: $!\n" if !open(my($f), "<", $0);
  $_ = join("", <$f>);
  die if !close($f);
  die1 "$0: fatal: #!perl not found in script\n" if !m@\n#!perl(?: .*)?\n@g;
  substr($_, 0, pos($_)) = ""; pos($_) = 0;
  die1 "$0: fatal: __END__ not found in script\n" if !m@\n__END__\n@g;
  substr($_, pos($_)) = "";
  s@'@'\\''@g;
  $topcmd =~ s@\W@_@g;  # - is not allowed in shell function name.
  # TODO(pts): Add bash and zsh completion in addition to these functions.
  my $funcs = join("", map { "${topcmd}_$_() { ${topcmd} $_ \"\$@\"; }\n" } @cmds);
  # Unlimited argv support (using set -x) works in bash, zsh, ksh, pdksh, lksh,
  # mksh and busybox sh (since about 1.17.3 in 2010) and dash.
  prepend_path_to_argv0();
  if ($argv0 !~ m@\A/@) {
    eval {
      require Cwd;
      my $cwd = Cwd::getcwd();
      if (defined($cwd) and length($cwd)) {
        $argv0 =~ s@\A(?:[.]/+)+@@;
        $argv0 = "$cwd/$argv0";
      }
    };
  }
  my $argv0q = $argv0; $argv0 =~ s@'@'\\''@g;
  my $xq = $^X; $xq =~ s@'@'\\''@g;
  print "unset _${topcmd}_ARGV0; _${topcmd}_ARGV0='$argv0q'\n".
      "unset _${topcmd}_PERLCODE; _${topcmd}_PERLCODE='\$0=\"$topcmd\";$_'\n".qq(
case "\$(exec 2>&1; set -x; : "a b")" in  # Detect unlimited argv support.
*" : 'a b'"\) ${topcmd}() {  # Avoid E2BIG by passing long argv on stdin.
  (exec 9>&0; (exec 2>&1; set -x; : - "\$\@") |
  (export _${topcmd}_PERLCODE; export _${topcmd}_ARGV0; exec perl -e 'eval\$ENV{_${topcmd}_PERLCODE};die\$\@if\$\@' -- --sa))
} ;;
*\) case "\$(exec 2>&1; printf %s\\\\000\\\\ny "a  b" | '$xq' -pe 'y~\\0~x~')" in
"a  bx
y"*\) ${topcmd}() {  # Terminating long args with NUL NL. For dash.
  (exec 9>&0; for A in : "\$@"; do printf %s\\\\000\\\\n "\$A"; done |
  (export _${topcmd}_PERLCODE; export _${topcmd}_ARGV0; exec perl -e 'eval\$ENV{_${topcmd}_PERLCODE};die\$\@if\$\@' -- --sa))
} ;;
*\) ${topcmd}() {  # Fallback with size-limited argv (E2BIG).
  (export _${topcmd}_PERLCODE; export _${topcmd}_ARGV0; exec perl -e 'eval\$ENV{_${topcmd}_PERLCODE};die\$\@if\$\@' -- "\$\@")
} ;;
esac ;;
esac\n$funcs);
  exit;
  ENDLOAD
}
$0 = $topcmd;

if (!@ARGV or $ARGV[0] eq "--help") {
  if ($topcmd eq "_mmfs") {
    prepend_path_to_argv0();
    my $progdir = $argv0;
    if ($progdir =~ s@/+[^/]+\Z(?!\n)@/@) {
      for my $cmd (qw(rmtimequery rmtimescan)) {
        $_ = $progdir . $cmd;
        push @cmds, $cmd if -f and -x;
      }
    }
  }
  exit_usage();
}

my $cmd = shift(@ARGV);
if ($cmd eq "help") {
  exit_usage() if !@ARGV;
  if (@ARGV == 1) { $cmd = shift(@ARGV); push @ARGV, "--help" }
}
{
  my $cmdp = "_cmd_$cmd";
  die1 "$0: fatal: no $0 <command>: $cmd\n" if !exists($parts{$cmdp});
  my %done;
  my @todo = ($cmdp);
  for my $part (@todo) {  # Figure out which parts are used.
    if (!exists($done{$part})) {
      $done{$part} = 1;
      for my $part2 (@{$parts{$part}}) {
        die1 "$0: assert: missing dep: $part2\n" if !exists($parts{$part2});
        push @todo, $part2;
      }
    }
  }
  my @src = (substr($_, 0, $partps[1]));
  for (my $i = 2; $i < @partps; $i += 2) {  # Prepare only used code parts.
    my($part, $pos, $endpos) = ($partps[$i - 2], $partps[$i - 1], $partps[$i + 1]);
    my $partsrc = substr($_, $pos, $endpos - $pos);
    $partsrc =~ y@\n@@cd if !exists($done{$part});
    push @src, $partsrc;
  }
  $_ = join("", @src);
}
eval; die $@ if $@;  # Delayed and partial parsing of actual Perl code.
my $func; { no strict qw(vars); $func = \&{__PACKAGE__ . "::_cmd_$cmd" } }
if (!defined(&$func)) {
  print STDERR "$0: assert: no command func: $cmd\n";
  exit(1);
}
$0 .= " $cmd";
$func->(@ARGV);
exit 1 if $EC;

__END__
