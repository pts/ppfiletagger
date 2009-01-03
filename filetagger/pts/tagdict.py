#! /usr/bin/python2.4
#
# Python module pts.tagstore
# by pts@fazekas.hu at Sun Aug 31 16:39:33 CEST 2008
#

import re
import sys

empty_list = []

def select_true(alist):
  return [item for item in alist if item]

WHITESPACE_RE = re.compile(r'\s+')

WHITESPACE_OR_BAR_RE = re.compile(r'[\s|]+')

PTAG_RE = re.compile(r'\A[a-zA-Z0-9_]+:[a-zA-Z0-9_]+\Z')
"""A regexp matching username:tagname.

There is a good reason why we don't allow internationalized (e.g. UTF-8,
Unicode) characters here: some TagStore()s, such as SQLite cannot implement
case insensitive match on Unicode.
"""

XTAG_RE = re.compile(r'\A(?:[a-zA-Z0-9_]+:)?[a-zA-Z0-9_]+\Z')

def split_utagtext(utagtext):
  """Split a opaquetext string.

  Args:
    opaquetext: whitespace-separated u:tag and -u:tag strings
  Return:
    Pair of sorted, unique lists of +-u:tag strings: (positives, netgatives).
  """
  positives = set()
  negatives = set()
  for utag in re.split(WHITESPACE_RE, utagtext):
    if not utag: continue
    if utag[0] == '-':
      ptag = utag[1:]
    else:
      ptag = utag
    if not re.match(PTAG_RE, ptag): raise ValueError, "bad ptag: %r" % ptag
    if utag[0] == '-':
      if utag in positives: raise ValueError, "utag in both: %r" % utag
      negatives.add(utag)
    else:
      if utag in negatives: raise ValueError, "utag in both: %r" % utag
      positives.add(utag)
  return (sorted(positives), sorted(negatives))

def split_xtagspec(xtagspec):
  """Split an xtagspec string.

  Args:
    opaquetext: whitespace-separated +-u:tag strings
  Return:
    Pair of sorted, unique lists of +-u:tag strings: (positives, netgatives).
  """
  positives = set()
  negatives = set()
  for utag in re.split(WHITESPACE_RE, xtagspec):
    if not utag: continue
    if utag[0] == '-':
      ptag = utag[1:]
    else:
      ptag = utag
    if not re.match(XTAG_RE, ptag): raise ValueError, "bad xtag: %r" % ptag
    if utag[0] == '-':
      if utag in positives: raise ValueError, "utag in both: %r" % utag
      negatives.add(utag)
    else:
      if utag in negatives: raise ValueError, "utag in both: %r" % utag
      positives.add(utag)
  if not positives: raise ValueError, "empty positives in xtagspec: %r" % (
      xtagspec)
  return (sorted(positives), sorted(negatives))

class TagStore(object):
  """Abstract class for backend which stores filename--tag associations.

  The TagStore is a dumb data store which is used as a backend by TagDict
  to store filename--tag associations. The class TagStore is an abstract
  base class. The actual functionality is provided by subclasses.

  The data in a TagStore is a list of (filename, opaquetext, xtags) tuples,
  with the following constraints:

  * filename is a nonempty string which may not contain "\0".
  * opaquetext is a nonempty string which may not contain "\0".
  * xtags is a set of strings, each of them nonempty and having only
    characters [a-z0-9_:].

  Each filename in a tagstore must be unique.

  The TagStore provides the following operations:

  * set_tuple(filename, xtags, opaquetext): add a new tuple or modify
    existing tuple specified by `filename' or remove that tuple (if the
    specified `opaqutext' is empty)
  * contains_filename(filename): indicate whether hte specified `filename' is
    in any of the tuples.
  * get_opaquetext(filename): return the opaquetext in the tuple specified by
    `filename'.
  * search_with_xtags(xtags): return all (filename, opaquetext) of all
    tuples whose xtags set is is a subset of the specified `xtags'.

  Please note that `xtags' is not readable (except internally within
  search_with_xtags). This is by design.

  The TagStore treats the filename and opaquetext strings as case sensitive. It
  never changes the case of such strings. Two filenames differing only by
  case are different.

  The TagStore can treat strings in xtags as case sensitive or case
  insensitive. There is no difference since those strings may not contain
  uppercase characters.

  A TagStore is not necessarily persistent (i.e. keeps its data after the
  process exited) or thread-safe or transactionally isolated (i.e. multiple
  processes reading or writing it get consistent data). Such properties are
  declared for each subclass of TagStore.

  The methods can assume that the input they get is correct -- they shouldn't
  check for types are syntax of the input variables.
  """
  def set_tuple(self, filename, xtags, opaquetext):
    """Add (filename, xtags, opaquetext) or update it.

    If opaquetext is empty, delete the tuple, otherwise if filename is already
    present, update its tuple, otherwise add a new tuple.

    Returns:
      Old opaquetext for filename, or None if there wasn't any.
    """
    raise NotImplementedError, 'abstract method'

  def contains_filename(self, filename):
    """Indicate whether filename is present in a tuple.

    Return:
      A boolean indicating whether filename is present in a tuple.
    """
    raise NotImplementedError, 'abstract method'

  def get_opaquetext(self, filename):
    """Get the opaquetext corresponding to filename.

    Returns:
      opaquetext string or None if filename not found.
    """
    raise NotImplementedError, 'abstract method'

  def search_with_xtags(self, xtags):
    """Find (filename, opaquetext) pairs having all specified xtags.

    Imp: allow limit=42 etc.

    Args:
      xtags: Nonempty sequence of strings, each of them having the same
      syntax as the strings in the xtags in the tuples.
    Returns:
      List of (filename, opaquetext) pairs. The list is in any order.
    """
    raise NotImplementedError, 'abstract method'


class SlowMemoryTagStore(TagStore):
  """A slow, in-memory TagStore, useful for testing.

  SlowMemoryTagStore implements the TagStore with an in-memory Python
  dictionary whose keys are `filename's. SlowMemoryTagStore is slow, because
  the search_with_xtags operation is slow, because it examines all tuples for
  a possible match.

  SlowMemoryTagStore is neither persistent nor thread-safe.
  """
  def __init__(self):
    self._data = {}

  def set_tuple(self, filename, xtags, opaquetext):
    old_opaquetext = self._data.get(filename, (None, None))[1]
    if opaquetext:
      self._data[filename] = (set(xtags), opaquetext)
    elif filename in self._data:
      del self._data[filename]
    return old_opaquetext

  def contains_filename(self, filename):
    return filename in self._data

  def get_opaquetext(self, filename):
    return self._data.get(filename, (None, None))[1]

  def search_with_xtags(self, xtags):
    xtags_set = set(xtags)
    result = []
    # This loop is the slow operation, because it iterates over the whole
    # tagstore.
    for row_filename in self._data:
      row_xtags, row_opaquetext = self._data[row_filename]
      if not xtags_set.difference(row_xtags):
        result.append((row_filename, row_opaquetext))
    return result


def GetSimpleUtagWeight(is_positive, username, tagname):
  """Calculate the weight of an +-u:tag."""
  if is_positive:
    return 10
  else:
    return -7
# Always maps a positive utag to a positive weight. It would not be OK
# to map a positive utag to weight 0. The maps_positive_to_positive attribute
# is useful in a speed optimization in search_xtagspec.
GetSimpleUtagWeight.maps_positive_to_positive = True


def get_heavy_xtags(utags, get_utag_weight, tolower=False):
  tag_weights = {}
  positive_xtags = set()
  for utag in utags:
    if tolower: utag = utag.lower()
    is_positive = utag[0] != '-'
    if is_positive:
      ptag = utag
      positive_xtags.add(utag)
    else:
      ptag = utag[1:]
    username, tagname = ptag.split(':', 1)
    tag_weights[tagname] = tag_weights.get(tagname, 0) + (
        get_utag_weight(is_positive, username, tagname))
  for tagname in tag_weights:
    if tag_weights[tagname] > 0:
      positive_xtags.add(tagname)
  return positive_xtags


class TagDict(object):
  def __init__(self, tagstore, get_utag_weight=None):
    """Initialize the class.
    
    Args:
      get_utag_weight: A function like GetSimpleUtagWeight (the default).
      Can implement a special logic which gives large weight to administrator
      users. The function must return a positive integer or zero for positive
      utags, and a negative integer for negative utags. (This is not checked.)
    """
    self._tagstore = tagstore
    self._get_utag_weight = (get_utag_weight or GetSimpleUtagWeight)

  def __setitem__(self, filename, utagtext):
    """Set opaquetext for the specified filename.
    
    This function must run in a transaction."""
    positives, negatives = split_utagtext(utagtext)
    positives_lower = [s.lower() for s in positives]
    positive_tagnames = sorted(set([ptag.split(':', 1)[1]
        for ptag in positives_lower]))
    self._tagstore.set_tuple(filename,
        positives_lower + positive_tagnames,
        ' '.join(positives + negatives))

  def __getitem__(self, filename):
    opaquetext = self._tagstore.get_opaquetext(filename)
    if opaquetext is None: raise KeyError, filename
    assert type(opaquetext) == str
    assert opaquetext
    return opaquetext

  def get(self, filename, default=None):
    opaquetext = self._tagstore.get_opaquetext(filename)
    if opaquetext is None: return default
    assert type(opaquetext) == str
    assert opaquetext
    return opaquetext

  def __contains__(self, filename):
    return self._tagstore.contains_filename(filename)

  def __delitem__(self, filename):
    if self._tagstore.set_tuple(filename, empty_list, empty_list) is None:
      raise KeyError, filename

  def delete(self, filename):
    """Delete filename, return previous opaquetext (or None)."""
    return self._tagstore.set_tuple(filename, empty_list, empty_list)

  def search_xtagspec(self, searchspec, get_utag_weight=None):
    """Search for filenames matching the xtagspec.
    
    The search is case insensitive (in searchspec), but the returned values
    preserve case.
    
    Return:
      List of (filename, utags) tuples, where utags is a list of strings.
      __get__(filename) would return ' '.join(utags).
    """
    # Imp: searchspec.split("|");
    match = re.match(WHITESPACE_OR_BAR_RE, searchspec)
    assert len(searchspec) > ((match and match.end(0)) or 0), (
        'search specification is empty')
    kept = {}
    for xtagspec in searchspec.split("|"):
      match = re.match(WHITESPACE_RE, xtagspec)
      if len(xtagspec) == ((match and match.end(0)) or 0): continue
      positives, negatives = split_xtagspec(xtagspec.lower())
      if get_utag_weight is None: get_utag_weight = self._get_utag_weight
      search_result = self._tagstore.search_with_xtags(positives)
      if not search_result: continue
      if negatives or not get_utag_weight.__dict__.get(
          'maps_positive_to_positive', False):
        nominus_negatives = [xtag[1:] for xtag in negatives]
        for filename, opaquetext in search_result:
          utags = opaquetext.split(' ')
          heavy_xtags = get_heavy_xtags(utags, get_utag_weight, tolower=True)
          ##print (utags, heavy_xtags, positives, nominus_negatives)
          is_good = True
          for ptag in positives:
            if ptag not in heavy_xtags:
              is_good = False
              break
          for ptag in nominus_negatives:
            if ptag in heavy_xtags:
              is_good = False
              break
          if is_good: kept[filename] = utags
        search_result = ()
      else:
        for filename, tagname in search_result:
          kept[filename] = tagname.split(' ')

    # Sort by filename.
    return sorted(kept.items())
