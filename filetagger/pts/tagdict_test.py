#! /usr/bin/python2.4
# by pts@fazekas.hu at Sun Aug 31 20:37:38 CEST 2008

import sys
import unittest
from pts import tagdict
from pts import tagstore_sqlite

class TagDictTest(unittest.TestCase):
  def DoTestTagStore(self, tagstore):
    atagdict = tagdict.TagDict(tagstore)
    assert "file1.jpg" not in atagdict
    assert atagdict.delete('file1.jpg') is None

    exc_info = None
    try:
      del atagdict['file1.jpg']
    except KeyError:
      exc_info = sys.exc_info()
    assert (exc_info and str(exc_info[1])) == "'file1.jpg'"

    atagdict["file1.jpg"] = "  vs:bar\nus:foo \t -vs:foo "
    assert "file1.jpg" in atagdict
    assert 'us:foo vs:bar -vs:foo' == atagdict["file1.jpg"]
    atagdict["file1.jpg"] = "  us:foo vs:bar -vs:foo vs:bar"
    assert 'us:foo vs:bar -vs:foo' == atagdict["file1.jpg"]
    atagdict["file2.jpg"] = "us:foo"
    atagdict["file3.jpg"] = "-vs:bar"
    assert "file4.jpg" not in atagdict
    atagdict["file4.jpg"] = "us:baz"
    assert "file4.jpg" in atagdict
    atagdict["file4.jpg"] = ""
    # Test that file1.jpg and File2.jpg are different filenames
    assert "File1.jpg" not in atagdict
    atagdict["File1.jpg"] = "us:foo"
    del atagdict["File1.jpg"]
    assert 'us:foo vs:bar -vs:foo' == atagdict["file1.jpg"]
    atagdict["file5.jpg"] = "us:food"
    atagdict["file6.jpg"] = "A_User_Name:A_Tag_Name"
    atagdict["file7.jpg"] = "ignored_user:food"
    atagdict["file8.jpg"] = "us:is vs:if us:and vs:not"

    assert ([] == (atagdict.search_xtagspec('whatever')))
    assert ([] == (atagdict.search_xtagspec('vs:foo')))
    assert ([] == (atagdict.search_xtagspec('foo -us:foo')))
    assert ([('file1.jpg', ['us:foo', 'vs:bar', '-vs:foo']),
        ('file2.jpg', ['us:foo'])] ==
        (atagdict.search_xtagspec('us:foo')))
    assert ([('file1.jpg', ['us:foo', 'vs:bar', '-vs:foo'])] ==
        (atagdict.search_xtagspec('foo vs:bar')))
    assert ([('file5.jpg', ['us:food'])] ==
        (atagdict.search_xtagspec('us:food')))
    # Case insensitive match. 
    assert ([('file5.jpg', ['us:food'])] ==
        (atagdict.search_xtagspec('us:FoOd')))
    assert ([('file2.jpg', ['us:foo'])] ==
        (atagdict.search_xtagspec('foo -vs:bar')))
    # Result preserves case.
    assert ([('file6.jpg', ['A_User_Name:A_Tag_Name'])] ==
        (atagdict.search_xtagspec('A_User_Name:A_Tag_Name')))
    assert ([('file6.jpg', ['A_User_Name:A_Tag_Name'])] ==
        (atagdict.search_xtagspec('A_Tag_Name')))
    assert ([('file6.jpg', ['A_User_Name:A_Tag_Name'])] ==
        (atagdict.search_xtagspec('A_Tag_name')))
    assert ([('file6.jpg', ['A_User_Name:A_Tag_Name'])] ==
        (atagdict.search_xtagspec('A_User_name:A_Tag_Name')))
    assert ([('file5.jpg', ['us:food']), ('file7.jpg', ['ignored_user:food'])] ==
        (atagdict.search_xtagspec('food')))
    def GetDiscriminativeUtagWeight(is_positive, username, tagname):
      if username == 'ignored_user': return 0
      if is_positive:
        return 10
      else:
        return -7
    assert ([('file5.jpg', ['us:food'])] ==
        (atagdict.search_xtagspec('food', GetDiscriminativeUtagWeight)))
    # Test that even ignored_user's stuff is found if he is specified
    # explicitly.
    assert ([('file7.jpg', ['ignored_user:food'])] ==
        (atagdict.search_xtagspec('ignored_user:food',
        GetDiscriminativeUtagWeight)))
    # Test that stop words are returned.
    assert ([('file8.jpg', ['us:and', 'us:is', 'vs:if', 'vs:not'])] ==
        (atagdict.search_xtagspec('and if is not -was')))

    exc_info = None
    try:
      atagdict.search_xtagspec(' |  \t')
    except AssertionError:
      exc_info = sys.exc_info()
    assert (exc_info and str(exc_info[1])) == 'search specification is empty'

    # Test disjunction (logical or, |).
    assert ([('file1.jpg', ['us:foo', 'vs:bar', '-vs:foo']),
        ('file2.jpg', ['us:foo']), ('file5.jpg', ['us:food']),
        ('file7.jpg', ['ignored_user:food']),
        ('file8.jpg', ['us:and', 'us:is', 'vs:if', 'vs:not'])] ==
        atagdict.search_xtagspec('NOT and |  | foo -bAd | bAR |food || What'))
    # !! proper assertEqual

  def testBasic(self):
    # !! move some of these tests

    assert 'foo8bar7baz820065' == tagstore_sqlite.xtag_to_sqliteword(
        'foo_bar:baz_2007')

    assert set(['vs:foo', 'bar', 'us:baz', 'food', 'us:bar',
        'us:foo', 'us:food', 'foo']) == (
        tagdict.get_heavy_xtags(['us:food', 'us:foo', 'vs:foo',
        'us:bar', '-vs:bar',
        'us:baz', '-vs:baz', '-ws:baz'],
        tagdict.GetSimpleUtagWeight))

  def testSqlite3TagStore(self):
    conn = tagstore_sqlite.connect(":memory:")
    tagstore = tagstore_sqlite.Sqlite3TagStore(cursor=conn.cursor())
    self.DoTestTagStore(tagstore)

  def testSlowMemoryTextStore(self):
    self.DoTestTagStore(tagdict.SlowMemoryTagStore())

if __name__ == "__main__":
  unittest.main()
