#!/usr/bin/env python
#===============================================================================
# Copyright 2014 NetApp, Inc. All Rights Reserved,
# contribution by Jorge Mora <mora@netapp.com>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#===============================================================================
import os
import re
import sys
import time
import textwrap
import nfstest_config as c
from optparse import OptionParser, IndentedHelpFormatter

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2014 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.2"

USAGE = """%prog [options] <xdrfile1.x> [<xdrfile2.x> ...]

Convert the XDR definition file into python code
================================================
Process the XDR program definition file and convert it into python code.
A couple of files are created: xdrfile1_const.py where all constant definitions
and enum dictionaries are stored and xdrfile1.py where the python code
corresponding to all structures and discriminated unions are stored.

A variable length array or opaque with a maximum length of 1 (name<1>)
is changed to a regular non-list variable to make it easier to access.
If the length is 0 then the variable will have a value of None.

Linked lists are changed into a simple list, so when the following definition
is processed:
    struct entry4 {
        nfs_cookie4     cookie;
        component4      name;
        fattr4          attrs;
        entry4          *nextentry;
    };

    struct dirlist4 {
        entry4          *entries;
        bool            eof;
    };
The class created for entry4 will not have the nextentry attribute and the
entries attribute in class dirlist4 will be a simple list of entry4 items.
This makes it easier to access the list in python instead of traversing
the linked list.

In addition to processing the XDR definitions, it processes different tags
to change or expand the behavior of the python object being created.
These tags are given as comments in the XDR definition file and are given
using the following syntax:

    COPYRIGHT: year
        Add copyright information to the python modules created
    VERSION: version
        Add version information to the python modules created
    INCLUDE: file
        Include the file and add it in-line to be processed
    COMMENT: comment
        Include the comment in both the decoding and constants modules
    INHERIT: name
        Create class inheriting from the given base class name. The name is
        is given as a full path including the package and class name, e.g.:
        /* INHERIT: packet.nfs.nfsbase.NFSbase */
        struct Obj {
            int    id;
            opaque data;
        };
        Creates the following:
        from packet.nfs.nfsbase import NFSbase
        class Obj(NFSbase):
            ...
    XARG: name[;disp][,...]
        Add extra arguments to the object constructor __init__()
        The disp modifier is to make it a displayable attribute, e.g.:
        /* XARG: arg1, arg2;disp */
    CLASSATTR: name=value[,...]
        Add name as a class attribute
    OBJATTR: name=value[,...]
        Add extra attribute having the given value. If value is the name of
        another attribute in the object a "self." is added to the value, e.g.:
        /* OBJATTR op=argop, fh=self.nfs4_fh, id="123" */
        Creates the following attributes:
        self.op = self.argop
        self.fh = self.nfs4_fh
        self.id = "123"
        If argop and nfs4_fh is an attribute for the object.
    GLOBAL: name[=value][,...]
        Set global attribute using set_global(). The value is processed the
        same as OBJATTR.
        If no value is given, the name given is a global defined somewhere
        else so it should not be defined -- this is a reference to a global
    FLATATTR: 1
        Make the object attributes of the given attribute part of the
        attributes of the current object, e.g.:
        struct Obj2 {
            int attr1;
        };
        struct Obj1 {
            int  count;
            Obj2 res;  /* FLATATTR: 1 */
        };
        An object instantiated as x = Obj1() is able to access all attributes
        for "res" as part of the Obj1 object (x.attr1 is the same as x.res.attr1)
    EQATTR: name
        Set comparison attribute so x == x.name is True, e.g.:
        /* EQATTR: id */
        struct Obj {
            int    id;
            opaque data;
        };
        An object instantiated as x = Obj() can use x == value,
        the same as x.id == value
    STRFMT1: <format>
        String representation format for object when using debug_repr(1), e.g.:
        /* STRFMT1 : {0#x} {1} */
        Where the index points to the object attribute defined in _attrlist
        {0#x} displays the first attribute in hex
        {1} displays the second attribute using str()
        For more information see FormatStr()
    STRFMT2: <format>
        String representation format for object when using debug_repr(2)
    STRHEX: 1
        Display attribute in hex.
        If given on a typedef, any attribute defined by this typedef
        will be displayed in hex.
    FOPAQUE: name
        The definition for a variable length opaque is broken down into its
        length and data, e.g.:
        opaque data<> /* FOPAQUE: count */
        Converted to
        unsigned int count;
        opaque data[count];
    FMAP: 1
        Add extra dictionary table for an enum definition which maps the value
        to a decoding function given by the lower case value of the key
        The resulting table is created in the main python file, not in the
        constants file:
        /* FMAP: 1 */
        enum nfs_fattr4 {
            FATTR4_SUPPORTED_ATTRS    = 0,
            FATTR4_TYPE               = 1,
        };
        Creates the additional dictionary:
        nfs_fattr4_f = {
            0: fattr4_supported_attrs,
            1: fattr4_type,
        };
    BITMAP: 1
        On a typedef use unpack_bitmap() to decode
        /* BITMAP: 1 */
        typedef uint32_t bitmap4<>;
        Creates the following:
        bitmap4 = Unpack.unpack_bitmap
    BITDICT: enum_def
        Convert an object to a dictionary where the key is the bit number
        and the value is given by executing the function provided by the
        enum definition table specified by FMAP
        Use on a structure with the following definition:
        /* BITDICT: nfs_fattr4 */
        struct fattr4 {
            uint32  mask<>;
            opaque  values<>;
        };
        Where the mask gives which bits are encoded in the opaque given
        by values. For more information see packet.utils.
    BITMAPOBJ: dmask[,args]
        Create a Bitmap() using the dictionary table dname. Table dname
        should be created using the bitmap tag, e.g.:
        typedef uint32_t access4; /* BITMAPOBJ:const.nfs4_access, sep="," */
        Creates the following:
        access4 = lambda unpack: Bitmap(unpack, const.nfs4_access, sep=",")
        For more information see packet.utils.
    TRY: 1
        Add try/except block to object definition

Also, the following comment markers are processed. The marker must be in
the first line of a multi-line comment:

    __DESCRIPTION__
        Description for the decoding module. If it is not given a default
        description is used.
    __CONST__
        Description for the constants module. If it is not given a default
        description is used. This marker is given within the same comment
        starting with the __DESCRIPTION__ marker."""

# Types to decode using unpack_int()
int32_list = ["int"]
# Types to decode using unpack_uint()
uint32_list = ["unsigned int"]
# Types to decode using unpack_int64()
int64_list = ["hyper"]
# Types to decode using unpack_uint64()
uint64_list = ["unsigned hyper"]
# Types to decode using unpack_opaque()
string_list = ["opaque", "string"]

valid_tags = {
    "COPYRIGHT" : 1,
    "VERSION"   : 1,
    "INCLUDE"   : 1,
    "COMMENT"   : 1,
    "XARG"      : 1,
    "CLASSATTR" : 1,
    "FLATATTR"  : 1,
    "TRY"       : 1,
    "STRFMT1"   : 1,
    "STRFMT2"   : 1,
    "FOPAQUE"   : 1,
    "STRHEX"    : 1,
    "FMAP"      : 1,
    "BITMAP"    : 1,
    "BITDICT"   : 1,
    "OBJATTR"   : 1,
    "GLOBAL"    : 1,
    "EQATTR"    : 1,
    "INHERIT"   : 1,
    "BITMAPOBJ" : 1,
}

# Constants
CONSTANT = 0
ENUM     = 1
UNION    = 2
STRUCT   = 3
BITMAP   = 4

deftypemap = {
    "enum"   : ENUM,
    "union"  : UNION,
    "struct" : STRUCT,
    "bitmap" : BITMAP,
}

empty_quotes = ("''", '""')

copyright_str = """
#===============================================================================
# Copyright __COPYRIGHT__ NetApp, Inc. All Rights Reserved,
# contribution by Jorge Mora <mora@netapp.com>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#===============================================================================
"""

modconst_str = """
# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) __COPYRIGHT__ NetApp, Inc."
__license__   = "GPL v2"
__version__   = __VERSION__
"""

# Variable definition regex
#   unsigned int varname;
#   int *varname;
#   opaque varname<20>;
# Examples:
#   unsigned int  stamp;
#       ("unsigned int", " int", "int", "", "stamp", "", None)
#   opaque server_scope<NFS4_OPAQUE_LIMIT>;
#       ("opaque", None, None, "", "server_scope", "<NFS4_OPAQUE_LIMIT>", "<NFS4_OPAQUE_LIMIT>")
vardefstr = r"\s*([\w.]+(\s+(\w+))?)\s+(\*?)\s*(\w+)(([<\[]\w*[>\]])?)"

class XDRobject:
    def __init__(self, xfile):
        """Constructor which takes an XDR definition file as argument"""
        # Dictionary of typedef where key is the typedef name and the value
        # is a list [type declaration, pointer marker, array declaration]
        self.dtypedef = {}

        # List of typedef definitions where each entry is a list
        # [typedef name, type declaration, array declaration, tags, comments array]
        self.typedef_list = []

        # Dictionary of base objects used in inheritance, use a dictionary
        # instead of a list to have unique elements
        self.inherit_names = {}

        # Copyright and module info constants
        self.copyright   = None
        self.modversion  = None
        self.description = None
        self.desc_const  = None

        # Enum data list where each entry is a dictionary having the following keys:
        # deftype, defname, deftags, defcomm, enumlist
        self.enum_data = []

        # FMAP dictionary where key is the definition name and the value
        # is the enum entry
        self.fmap_data = {}

        # Constants dictionary where key is the constant name
        self.dconstants = {}

        # List of enum names
        self.enumdef_list = []

        # List of bitmap typedefs
        self.bitmap_defs = []

        # Tags dictionary
        self.tags = {}

        # Attributes used for processing comments
        self.incomment = False
        self.is_comment = False
        self.blank_lines = 0

        # Initialize definition variables
        self.reset_defvars()

        # Input file
        self.xfile = xfile
        (self.bfile, ext) = os.path.splitext(self.xfile)
        self.bname = os.path.basename(self.bfile)
        # Output file for python class objects
        self.pfile = self.bfile + ".py"
        # Output file for python constants and mapping dictionaries
        self.cfile = self.bfile + "_const.py"
        if self.pfile == self.xfile:
            print "    The input file has a python extension,\n" + \
                  "    it will not be overwritten"
            return

        # Timestamp output files are generated
        progname = os.path.basename(sys.argv[0])
        stime = time.strftime("%a %b %d %H:%M:%S %Y", time.localtime())
        self.genstr = "# Generated by %s from %s on %s\n" % (progname, self.xfile, stime)

        # Contents of XDR file
        self.xdr_lines = []

        self.read_file()
        self.process_enum_and_const()
        self.process_xdr()

    def read_file(self):
        """Read entire contents of XDR definition file"""
        for line in open(self.xfile, "r"):
            self.process_comments(line)
            incl_file = self.tags.pop("INCLUDE", None)
            if incl_file is not None:
                print "  Including file %s" % incl_file
                for incl_line in open(incl_file, "r"):
                    self.xdr_lines.append(incl_line)
                continue
            self.xdr_lines.append(line)

    def reset_defvars(self):
        """Reset all definition variables"""
        # Attribute definition list for a struct, union (all vars defs)
        self.item_dlist = []
        # Case definition list
        self.case_list = []
        # In-line comment
        self.inline_comment = ""
        # Multi-line comment
        self.multi_comment = []
        # Previous comment
        self.old_comment = []

    def gettype(self, dtype, usetypedef=True):
        """Return real definition type

           dtype:
               Definition type given in XDR file
           usetypedef:
               If usetypedef is False the return value is just dtype except
               for type of "bool" which is changed to "nfs_bool" to avoid
               confusion with python's own bool keyword.
               If usetypedef is True the list of typedefs is traversed
               until a basic def type is found and returned, e.g.,
                 Giving the following typedef:
                   typedef opaque nfs_fh4<NFS4_FHSIZE>;
                 And the following code:
                   nfs_fh4 fh;
                 The call to gettype("nfs_fh4") will returned the basic type
                 "opaque" and its array definition:
                 ("opaque", [["", "<NFS4_FHSIZE>"]])
        """
        ret = []
        while usetypedef:
            item = self.dtypedef.get(dtype)
            if item is None:
                break
            dtype = item[0]
            if item[1] is not None or item[2] is not None:
                ret.append(item[1:])
        if dtype == "bool":
            dtype = "nfs_bool"
        return (dtype, ret)

    def getsize(self, adef):
        """Return the size definition for an opaque or array

           adef:
               Array definition
        """
        size = ""
        if adef is not None and adef[0] in ["[", "<"]:
            regex = re.search(r"[\.\w]+", adef)
            if regex:
                size = regex.group(0)
            if self.dconstants.get(size) is not None:
                # Size is given as a constant name
                size = "const." + size
        return size

    def getunpack(self, dname, alist, compound=False, typedef=False):
        """Return the correct decoding statement for given var definition

           dname:
               Variable definition, e.g., opaque, string, int, etc.
           alist:
               Variable definition modifier: array [opaque def, array def] where
               the first item is the opaque modifier (<>, [], <32>, [12], etc.)
               and the second item is the array modifier (<>, [], etc.) for the
               case where dname is an array of opaques
           compound:
               True if decoding a compound, e.g. array or list
           typedef:
               True if output is for a typedef, e.g.,
                   For dname="int"
                   typedef=False, output:unpack.unpack_int()
                   typedef=True,  output:Unpack.unpack_int
        """
        ret = ("", "", "")
        if compound or typedef:
            # Use class method
            ustr = "Unpack"
        else:
            # Use unpack object
            ustr = "unpack"

        if dname in int32_list:
            ret = ("%s.unpack_int" % ustr, "()", "")
        elif dname in uint32_list:
            ret = ("%s.unpack_uint" % ustr, "()", "")
        elif dname in int64_list:
            ret = ("%s.unpack_int64" % ustr, "()", "")
        elif dname in uint64_list:
            ret = ("%s.unpack_uint64" % ustr, "()", "")
        elif dname in string_list:
            if alist and alist[0][0] in ["[", "<"]:
                # Opaque
                fstr = ""
                if alist[0][0] == "[":
                    fstr = "f"
                size = self.getsize(alist[0])
                if typedef and len(size):
                    ustr = "lambda unpack: unpack"
                ltstr = ""
                if len(alist) > 1:
                    asize = self.getsize(alist[1])
                    if asize is not None:
                        # Size for each member of an array
                        ltstr = ", %s" % asize
                ret = ("%s.unpack_%sopaque" % (ustr, fstr), "(%s)" % size, '%s, args={"size":%s}' % (ltstr, size))
            else:
                ret = ("%s.unpack_opaque" % ustr, "()", "")
        elif typedef:
            if alist and len(alist[0]) >= 2 and alist[0][0] in ["[", "<"]:
                size = self.getsize(alist[0])
                fixed = (alist[0][0] == "[")
                sstr = ""
                if len(size):
                    if fixed:
                        sstr = ", %s" % size
                    else:
                        sstr = ", maxcount=%s" % size
                dname = "lambda unpack: unpack.unpack_array(%s%s)" % (dname, sstr)
            if dname == "bool":
                dname = "nfs_bool"
            ret = (dname, "", "")
        elif not compound and dname[:7].lower() == "unpack.":
            dname = dname[:7].lower() + dname[7:]
            ret = (dname, "()", "")
        else:
            ret = (dname, "(unpack)", "")

        if compound:
            return ret[0] + ret[2]
        elif typedef:
            if ustr == "Unpack":
                return ret[0]
            else:
                return ret[0] + ret[1]
        else:
            return ret[0] + ret[1]

    def fix_comments(self, item_list, commsidx):
        """Remove old comment if the previous multi-line comment
           is the same in order to avoid displaying the comment twice

           item_list:
               List of items
           commsidx:
               Index of comment in each item in item_list
        """
        save_comm = []
        for item in item_list:
            comms = item[commsidx]
            # Compare previous multi-line commnet against current old comment
            # removing the multi-line comment marker from the old comment
            old_comment = comms[2]
            if len(old_comment) > 1 and old_comment[-1] == "":
                old_comment = comms[2][:-1]
            if save_comm == old_comment:
                comms[2] = []
            save_comm = comms[1]

    def rm_multi_blanks(self, alist):
        """Remove multiple blank lines in given list of comments"""
        index = 0
        mlist = []
        isblank = False
        for item in alist:
            if len(item) == 0:
                if isblank:
                    mlist.append(index)
                isblank = True
            else:
                isblank = False
            index += 1
        for index in reversed(mlist):
            alist.pop(index)
        return

    def get_comments(self, comm_list, strline, spnam, sppre, ctype=False, newobj=False):
        """Returns a tuple of two comments to display, the first one is
           the main comment to be displayed before the python code and
           the second comment is the inline comment.

           comm_list:
               List of comments: (inline, multi, old)
           strline:
               Python code to be displayed. This is used for formatting the
               multi-line comments going as inline comments
           spnam:
               Extra spaces to match the longest variable name to line up
               inline comments, e.g., extra spaces are added after "id;"
                   int  id;     /* comment 1 */
                   data buffer; /* comment 2 */
           sppre:
               Extra spaces added to beginning of main comment to line up
               to the start of python code
           ctype:
               Comment type to output. If True, this is a C-language comment
               else it is a python comment
           newobj:
               This is a new object so add an extra new line at the beginning
        """
        incommstr = ""
        scomm_list = []
        inlinecomm,multicomm,oldcomm = comm_list
        if ctype:
            csign_str = "/*"
            csign_end = " */"
            cmult_str = "/*"
            cmult_end = " */"
        else:
            csign_str = "#"
            csign_end = ""
            cmult_str = "#"
            cmult_end = ""

        if len(oldcomm):
            if ctype and len(oldcomm) > 1:
                scomm_list.append("%s%s\n" % (sppre, csign_str))
                cmult_str = " *"
                cmult_end = ""
            if len(oldcomm[0]) == 0:
                oldcomm.pop(0) # Discard multi-line comment marker
            if len(oldcomm) and len(oldcomm[-1]) == 0:
                oldcomm.pop() # Discard space-before-comment marker
                if not ctype:
                    scomm_list.insert(0, "\n")

        # Remove multiple blank lines
        self.rm_multi_blanks(multicomm)
        self.rm_multi_blanks(oldcomm)
        for mline in oldcomm:
            sps = " "
            if len(mline) == 0:
                sps = ""
            scomm_list.append("%s%s%s%s%s\n" % (sppre, cmult_str, sps, mline, cmult_end))
        if len(oldcomm) and ctype and cmult_end == "":
            scomm_list.append("%s%s\n" % (sppre, csign_end))
        if newobj and scomm_list and scomm_list[0] != "\n":
            scomm_list.insert(0, "\n")

        if len(multicomm):
            sps = ""
            commlist = []
            for mline in multicomm:
                commlist.append("%s%s  %s %s%s" % (sps, spnam, csign_str, mline, csign_end))
                if len(sps) == 0:
                    sps = " " * len(strline)
            incommstr = "\n".join(commlist)
        elif len(inlinecomm):
            incommstr = "%s  %s %s%s" % (spnam, csign_str, inlinecomm, csign_end)
        return ("".join(scomm_list), incommstr)

    def process_comments(self, line):
        """Process comments for the given line from the XDR definition file"""
        line = line.rstrip()
        self.inline_comment = ""

        # Process tags
        regex = True
        while regex:
            regex = re.search(r"/\*\s*(\w+)\s*:\s*(.+)\*/", line)
            if regex:
                tag, tdata = regex.groups()
                tag.strip()
                if valid_tags.get(tag):
                    self.tags[tag] = tdata.strip()
                    # Do not include tags as comments
                    line = re.sub(r"/\*\s*(\w+)\s*:\s*(.+)\*/", "", line)
                else:
                    # No valid tag was found
                    regex = None

        # Process in-line comments
        regex = re.search(r"/\*\s*(.*)\s*\*/", line)
        if regex:
            # Save in-line comment
            self.inline_comment = regex.group(1).strip()
            line = re.sub(r"/\*.*\*/", "", line)
            self.multi_comment = []
        if re.search(r"^\s*$", line):
            # Empty line
            if len(self.inline_comment):
                self.old_comment += [self.inline_comment]
                if self.blank_lines and len(self.old_comment) and len(self.old_comment[0]):
                    # Add multi-line comment marker
                    self.old_comment.insert(0, "")
                self.inline_comment = ""
                self.blank_lines = 0
                self.is_comment = True
            # Skip empty lines
            self.blank_lines += 1
            if self.incomment:
                self.multi_comment.append("")
            return ""

        if self.incomment:
            if not self.is_comment:
                self.old_comment = []
            if re.search(r"\*/", line):
                # End of multi-line comment
                if self.copyright is None or self.description is None:
                    out = "\n".join(self.multi_comment)
                    if re.search(r"(Copyright .*\d\d\d\d|__DESCRIPTION__)", out):
                        # Ignore any copyright and description comments in XDR file
                        if "__DESCRIPTION__" in self.multi_comment:
                            while self.multi_comment.pop(0) != "__DESCRIPTION__":
                                pass
                            d_list = ['"""']
                            while len(self.multi_comment) > 0:
                                dline = self.multi_comment.pop(0)
                                if dline == "__CONST__":
                                    # The description of the decoding module
                                    # ends on the start of the description for
                                    # the constants module given by the
                                    # __CONST__ marker
                                    break
                                d_list.append(dline)
                            # Add description to decoding moule
                            while d_list[-1] == "":
                                d_list.pop()
                            if len(d_list) > 1:
                                self.description = "\n".join(d_list) + '\n"""\n'
                            # Add description to constants moule
                            d_list = ['"""'] + self.multi_comment
                            while d_list[-1] == "":
                                d_list.pop()
                            if len(d_list) > 1:
                                self.desc_const = "\n".join(d_list) + '\n"""\n'
                        self.multi_comment = []
                        self.old_comment = []
                line = re.sub(r"\*/.*", "", line)
                self.incomment = False
                self.is_comment = True
            regex = re.search(r"^\s*\*?\s?(.*)\s*(\*/)?", line)
            if regex and len(regex.group(1)):
                self.multi_comment.append(regex.group(1))
            elif re.search(r"^\s\*$", line):
                self.multi_comment.append("")
            if not self.incomment:
                # Reset multi-line comment list and add
                # space-before-comment marker (blank line at the end)
                self.old_comment += self.multi_comment + [""]
                self.multi_comment = []
            self.blank_lines = 0
            return ""
        else:
            regex = re.search(r"(.*)/\*\s?(.*)", line)
            if regex:
                # Start of multi-line comment
                comm = regex.group(2)
                if re.search(r"^\s*$", comm):
                    self.multi_comment = []
                else:
                    self.multi_comment = [regex.group(2)]
                if self.blank_lines:
                    # Add multi-line comment marker
                    self.multi_comment.insert(0, "")
                line = regex.group(1).strip()
                self.incomment = True
        self.blank_lines = 0
        if not self.incomment:
            self.is_comment = False
        return line.rstrip()

    def process_def(self, line):
        """Process a single line for any of the following definition types:
           struct, union, enum and bitmap
        """
        deftype = None
        defname = None
        deftags = {}
        defcomments = []
        regex = re.search(r"^\s*(struct|union|enum|bitmap)\s+(\w+)(\s+switch\s*\(" + vardefstr + r"\s*\))?", line)
        if regex:
            data = regex.groups()
            defname = data[1]
            deftype = deftypemap.get(data[0])
            if deftype == UNION:
                # Add discriminant to list of definitions
                comms = [self.inline_comment, self.multi_comment, []]
                self.item_dlist.append([data[7], data[3], data[6], data[8], [], {}, comms, []])

        if deftype is not None:
            defcomments = [self.inline_comment, self.multi_comment, self.old_comment]
            self.inline_comment = ""
            self.multi_comment = []
            self.old_comment = []
            deftags = self.tags
            self.tags = {}
        return (deftype, defname, deftags, defcomments)

    def set_vars(self, fd, tags, dnames, indent, pre=False, post=False, vname=None, noop=False):
        """Set GLOBAL variables

           fd:
               File descriptor for output file
           tags:
               Tags dictionary for given object
           dnames:
               List of attribute definition names in object.
               If the value of the global to be defined exists in this list
               then "self." is added to the value. If it does not exist the
               value is literal
           indent:
               Space indentation
           pre:
               Global variable is defined before any other attributes
           post:
               Global variable is defined after all other attributes
           vname:
               Set global variable for the given name only
           noop:
               No operation, do not write the global definition to the file
               just return the length of the global definition. This is used
               to find if an arm of a discriminated union should be created
               in case its body is "void", but if there is a global to be set
               then it should be created.
        """
        out = ""
        tag = "GLOBAL"
        globalvars = tags.get(tag)
        if globalvars is not None:
            for item in globalvars.split(","):
                data = item.split("=")
                if len(data) == 2:
                    name,var = data
                else:
                    continue
                if vname is not None and vname != var:
                    continue
                if pre:
                    # If global is set before any other attributes are set
                    # then it should not be in the dnames list
                    if var not in dnames:
                        out += '%sself.set_%s("%s", %s)\n' % (indent, tag.lower(), name, var)
                else:
                    if var in dnames:
                        out += '%sself.set_%s("%s", self.%s)\n' % (indent, tag.lower(), name, var)
                    elif not post:
                        # Only if post is not specified, this is to avoid
                        # duplicates when the same global is processed with
                        # pre as well
                        out += '%sself.set_%s("%s", %s)\n' % (indent, tag.lower(), name, var)
        if not noop and len(out) > 0:
            fd.write(out)
        return len(out)

    def set_objattr(self, fd, deftags, dnames, indent, maxlen=0, namesonly=False):
        """Process the OBJATTR tag and add the attribute initialization
           to the output file.

           fd:
               File descriptor for output file
           deftags:
               Tags dictionary for given object
           dnames:
               List of attribute definition names in object.
               If the value of the attribute to be defined exists in this list
               then "self." is added to the value. If it does not exist the
               value is literal
           indent:
               Space indentation
           maxlen:
               Length of longest attribute name in the class to be defined.
               This is used to align all attribute definitions in the class
           namesonly:
               Return only the list of names to be added, but do not write
               the attributes to the output file. This is used to include
               these names when calculating maxlen.
        """
        nlist = []
        vdnames = deftags.get("OBJATTR")
        if vdnames is not None:
            for vardup in vdnames.split(","):
                newname, oldname = vardup.split("=")
                nlist.append(newname)
                if not namesonly:
                    sps = ""
                    if maxlen > 0:
                        sps = " " * (maxlen - len(newname))
                    if oldname in dnames:
                        # Value in attribute to be set is an attribute
                        # in the class
                        fd.write("%sself.%s %s= self.%s\n" % (indent, newname, sps, oldname))
                    else:
                        # Literal value
                        fd.write("%sself.%s %s= %s\n" % (indent, newname, sps, oldname))
        return nlist

    def get_strfmt(self, level, deftags):
        """Process the STRFMT1 and STRFMT2 tags and return the string
           representation of class attribute _strfmt

           deftags:
               Tags dictionary for given object
        """
        out = []
        fmt = "STRFMT" + str(level)
        strfmt = deftags.get(fmt)
        if strfmt is not None:
            if strfmt in empty_quotes:
                strfmt = ""
            return '"%s"' % strfmt

    def set_strfmt(self, fd, deftags, indent):
        """Process the STRFMT1 and STRFMT2 tags and write the set_strfmt
           calls to the output file

           fd:
               File descriptor for output file
           deftags:
               Tags dictionary for given object
           indent:
               Space indentation
        """
        index = 1
        for fmt in ("STRFMT1", "STRFMT2"):
            strfmt = deftags.get(fmt)
            if strfmt is not None:
                if strfmt in empty_quotes:
                    strfmt = ""
                fd.write('%sself.set_strfmt(%d, "%s")\n' % (indent, index, strfmt))
            index += 1

    def process_fopaque(self):
        """Process FOPAQUE tag"""
        index = 0
        for item in self.item_dlist:
            vname,dname,pdef,adef,clist,tag,comms,pcomms = item
            tagval = tag.get("FOPAQUE")
            if tagval is not None and dname == "opaque":
                self.item_dlist.pop(index)
                self.item_dlist.insert(index, [tagval,"unsigned int","","",clist,{},comms,pcomms])
                self.item_dlist.insert(index+1, [vname,dname,pdef,"[self.%s]"%tagval,[],{},[],[]])
            index += 1

    def process_linkedlist(self, defname):
        """Process linked list. If any definition name in the attribute
           list is the same as the definition name of struct given,
           then this is a linked list and the attribute that matches
           is removed from the list.

           defname:
               Definition name for struct
        """
        index = 0
        for item in self.item_dlist:
            if item[1] == defname:
                # This is a linked list
                self.linkedlist[defname] = True
                self.item_dlist.pop(index)
                break
            index += 1

    def process_bitdict(self, defname, deftags):
        """Process the BITDICT tag

           defname:
               Definition name for struct
           deftags:
               Tags dictionary for given object
        """
        isbitdict = False
        if deftags.get("BITDICT"):
            # Process BITDICT
            if len(self.item_dlist) == 2:
                vname_mask,dname,pdef,adef,clist,tag,comms,pcomms = self.item_dlist[0]
                expr = (dname in self.bitmap_defs)
                dname,opts = self.gettype(dname)
                if (dname in uint32_list and adef == "<>") or expr:
                    vname,dname,pdef,adef,clist,tag,comms,pcomms = self.item_dlist[1]
                    dname,opts = self.gettype(dname)
                    if dname == "opaque" and opts[0][1] == "<>":
                        isbitdict = True
            if not isbitdict:
                raise Exception, "BITDICT tag is used incorrectly in definition for '%s'" % defname
        return isbitdict

    def set_copyright(self, fd):
        """Write copyright information"""
        if self.copyright is not None:
            copyright = copyright_str.lstrip().replace("__COPYRIGHT__", self.copyright)
            fd.write(copyright)

    def set_modconst(self, fd):
        """Write module constants"""
        if self.modversion is not None:
            if self.copyright:
                year = self.copyright
            else:
                year = time.strftime("%Y", time.localtime())
            modconst = modconst_str.replace("__COPYRIGHT__", year)
            modconst = modconst.replace("__VERSION__", self.modversion)
            fd.write(modconst)

    def set_original_definition(self, fd, deftype, defname):
        """Write original XDR definition to the output file

           fd:
               File descriptor for output file
           deftype:
               Definition type: either a STRUCT or UNION
           defname:
               Definition name for struct/union
        """
        fd.write('    """\n')
        sppre = " " * 11
        if deftype == STRUCT:
            #===========================================================
            # Write original definition of STRUCT
            #===========================================================
            fd.write("       struct %s {\n" % defname)
            if self.item_dlist:
                maxlennam = len(max([x[0]+x[2]+x[3] for x in self.item_dlist], key=len))
                maxlendef = len(max([x[1] for x in self.item_dlist], key=len))
                self.fix_comments(self.item_dlist, 6)
                for item in self.item_dlist:
                    vname,dname,pdef,adef,clist,tag,comms,pcomms = item
                    spdef = " " * (maxlendef - len(dname))
                    spnam = " " * (maxlennam - len(vname+pdef+adef))
                    out = "%s%s%s %s%s%s;" % (sppre, dname, spdef, pdef, vname, adef)
                    mcommstr, incommstr = self.get_comments(comms, out, spnam, sppre, True)
                    if len(mcommstr):
                        fd.write(mcommstr)
                    fd.write("%s%s\n" % (out, incommstr))
        else:
            #===========================================================
            # Write original definition of UNION
            #===========================================================
            item = self.item_dlist[0]
            fd.write("       union switch %s (%s %s) {\n" % (defname, item[1], item[0]))
            if self.item_dlist:
                sppre_case = sppre + "    "
                maxlen1 = len(max([y[0] for y in [x[4][0] for x in self.item_dlist[1:]]], key=len))
                maxlen2 = len(max([x[0]+x[1] for x in self.item_dlist[1:]], key=len))
                maxlen = max(maxlen1+3, maxlen2+4)
            for item in self.item_dlist[1:]:
                vname,dname,pdef,adef,clist,tag,comms,pcomms = item
                for citem in clist:
                    if citem[0] == "default":
                        if dname != "void":
                            # The default case does not have "void",
                            # so all cases must have an "elif"
                            # statement even if returning void
                            valid_default = True
                        out = "%sdefault:" % sppre
                        spnam = " " * (maxlen - 8)
                    else:
                        out = "%scase %s:" % (sppre, citem[0])
                        spnam = " " * (maxlen - len(citem[0]) - 5)
                    mcommstr, incommstr = self.get_comments(citem[1], out, spnam, sppre, True)
                    if len(mcommstr):
                        fd.write(mcommstr)
                    fd.write("%s%s\n" % (out, incommstr))
                if dname == "void":
                    out = "%svoid;" % sppre_case
                    spnam = " " * (maxlen - len(vname) - len(dname) - 4)
                else:
                    out = "%s%s %s%s%s;" % (sppre_case, dname, pdef, vname, adef)
                    spnam = " " * (maxlen - len(vname) - len(dname) - 5)
                mcommstr, incommstr = self.get_comments(item[6], out, spnam, sppre_case, True)
                if len(mcommstr):
                    fd.write(mcommstr)
                fd.write("%s%s\n" % (out, incommstr))
        fd.write('       };\n')
        fd.write('    """\n')

    def process_union_var(self, line):
        """Process variable definition on a union"""
        regex = re.search(r"^\s*void;", line)
        if regex:
            comms = [self.inline_comment, self.multi_comment, self.old_comment]
            self.item_dlist.append(["", "void", "", "", self.case_list, self.tags, comms, []])
        else:
            regex = re.search(vardefstr, line)
            dname,atmp,btmp,pdef,vname,adef,tmp = regex.groups()
            comms = [self.inline_comment, self.multi_comment, self.old_comment]
            self.item_dlist.append([vname, dname, pdef, adef, self.case_list, self.tags, comms, []])
        self.old_comment = []
        self.case_list = []
        self.tags = {}

    def process_struct_union(self, fd, deftype, defname, deftags, defcomments):
        """Process a struct or a union

           fd:
               File descriptor for output file
           deftype:
               Definition type: either a STRUCT or UNION
           defname:
               Definition name for struct/union
           deftags:
               Tags dictionary for given object
           defcomments:
               List of comments: (inline, multi, old)
        """
        prefix = "self."
        valid_default = False

        isbitdict = self.process_bitdict(defname, deftags)

        mcommstr, incommstr = self.get_comments(defcomments, "", "", "", newobj=True)
        if len(mcommstr):
            fd.write(mcommstr)
        else:
            fd.write("\n")

        if isbitdict:
            fd.write("def %s(unpack):%s\n" % (defname, incommstr))
        else:
            # Get base classes if they exist, default is BaseObj
            inherit = deftags.get("INHERIT", "BaseObj")
            bclass_names = [x.strip().split(".").pop() for x in inherit.split(",")]
            fd.write("class %s(%s):%s\n" % (defname, ", ".join(bclass_names), incommstr))

        self.set_original_definition(fd, deftype, defname)
        self.process_fopaque()
        self.process_linkedlist(defname)
        dnames = [x[0] for x in self.item_dlist]

        # Process the XARG tag
        extra_args = ""
        xarg_list = []
        tagstr = deftags.get("XARG")
        if tagstr is not None:
            xarg_list = re.findall(r"([\w\d_]+)\s*;?\s*(\w+)?", tagstr)
            if len(xarg_list):
                extra_args = ", " + ", ".join(x[0] for x in xarg_list)

        # Split attributes given in XARG tag into the ones that will be
        # displayed (disp flag, added to _attrlist) and those that won't
        xarg_set_names = []
        xarg_nodisp_names = []
        if len(xarg_list):
            for xarg in xarg_list:
                if xarg[1] == "disp":
                    xarg_set_names.append(xarg[0])
                else:
                    xarg_nodisp_names.append(xarg[0])

        if not isbitdict:
            # Class attributes
            classattr = []

            # Process CLASSATTR
            cattrs = deftags.get("CLASSATTR")
            if cattrs is not None:
                for cattr in cattrs.split(","):
                    classattr.append(cattr.split("="))

            # Process _fattrs
            out = []
            for item in self.item_dlist:
                vname,dname,pdef,adef,clist,tag,comms,pcomms = item
                if tag.get("FLATATTR"):
                    out.append(vname)
            if len(out):
                cstr = ""
                if len(out) == 1:
                    cstr = ","
                classattr.append(["_fattrs", "(%s%s)" % (", ".join(['"%s"'%x for x in out]),cstr)])

            # Process _eqattr
            eqattr = deftags.get("EQATTR")
            if eqattr is not None:
                classattr.append(["_eqattr", '"%s"'%eqattr])

            # Process _strfmt1 and _strfmt2
            for level in (1,2):
                strfmt = self.get_strfmt(level, deftags)
                if strfmt is not None:
                    classattr.append(["_strfmt"+str(level), strfmt])

            # Process _attrlist
            if deftype == STRUCT:
                cstr = ""
                if len(dnames+xarg_set_names) == 1:
                    cstr = ","
                classattr.append(["_attrlist", "(%s%s)" % (", ".join(['"%s"'%x for x in dnames+xarg_set_names]), cstr)])

            if len(classattr):
                fd.write("    # Class attributes\n")
                mlen = len(max([x[0] for x in classattr], key=len))
                for item in classattr:
                    sps = " " * (mlen - len(item[0]))
                    if item[0] in ("_attrlist"):
                        # Wrap list into multiple lines
                        lines = textwrap.wrap(item[1], 73-mlen)
                        fd.write("    %s%s =" % (item[0], sps))
                        xsps = 1
                        for line in lines:
                            fd.write("%s%s\n" % (" "*xsps, line))
                            xsps = mlen+8
                    else:
                        fd.write("    %s%s = %s\n" % (item[0], sps, item[1]))
                fd.write("\n")

        #===========================================================
        # Create python definition of STRUCT/UNION
        #===========================================================
        if isbitdict:
            nindent = 4
            fd.write("    bitmap = bitmap4(unpack)\n")
            fd.write("    unpack.unpack_uint()  # size of opaque\n")
            fd.write("    return bitmap_dict(unpack, bitmap, %s_f)\n" % deftags.get("BITDICT"))
        elif not self.item_dlist:
            fd.write("    pass\n")
            nindent = 4
        else:
            fd.write("    def __init__(self, unpack%s):\n" % extra_args)
            nindent = 8
        indent = " " * nindent

        tindent = ""
        istry = False
        if deftags.get("TRY"):
            # Process the TRY tag
            fd.write("%stry:\n" % indent)
            nindent = 4
            tindent = " " * nindent
            istry = True

        # Get list of global names (not initialized)
        global_list = []
        globalvars = deftags.get("GLOBAL")
        if globalvars is not None:
            for item in globalvars.split(","):
                data = item.split("=")
                if len(data) == 1:
                    global_list.append(data[0])

        # Process the OBJATTR tag and just get a list of names only
        # to include these into the calculation for maxlen
        oattrlist = self.set_objattr(fd, deftags, dnames, "", namesonly=True)
        omaxlen = 0
        if oattrlist:
            omaxlen = len(max(oattrlist, key=len))

        if self.item_dlist:
            maxlen = len(max([x[0] for x in self.item_dlist]+xarg_set_names+xarg_nodisp_names+oattrlist, key=len))
            if deftype == STRUCT:
                self.set_vars(fd, deftags, dnames, indent+tindent, pre=True)

            if deftype == UNION and (xarg_set_names or xarg_nodisp_names):
                mlen = len(max(xarg_set_names+xarg_nodisp_names, key=len))
            else:
                mlen = maxlen

            for name in xarg_nodisp_names:
                # This is an XARG variable
                sps = " " * (mlen - len(name))
                valname = name
                for item in self.item_dlist:
                    vname,dname,pdef,adef,clist,tag,comms,pcomms = item
                    if name == vname:
                        valname = "%s(%s)" % (dname, name)
                        break
                fd.write("%s%sself.%s%s = %s\n" % (indent, tindent, name, sps, valname))

            if deftype == UNION:
                self.set_vars(fd, deftags, dnames, indent+tindent, pre=True)

            for name in xarg_set_names:
                # This is an XARG variable with "disp" option
                sps = " " * (mlen - len(name))
                valname = name
                for item in self.item_dlist:
                    vname,dname,pdef,adef,clist,tag,comms,pcomms = item
                    if name == vname:
                        valname = "%s(%s)" % (dname, name)
                        break
                fd.write('%s%sself.set_attr("%s", %s%s)\n' % (indent, tindent, name, sps, valname))

        #===========================================================
        # Create python definition of STRUCT/UNION for all vars
        #===========================================================
        switch_cond = "if"
        switch_var = None
        if isbitdict:
            dlist = []
        else:
            dlist = self.item_dlist

        for item in dlist:
            # Start of for loop {
            cindent = ""
            vname,dname,pdef,adef,clist,tag,comms,pcomms = item
            if dname == defname:
                # This is a linked list
                continue
            if deftype == UNION:
                sps = ""
                swstr = ", switch=True"
            else:
                sps = " " * (maxlen - len(vname))
                swstr = ""
            if switch_var is None:
                swstr = ""  # Don't use True argument for switch variable
                switch_var = vname
            if vname in xarg_set_names+xarg_nodisp_names:
                continue
            if vname in global_list:
                # This is a global reference
                continue

            # Use option usetypedef to return the same definition name except
            # for names that need to be renamed like "bool" -> "nfs_bool"
            dname,opts = self.gettype(dname, usetypedef=False)

            # Ignore opts from gettype() and just use the array def "adef"
            alist = filter(None, [adef])
            isarray = False
            if len(alist) > 1 or (len(alist) == 1 and dname not in string_list):
                # This is an array
                isarray = True

            need_if = self.set_vars(fd, tag, dnames, "", noop=True)

            need_if_fmt = False
            if tag.get("STRFMT1") is not None or tag.get("STRFMT2") is not None:
                need_if_fmt = True

            if len(clist) and (valid_default or need_if or need_if_fmt or dname != "void"):
                if len(clist) == 1:
                    if clist[0][0] == "default":
                        fd.write("%s%selse:\n" % (indent, tindent))
                    else:
                        fd.write("%s%s%s %s%s == %s:\n" % (indent, tindent, switch_cond, prefix, switch_var, clist[0][0]))
                else:
                    c_list = [x[0] for x in clist]
                    fd.write("%s%s%s %s%s in [%s]:\n" % (indent, tindent, switch_cond, prefix, switch_var, ", ".join(c_list)))
                cindent = " " * 4
                switch_cond = "elif"

            # Get the correct decoding statement for given var definition
            astr = self.getunpack(dname, alist, compound=isarray)
            if tag.get("STRHEX"):
                # This definition has a STRHEX tag -- display object in hex
                d_name,d_opts = self.gettype(dname)
                if d_name in int32_list + uint32_list:
                    objtype = "IntHex"
                elif d_name in int64_list + uint64_list:
                    objtype = "LongHex"
                else:
                    objtype = "StrHex"
                astr = "%s(%s)" % (objtype, astr)

            for comm in pcomms:
                fd.write("%s%s%s# %s\n" % (indent, tindent, cindent, comm))

            # Initial set_attr string
            if deftype == STRUCT:
                setattr_str = "%s%s%sself.%s%s = " % (tindent, cindent, indent, vname, sps)
            else:
                setattr_str = '%s%s%sself.set_attr("%s", %s' % (tindent, cindent, indent, vname, sps)
                swstr += ")"

            if self.linkedlist.get(dname) or pdef == "*":
                # Pointer to a linked list
                fd.write("%sunpack.unpack_list(%s)%s\n" % (setattr_str, dname, swstr))
            elif isarray:
                cond = False
                if len(adef):
                    regex = re.search(r"(.)(\d*)", adef)
                    if regex:
                        data = regex.groups()
                        if data[0] == "[":
                            # Fixed length array
                            astr += ", %s" % data[1]
                        elif data[0] == "<" and len(data[1]):
                            if data[1] == "1":
                                # Treat this not as an array with maxcount=1, but a conditional
                                cond = True
                            else:
                                # Variable length array
                                astr += ", maxcount=%s" % data[1]
                if cond:
                    fd.write("%sunpack.unpack_conditional(%s)%s\n" % (setattr_str, astr, swstr))
                else:
                    fd.write("%sunpack.unpack_array(%s)%s\n" % (setattr_str, astr, swstr))
            elif dname[:7] == "Unpack.":
                fd.write("%sunpack.%s()%s\n" % (setattr_str, dname[7:], swstr))
            elif dname in (int32_list + uint32_list + int64_list + uint64_list + string_list):
                fd.write("%s%s%s\n" % (setattr_str, astr, swstr))
            elif dname == "void":
                if need_if:
                    self.set_vars(fd, tag, dnames, indent+tindent+cindent)
                elif need_if_fmt:
                    pass
                elif valid_default:
                    fd.write("%s%s%spass;\n" % (indent, tindent, cindent))
            else:
                if dname == "bool":
                    # Rename "bool" definition
                    dname = "nfs_bool"
                fd.write("%s%s(unpack)%s\n" % (setattr_str, dname, swstr))

            self.set_vars(fd, deftags, dnames, indent+tindent, post=True, vname=vname)
            self.set_objattr(fd, tag, dnames, indent+tindent+cindent)
            self.set_strfmt(fd, tag, indent+tindent+cindent)
            # End of for loop }

        if deftype == UNION:
            maxlen = omaxlen
        self.set_objattr(fd, deftags, dnames, indent+tindent, maxlen=maxlen)

        if deftags.get("TRY"):
            # End try block
            fd.write("%sexcept:\n" % indent)
            fd.write("%s%spass\n" % (indent, tindent))

    def process_enum_and_const(self):
        """Process enum and constants"""
        buffer = ""
        deftype = None
        defname = None
        tagcomm = None
        enumlist = []
        constlist = []
        self.tags = {}
        self.copyright   = None
        self.modversion  = None
        self.incomment   = False
        self.description = None
        self.desc_const  = None
        for line in self.xdr_lines:
            line = self.process_comments(line)
            if tagcomm is None:
                tagcomm = self.tags.pop("COMMENT", None)
            if len(line) == 0:
                if deftype in [ENUM, BITMAP] and self.inline_comment is not None and len(self.inline_comment):
                    # Save comment
                    comms = [self.inline_comment, self.multi_comment, self.old_comment]
                    enumlist.append(["", "", comms])
                    self.old_comment = []
                # Skip empty lines
                continue

            if deftype is None:
                deftype, defname, deftags, defcomments = self.process_def(line)
                inherit = deftags.get("INHERIT")
                if inherit and len(inherit) > 1:
                    # Save inherit class names
                    for bclass in [x.strip() for x in inherit.split(",")]:
                        self.inherit_names[bclass] = 1
                copyright = deftags.get("COPYRIGHT")
                if copyright is not None:
                    self.copyright = copyright
                modversion = deftags.get("VERSION")
                if modversion is not None:
                    self.modversion = modversion
                if deftype is None:
                    regex = re.search(r"^\s*const\s+(\w+)(\s*)=(\s*)(\w+)", line)
                    if regex:
                        # Constants
                        const,sp1,sp2,value = regex.groups()
                        self.dconstants[const] = value
                        comms = [self.inline_comment, self.multi_comment, self.old_comment]
                        constlist.append([const, value, comms])
                        self.old_comment = []
                    else:
                        regex = re.search(r"^\s*typedef\s" + vardefstr, line)
                        if regex:
                            # Typedef
                            data = regex.groups()
                            self.dtypedef[data[4]] = [data[0], data[3], data[5]]
                            self.old_comment = []
                elif deftype in [ENUM, BITMAP]:
                    enumlist = []
                    # Add to list of enum definitions
                    self.enumdef_list.append(defname)
                if deftype is not None and len(constlist):
                    self.enum_data.append({"deftype":CONSTANT, "defname":None, "deftags":deftags, "defcomm":tagcomm, "enumlist":constlist})
                    self.old_comment = []
                    tagcomm = None
            elif re.search(r"^\s*};", line):
                # End of definition
                if deftype in [ENUM, BITMAP]:
                    self.enum_data.append({"deftype":deftype, "defname":defname, "deftags":deftags, "defcomm":tagcomm, "enumlist":enumlist})
                    tagcomm = None
                deftype = None
                constlist = []
                self.old_comment = []
            elif deftype in [ENUM, BITMAP]:
                regex = re.search(r"^\s*([\w\-]+)\s*=\s*([^,;\s]+),?.*", line)
                ename  = regex.group(1).strip()
                evalue = regex.group(2).strip()
                comms = [self.inline_comment, self.multi_comment, self.old_comment]
                enumlist.append([ename, evalue, comms])
                self.old_comment = []
                if deftype == ENUM:
                    self.dconstants[ename] = evalue

        # Save enum and constants to *_const.py file
        if self.enum_data:
            print "  Creating file %s" % self.cfile
            fd = open(self.cfile, "w")
            self.set_copyright(fd)
            fd.write(self.genstr)
            if self.desc_const:
                fd.write(self.desc_const)
            else:
                sname = re.sub(r"(\d)", r"v\1", self.bname.upper())
                fd.write('"""\n%s constants module\n"""\n' % sname)

            if self.modversion is not None:
                fd.write("import nfstest_config as c\n")
                self.set_modconst(fd)

            # Save enums
            for enum_item in self.enum_data:
                deftype  = enum_item["deftype"]
                defname  = enum_item["defname"]
                deftags  = enum_item["deftags"]
                defcomm  = enum_item["defcomm"]
                enumlist = enum_item["enumlist"]
                if defname is not None and deftags.get("FMAP"):
                    self.fmap_data[defname] = enum_item

                if defname == "bool":
                    # Rename "bool" definition
                    defname = "nfs_bool"

                if defcomm is not None:
                    fd.write("\n# %s\n" % defcomm)

                name_maxlen  = len(max([x[0] for x in enumlist], key=len))
                value_maxlen = len(max([x[1] for x in enumlist], key=len))
                self.fix_comments(enumlist, 2)
                if deftype == ENUM:
                    fd.write("\n# Enum %s\n" % defname)
                    # Save enums constant definitions
                    for item in enumlist:
                        out = ""
                        spnam = " " * (value_maxlen - len(item[1]))
                        if len(item[0]):
                            sps = " " * (name_maxlen - len(item[0]))
                            out = "%s%s = %s" % (item[0].replace("-", "_"), sps, item[1])
                        mcommstr, incommstr = self.get_comments(item[2], out, spnam, "")
                        if len(mcommstr):
                            fd.write(mcommstr)
                        fd.write("%s%s\n" % (out, incommstr))

                    # Save enums dictionary definition
                    fd.write("\n%s = {\n" % defname)
                    for item in enumlist:
                        if item[0] == "":
                            continue
                        sps = " " * (value_maxlen - len(item[1]))
                        fd.write('    %s%s : "%s",\n' % (sps, item[1], item[0]))
                    fd.write("}\n")
                elif deftype == BITMAP:
                    # BITMAP
                    fd.write("\n# Bitmap %s\n" % defname)
                    fd.write("%s = {\n" % defname)
                    for item in enumlist:
                        sps = " " * (name_maxlen - len(item[0]))
                        fd.write("    %s%s : %s,\n" % (sps, item[0], item[1]))
                    fd.write("}\n")
                elif deftype == CONSTANT:
                    # CONSTANT
                    first_item = True
                    for item in enumlist:
                        out = ""
                        spnam = " " * (value_maxlen - len(item[1]))
                        if len(item[0]):
                            sps = " " * (name_maxlen - len(item[0]))
                            out = "%s%s = %s" % (item[0], sps, item[1])
                        mcommstr, incommstr = self.get_comments(item[2], out, spnam, "")
                        if len(mcommstr):
                            fd.write(mcommstr)
                        elif first_item:
                            fd.write("\n")
                        fd.write("%s%s\n" % (out, incommstr))
                        first_item = False
            fd.close()

    def process_xdr(self):
        """Process XDR definitions"""
        print "  Creating file %s" % self.pfile
        fd = open(self.pfile, "w")
        self.set_copyright(fd)
        fd.write(self.genstr)
        if self.description:
            fd.write(self.description)
        else:
            sname = re.sub(r"(\d)", r"v\1", self.bname.upper())
            fd.write('"""\n%s decoding module\n"""\n' % sname)
        import_list = []
        import_dict = {
            "packet.utils":  ["*"],
            "baseobj":       ["BaseObj"],
            "packet.unpack": ["Unpack"],
        }

        for inherit in self.inherit_names:
            data = inherit.split(".")
            objdef = data.pop()
            objpath = ".".join(data)
            if len(objpath) > 0:
                if not import_dict.get(objpath):
                    import_dict[objpath] = []
                import_dict[objpath].append(objdef)

        if self.modversion is not None:
            import_list.append("import nfstest_config as c\n")
        if self.enum_data:
            import_list.append("import %s_const as const\n" % self.bname)

        for objpath in import_dict:
            import_str = "from %s import %s\n" % (objpath, ", ".join(import_dict[objpath]))
            import_list.append(import_str)

        for line in sorted(import_list, key=len):
            fd.write(line)

        self.set_modconst(fd)

        self.item_dlist = []
        self.linkedlist = {}
        self.tags = {}
        deftype = None
        defname = None
        deftags = {}
        defcomments = []
        need_newline = False
        self.copyright = None
        self.incomment = False
        self.description = None
        self.desc_const  = None
        for line in self.xdr_lines:
            line = self.process_comments(line)

            tagcomm = self.tags.pop("COMMENT", None)
            if tagcomm is not None:
                fd.write("\n# %s\n" % tagcomm)
                continue

            if len(line) == 0:
                continue

            if deftype is None:
                deftype, defname, deftags, defcomments = self.process_def(line)
                # Process CLASSATTR
                classattr = []
                cattrs = deftags.get("CLASSATTR")
                if cattrs is not None:
                    for cattr in cattrs.split(","):
                        classattr.append(cattr.split("="))
                if deftype is None:
                    regex = re.search(r"^\s*typedef\s" + vardefstr, line)
                    if regex:
                        # Typedef
                        data = regex.groups()
                        defcomments = [self.inline_comment, self.multi_comment, self.old_comment]
                        self.old_comment = []
                        self.typedef_list.append([data[4], data[0], data[5], self.tags, defcomments])
                        self.tags = {}
                    else:
                        # Constants
                        regex = re.search(r"^\s*const\s+(\w+)(\s*)=(\s*)(\w+)", line)
                        if regex:
                            self.old_comment = []
                            self.tags = {}
                elif len(self.typedef_list):
                    maxlen = len(max([x[0] for x in self.typedef_list], key=len))
                    first_entry = True
                    for item in self.typedef_list:
                        mcommstr, incommstr = self.get_comments(item[4], "", "", "")
                        if need_newline and len(mcommstr) and mcommstr[0] != "\n":
                            fd.write("\n")
                        if len(mcommstr):
                            fd.write(mcommstr)
                        elif first_entry:
                            fd.write("\n")
                        first_entry = False
                        need_newline = False

                        func = ""
                        if item[3].get("BITMAP"):
                            # This typedef has a BITMAP tag -- use unpack_bitmap() to decode
                            self.bitmap_defs.append(item[0])
                            dname,opts = self.gettype(item[1])
                            if len(item[3]) == 1:
                                # This is the only tag
                                func = "Unpack.unpack_bitmap"
                            elif item[3].get("BITMAP"):
                                func = "unpack.unpack_bitmap"

                        if item[3].get("INHERIT"):
                            # Process the following: typedef baseclass newclass;
                            # Create class inheriting from the typdedef baseclass
                            # so the str version of the class has the name of
                            # the new class instead of the base class
                            fd.write("class %s(%s): pass\n" % (item[0], item[1]))
                            continue
                        elif item[3].get("BITMAPOBJ"):
                            func = "lambda unpack: Bitmap(unpack, %s)" % item[3]["BITMAPOBJ"]
                        elif item[3].get("STRHEX"):
                            # This typedef has a STRHEX tag -- display object in hex
                            if len(func) > 0:
                                # This item has a BITMAP tag as well
                                dname = func
                                item[2] = ""
                            else:
                                dname,opts = self.gettype(item[1])
                            if dname in int32_list + uint32_list:
                                objtype = "IntHex"
                            elif dname in int64_list + uint64_list + ["unpack.unpack_bitmap"]:
                                objtype = "LongHex"
                            else:
                                objtype = "StrHex"
                            astr = self.getunpack(dname, [item[2]])
                            func = "lambda unpack: %s(%s)" % (objtype, astr)
                        elif len(func) == 0:
                            func = self.getunpack(item[1], [item[2]], typedef=True)

                        sps = " " * (maxlen - len(item[0]))
                        fd.write("%s%s = %s%s\n" % (item[0], sps, func, incommstr))
                    self.typedef_list = []
                if deftype == ENUM and defname is not None:
                    if defname == "bool":
                        # Rename "bool" definition
                        defname = "nfs_bool"
                    objdesc = '    """enum %s"""' % defname
                    out = "class %s(Enum):\n%s" % (defname, objdesc)
                    classattr.append(["_enumdict", "const.%s" % defname])
                    lmax = max([len(x[0]) for x in classattr])
                    for cattr in classattr:
                        out += "\n    %-*s = %s" % (lmax, cattr[0], cattr[1])
                    mcommstr, incommstr = self.get_comments(defcomments, out, "", "", newobj=True)
                    if len(mcommstr):
                        fd.write(mcommstr)
                    else:
                        fd.write("\n")
                    fd.write("%s%s\n" % (out, incommstr))
                    need_newline = True

                    enum_item = self.fmap_data.get(defname)
                    if enum_item is not None:
                        # Process FMAP
                        deftype  = enum_item["deftype"]
                        defname  = enum_item["defname"]
                        deftags  = enum_item["deftags"]
                        defcomm  = enum_item["defcomm"]
                        enumlist = enum_item["enumlist"]

                        # Save enums dictionary definition
                        fd.write("\n%s_f = {\n" % defname)

                        value_maxlen = len(max([x[1] for x in enumlist], key=len))
                        for item in enumlist:
                            if item[0] == "":
                                continue
                            sps = " " * (value_maxlen - len(item[1]))
                            out = "    %s%s : %s," % (sps, item[1], item[0].lower())
                            mcommstr, incommstr = self.get_comments(item[2], out, sps, "    "+sps)
                            if len(mcommstr):
                                fd.write(mcommstr)
                            fd.write("%s%s\n" % (out, incommstr))
                        fd.write("}\n")
            elif re.search(r"^\s*};", line):
                # End of definition
                if deftype in (STRUCT, UNION):
                    self.process_struct_union(fd, deftype, defname, deftags, defcomments)

                # Reset all variables
                deftype = None
                self.reset_defvars()
            elif deftype == UNION:
                # Process all lines inside a union
                regex = re.search(r"^\s*case\s+(\w+)\s*:\s*(.*)", line)
                if regex:
                    # CASE line
                    case_val = regex.group(1).strip()
                    if self.dconstants.get(case_val) is not None:
                        case_val = "const." + case_val
                    comms = [self.inline_comment, self.multi_comment, self.old_comment]
                    self.case_list.append([case_val, comms])
                    self.old_comment = []
                    if len(regex.group(2)) > 0:
                        # Process in-line case
                        #   case NFS4_OK: READ4resok resok4;
                        self.inline_comment = ""
                        self.multi_comment = []
                        self.process_union_var(regex.group(2))
                else:
                    regex = re.search(r"^\s*default:", line)
                    if regex:
                        # DEFAULT line
                        comms = [self.inline_comment, self.multi_comment, self.old_comment]
                        self.case_list.append(["default", comms])
                        self.old_comment = []
                    else:
                        # Union variable
                        self.process_union_var(line)
            elif deftype == STRUCT:
                # Process all lines inside a structure
                regex = re.search(vardefstr, line)
                if regex:
                    data = regex.groups()
                    comms = [self.inline_comment, self.multi_comment, list(self.old_comment)]
                    self.item_dlist.append([data[4], data[0], data[3], data[5], [], self.tags, comms, []])
                    self.old_comment = []
                    self.tags = {}

        fd.close()

#===============================================================================
# Entry point
#===============================================================================
# Setup options to parse in the command line
opts = OptionParser(USAGE, formatter = IndentedHelpFormatter(2, 25), version = "%prog " + __version__)
# Run parse_args to get options and process dependencies
vopts, args = opts.parse_args()
if len(args) < 1:
    opts.error("XDR definition file is required")

for xdrfile in args:
    print "Process XDR file %s" % xdrfile
    XDRobject(xdrfile)
