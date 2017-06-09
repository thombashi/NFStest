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
"""
Pktt utilities module

The Packet trace utilities module has classes which augment functionality
of basic data types like displaying integers as their hex equivalent.
It also includes an Enum base class which displays the integer as its
string representation given by a mapping dictionary. There is also a
class to be used as a base class for an RPC payload object.
This module also includes some module variables to change how certain
objects are displayed.
"""
import nfstest_config as c
from baseobj import BaseObj, fstrobj

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2014 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.3"

# RPC type constants
RPC_CALL  = 0
RPC_REPLY = 1
rpc_type = {RPC_CALL:'call', RPC_REPLY:'reply'}

# Module variables that change the way an RPC packet is displayed
RPC_type = True  # Display RPC type, e.g., call or reply
RPC_load = True  # Display RPC load name, e.g., NFS, etc.
RPC_ver  = True  # Display RPC load version, e.g., v3, v4, etc.
RPC_xid  = True  # Display RPC xid

# Module variables that change the way an RPC payload is displayed
NFS_mainop = False # Display only the main operation in an NFS COMPOUND
LOAD_body  = True  # Display the body of layer/procedure/operation

# Module variables for Enum
ENUM_CHECK = False

class ShortHex(int):
    """Short integer object which is displayed in hex"""
    def __str__(self):
        return "0x%04x" % self
    __repr__ = __str__

class IntHex(int):
    """Integer object which is displayed in hex"""
    def __str__(self):
        return "0x%08x" % self
    __repr__ = __str__

class LongHex(long):
    """Long integer object which is displayed in hex"""
    def __str__(self):
        return "0x%016x" % self
    __repr__ = __str__

class DateStr(float):
    """Floating point object which is displayed as a date"""
    _strfmt = "{0:date}"
    def __str__(self):
        return repr(fstrobj.format(self._strfmt, self))

class StrHex(str):
    """String object which is displayed in hex"""
    def __str__(self):
        return "0x" + self.encode("hex")

class EnumInval(Exception):
    """Exception for an invalid enum value"""
    pass

class Enum(int):
    """Enum base object
       This should only be used as a base class where the class attributes
       should be initialized
    """
    _offset = 0    # Strip the first bytes from the string name after conversion
    _enumdict = {} # Enum mapping dictionary to convert integer to string name

    def __new__(cls, unpack):
        """Constructor which checks if integer is a valid enum value"""
        if isinstance(unpack, int):
            # Value is given as an integer
            value = unpack
        else:
            # Unpack integer
            value = unpack.unpack_int()
        # Instantiate base class (integer class)
        obj = super(Enum, cls).__new__(cls, value)
        if ENUM_CHECK and obj._enumdict.get(value) is None:
            raise EnumInval, "value=%s not in enum '%s'" % (value, obj.__class__.__name__)
        return obj

    def __str__(self):
        """Informal string representation, display value using the mapping
           dictionary provided as a class attribute
        """
        value = self._enumdict.get(self)
        if value is None:
            return super(Enum, self).__str__()
        else:
            return value[self._offset:]

class BitmapInval(Exception):
    """Exception for an invalid bit number"""
    pass

def bitmap_dict(unpack, bitmap, func_map, name_map=None):
    """Returns a dictionary where the key is the bit number given by bitmap
       and the value is the decoded value by evaluating the function used
       for that specific bit number

       unpack:
           Unpack object
       bitmap:
           Unsigned integer where a value must be decoded for every bit that
           is set, starting from the least significant bit
       func_map:
           Dictionary which maps a bit number to the function to be used for
           decoding the value for that bit number. The function must have
           the "unpack" object as the only argument
       name_map:
           Dictionary which maps a bit number to a bit name. If this is given
           the resulting dictionary will have a bit name for a key instead
           of the bit number
    """
    ret = {}
    bitnum = 0
    while bitmap > 0:
        # Check if bit is set
        if bitmap & 0x01 == 1:
            # Get decoding function for this bit number
            func = func_map.get(bitnum)
            if func is None:
                raise BitmapInval, "decoding function not found for bit number %d" % bitnum
            else:
                if name_map:
                    # Use the bit number name instead of the bit number
                    # for the key
                    ret[name_map.get(bitnum, bitnum)] = func(unpack)
                else:
                    ret[bitnum] = func(unpack)
        bitmap = bitmap >> 1
        bitnum += 1
    return ret

class OptionFlags(BaseObj):
    """OptionFlags base object

       This base class is used to have a set of raw flags represented by an
       integer and splits every bit into an object attribute according to the
       class attribute _bitnames where the key is the bit number and the value
       is the attribute name.

       This should only be used as a base class where the class attribute
       _bitnames should be initialized. The class attribute _reversed can
       also be initialized to reverse the _bitnames so the first bit becomes
       the last, e.g., _reversed = 31, bits are reversed on a 32 bit integer
       so 0 becomes 31, 1 becomes 30, etc.

       Usage:
           from packet.utils import OptionFlags

           class MyFlags(OptionFlags):
               _bitnames = {0:"bit0", 1:"bit1", 2:"bit2", 3:"bit3"}

           x = MyFlags(10) # 10 = 0b1010

           The attributes of object are:
               x.rawflags = 10, # Original raw flags
               x.bit0     = 0,
               x.bit1     = 1,
               x.bit2     = 0,
               x.bit3     = 1,
    """
    _strfmt1  = "{0}"
    _strfmt2  = "{0}"
    _rawfunc  = IntHex # Raw flags object modifier
    _attrlist = ("rawflags",)
    # Dictionary where key is bit number and value is attribute name
    _bitnames = {}
    # Bit numbers are reversed if > 0, this is the max number of bits in flags
    # if set to 31, bits are reversed on a 32 bit integer (0 becomes 31, etc.)
    _reversed = 0

    def __init__(self, options):
        """Initialize object's private data.

           options:
               Unsigned integer of raw flags
        """
        self.rawflags = self._rawfunc(options) # Raw option flags
        bitnames = self._bitnames
        for bit,name in bitnames.items():
            if self._reversed > 0:
                # Bit numbers are reversed
                bit = self._reversed - bit
            setattr(self, name, (options >> bit) & 0x01)
        # Get attribute list sorted by its bit number
        self._attrlist += tuple(bitnames[k] for k in sorted(bitnames))

    def str_flags(self):
        """Display the flag names which are set, e.g., in the above example
           the output will be "bit1,bit3" (bit1=1, bit3=1)
           Use "__str__ = OptionFlags.str_flags" to have it as the default
           string representation
        """
        ulist = []
        bitnames = self._bitnames
        for bit in sorted(bitnames):
            if self._reversed > 0:
                # Bit numbers are reversed
                bit = self._reversed - bit
            if (self.rawflags >> bit) & 0x01:
                ulist.append(bitnames[bit])
        return ",".join(ulist)

class RPCload(BaseObj):
    """RPC load base object
       This is used as a base class for an RPC payload object
    """
    # Class attributes
    _pindex  = 0    # Discard this number of characters from the procedure name
    _strname = None # Name to display in object's debug representation level=1

    def rpc_str(self, name=None):
        """Display RPC string"""
        out = ""
        rpc = self._rpc
        if name is None:
            self._strname = self.__class__.__name__
            name = self._strname
        if RPC_load:
            out += "%-5s " % name
        if RPC_ver:
            mvstr = ""
            minorversion = getattr(self, 'minorversion', 0)
            if minorversion > 0:
                mvstr = ".%d" % minorversion
            vers = "v%d%s" % (rpc.version, mvstr)
            out += "%-4s " % vers
        if RPC_type:
            out += "%-5s " % rpc_type.get(rpc.type)
        if RPC_xid:
            out += "xid:0x%08x " % rpc.xid
        return out

    def __str__(self):
        """Informal string representation"""
        rdebug = self.debug_repr()
        if rdebug == 1:
            out = self.rpc_str(self._strname)
            out += "%-10s" % str(self.procedure)[self._pindex:]
            if LOAD_body and getattr(self, "switch", None) is not None:
                itemstr = str(self.switch)
                if len(itemstr):
                    out += " " + itemstr

            rpc = self._rpc
            if rpc.type and getattr(self, "status", 0) != 0:
                # Display the status of the packet only if it is an error
                out += " %s" % self.status
            return out
        else:
            return BaseObj.__str__(self)
