#===============================================================================
# Copyright 2015 NetApp, Inc. All Rights Reserved,
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
DER decoding module

Decode using ASN.1 DER (Distinguished Encoding Representation)
ASN.1: Abstract Syntax Notation 1

This module does not completely decode all DER data types,
the following is a list of supported data types in this implementation:
    INTEGER,
    BIT_STRING,
    NULL,
    OBJECT_IDENTIFIER,
    GeneralizedTime,
    Strings (OCTET STRING, PrintableString, etc.)
    SEQUENCE OF,
    SEQUENCE,
"""
import re
import time
import struct
import nfstest_config as c
from packet.unpack import Unpack

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2015 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

# DER types
EOC               = 0x00  # End-of-content
BOOLEAN           = 0x01  # Boolean
INTEGER           = 0x02
BIT_STRING        = 0x03  # Bit string
OCTET_STRING      = 0x04  # Octet string
NULL              = 0x05
OBJECT_IDENTIFIER = 0x06  # Object identifier
OBJECT_DESCRIPTOR = 0x07  # Object descriptor
EXTERNAL          = 0x08  # External
REAL              = 0x09  # Floating point number
ENUMERATED        = 0x0a  # Enumerated
EMBEDDED_PDV      = 0x0b  # Embedded PDV
UTF8String        = 0x0c  # UTF8 string
RELATIVE_OID      = 0x0d  # Relative OID
NumericString     = 0x12  # Numeric string
PrintableString   = 0x13  # Printable string
T61String         = 0x14  # T61 string
VideotexString    = 0x15  # Videotex string
IA5String         = 0x16  # IA5 string
UTCTime           = 0x17  # UTC time
GeneralizedTime   = 0x18  # Generalized time
GraphicString     = 0x19  # Graphic string
VisibleString     = 0x1a  # Visible string
GeneralString     = 0x1b  # General string
UniversalString   = 0x1c  # Universal string
CharacterString   = 0x1d  # Character string
BMPString	  = 0x1e  # Unicode string
# DER CONSTRUCTED types
SEQUENCE          = 0x10  # Ordered list of one or more items of different types
SEQUENCE_OF       = 0x10  # Ordered list of one or more items of the same type
SET               = 0x11  # Unordered list of one or more types
SET_OF            = 0x11  # Unordered list of the same types

# ASN.1 form
PRIMITIVE   = 0
CONSTRUCTED = 1

# ASN.1 tagging class
UNIVERSAL   = 0
APPLICATION = 1
CONTEXT     = 2
PRIVATE     = 3

class DERunpack(Unpack):
    """DER unpack object

       Usage:
           from packet.derunpack import DERunpack

           x = DERunpack(buffer)

           # Get the decoded object structure for the stream bytes in buffer
           obj = x.get_item()

           Where obj is of the form:
               obj = {
                   application = {
                       context-tag0 = int|list|dictionary,
                       context-tag1 = int|list|dictionary,
                       ...
                       context-tagN = int|list|dictionary,
                   }
               }

           Example:
             For the following ASN.1 definition:
               TEST ::= [APPLICATION 10] SEQUENCE {
                   id       [0] INTEGER,
                   numbers  [1] SEQUENCE OF INTEGER,
                   data     [2] SEQUENCE {
                       -- NOTE: first tag is [1], not [0]
                       type   [1] INTEGER,
                       value  [2] PrintableString,
                   },
               }

             Using the streamed bytes of the above ASN.1 definition,
             the following is returned by get_item():
               obj = {
                   10 = {              # Application 10
                       0: 53,          # id: context-tag=0, value=53
                       1: [1,2,3],     # numbers: context-tag=1, value=[1,2,3]
                       2: {            # data: context-tag=1, value=structure
                           1: 2,       # id: context-tag=1, value=2
                           2: "test",  # id: context-tag=2, value="test"
                       }
                   }
               }
    """
    def get_tag(self):
        """Get the tag along with the tag class and form or P/C bit

           The first byte(s) of the TLV (Type, Length, Value) is the type
           which has the following format:
             First byte:
               bits 8-7: tag class
               bit 6:    form or P/C (Constructed if bit is set)
               bits 5-1: tag number (0-30)
                         if all bits are 1's (decimal 31) then one or more
                         bytes are required for the tag

             If bits 5-1 are all 1's in the first byte, the tag is given
             in the following bytes:
             Extra byes for tag:
               bit 8:    next byte is part of tag
               bits 7-1: tag bits

           Examples:
             0xa1 (0b10100001): Short form
               tag class: 0b10 = 2 (CONTEXT)
               P/C:       0b0  = 0 (not constructed)

             0x1f8107 (0b000111111000000100000111): Long form
               tag class: 0b00 = 0 (UNIVERSAL -- standard tag)
               P/C:       0b0  = 0 (not constructed)
               tag:   0b11111 = 31 (tag is given in following bytes)
               First extra byte: 0x81 (0b10000001)
                 bit8=1  : there is an extra byte after this
                 bits 7-1: 0b0000001 (0x01 most significant 7 bits of tag)
               Second extra byte: 0x07 (0b00000111)
                 bit8=1  : this is the last byte
                 bits 7-1: 0b0000111 (0x07 least significant 7 bits of tag)
               Tag number: big-endian bits from extra bytes (7 bits each)
                          14 bits: 0x0087 (0x01 << 7 + 0x07) = 135
        """
        tag = self.unpack_uchar()
        self.tclass = tag >> 6
        self.form   = (tag >> 5) & 0x01
        self.tag    = tag & 0x1f
        if tag & 0x1f == 0x1f:
            # Tag is given in the following octets where MSB is set if there
            # is another byte (MSB is 0 for last byte) and the tag number
            # is given by concatenating the 7-bits of all octets
            tag = 0x80
            self.tag = 0
            while tag & 0x80:
                tag = self.unpack_uchar()
                self.tag = (self.tag << 7) + (tag & 0x7f)
        return self.tag

    def get_size(self):
        """Get the size of element (length in TLV)

           Short form: bit8=0, one octet, length given by bits 7-1 (0-127)
           Long form:  bit8=1, 2-127 octet, bits 7-1 give number of length
                       objects

           Example:
             Short form (bit8=0):
               0x0f (0b00001111): length is 0x0f (15)
             Long form (bit8=1 of first byte):
               0x820123 (0b100000100000000100100011):
               length is given by the next 2 bytes (first 7-1 bits 0x02)
               Next two bytes gives the length 0x0123 = 291
        """
        size = self.unpack_uchar()
        if size & 0x80:
            # Long form, get the number of octets for length
            count = size & 0x7f
            # Get length from an unsigned integer of "count" octets
            size = self.der_integer(count, True)
        return size

    def der_integer(self, size=None, unsigned=False):
        """Return an integer given the size of the integer in bytes

           size:
               Number of bytes for the integer, if this option is not given
               the method get_size() is used to get the size of the integer
           unsigned:
               Usually an unsigned integer is encoded with a leading byte
               of all zeros but when decoding data of BIT_STRING type all
               decoded bytes must be unsigned so they can be concatenated
               correctly
        """
        ret = None
        if size is None:
            # If size is not given, get it from the byte stream
            size = self.get_size()
        ret  = 0
        hbit = 0
        for i in range(size):
            byte = self.unpack_uchar()
            if i == 0:
                # Get the most significant bit from the first byte in order
                # to know if this integer is a negative number
                ret = byte
                hbit = byte >> 7
            else:
                ret = (ret << 8) + byte
        if not unsigned and hbit:
            # Convert it to a negative number (two's complement) only if the
            # unsigned option is not given and the most significant bit is set
            ret -= (1<<(8*size))
        return ret

    def der_date(self, size):
        """Return a date time of type GeneralizedTime
           Type GeneralizedTime takes values of the year, month, day, hour,
           minute, second, and second fraction in any of following three forms:

           Local time: "YYYYMMDDHH[MM[SS[.fff]]]"
           Universal time (UTC): "YYYYMMDDHH[MM[SS[.fff]]]Z"
           Difference between local and UTC times" "YYYYMMDDHH[MM[SS[.fff]]]+|-HHMM".

           Where the optional fff is accurate to three decimal places
        """
        data = re.search(r"(\d+)(.(\d+))?(Z?)(([\+\-])(\d\d)(\d\d))?", self.read(size)).groups()
        datestr = data[0]
        if len(datestr) == 14:
            fmt = "%Y%m%d%H%M%S"
        elif len(datestr) == 12:
            fmt = "%Y%m%d%H%M"
        else:
            fmt = "%Y%m%d%H"
        # Local time structure
        ret = time.strptime(datestr, fmt)
        # Convert it to seconds from epoch in current timezone
        utctime = time.mktime(ret)

        tday = 0
        if time.daylight:
            # An hour difference if daylight savings time
            tday = 3600

        if data[3] == "Z":
            # Convert it to UTC including daylight savings time
            utctime -= time.timezone - tday
        elif data[6] is not None and data[7] is not None:
            # Convert it to UTC including daylight savings time
            tz = 3600*eval(data[6]) + 60*eval(data[7])
            if data[5] == "-":
                tz = -tz
            utctime -= tz + time.timezone - tday
        if data[2] is not None:
            # Add the fraction
            slen = len(data[2])
            utctime += int(data[2])/float(10**slen)
        return utctime

    def der_oid(self, size):
        """Return an object identifier (OID)"""
        out = 0
        clist = struct.unpack("!%dB"%size, self.read(size))
        # First byte has the first two nodes
        ret = [str(clist[0]/40), str(clist[0]%40)]
        for item in clist[1:]:
            if item & 0x80:
                # Current node has more bytes
                out = (out << 7) + (item & 0x7f)
            else:
                if out > 0:
                    # This is the last byte for multi-byte node
                    item = (out << 7) + (item & 0x7f)
                ret.append(str(item))
                # Reset multi-byte node
                out = 0
        return ".".join(ret)

    def get_item(self, oid=None):
        """Get item from the byte stream using TLV
           This is a recursive function where the tag and length are decoded
           and then this function is called to get the value if tag is one of
           primitive or non-constructed types.

           Calling this method right after instantiation of the object will
           decode the whole ASN.1 representation
        """
        ret = None
        tagidx = 0
        # Get the Tag
        tag = self.get_tag()
        # Save tag class and P/C
        tclass = self.tclass
        form   = self.form
        # Get the Length
        size = self.get_size()
        if size > len(self):
            # Not enough bytes
            return

        # Get the Value
        if self.tclass in (APPLICATION, CONTEXT) or \
          (self.tclass == UNIVERSAL and self.form == CONSTRUCTED):
            ret = {}
            offset = self.tell()
            while self.tell() - offset < size:
                item = self.get_item()
                if tclass in (APPLICATION, CONTEXT):
                    # Current item (ret) is an Application or Context
                    if tagidx == 1:
                        # Application has more than one item so use implicit
                        # tag numbering
                        ret[tag] = {0:ret[tag], 1:item}
                    elif tagidx > 1:
                        ret[tag][tagidx] = item
                    else:
                        if self.tag == OBJECT_IDENTIFIER and oid is not None and oid == item:
                            ret[tag] = {tagidx:item}
                            break
                        else:
                            ret[tag] = item
                elif self.tclass == CONTEXT:
                    # The item (item) has a Context tag
                    key, value = item.items()[0]
                    ret[key] = value
                else:
                    # Current item (ret) and item have no context tag so this
                    # is a list of simple types (SEQUENCE OF int|string...)
                    # If ret has any items they will be deleted but this should
                    # never happen because all items must have a context tag
                    if isinstance(ret, dict):
                        ret = []
                    ret.append(item)
                if tclass == APPLICATION:
                    tagidx += 1
        elif self.tclass == UNIVERSAL:
            if self.tag == INTEGER:
                ret = self.der_integer(size)
            elif self.tag == BIT_STRING:
                # The first octet in value gives the number of unused bits
                nbits = self.unpack_uchar()
                ret = self.der_integer(size-1, unsigned=True) >> nbits
            elif self.tag == NULL:
                ret = None
            elif self.tag == GeneralizedTime:
                ret = self.der_date(size)
            elif self.tag == OBJECT_IDENTIFIER:
                ret = self.der_oid(size)
            else:
                ret = self.read(size)
        else:
            ret = self.read(size)

        # Restore original tag, tag class and P/C since this method is
        # recursive and a call to get_item() again will modify these values
        self.tag    = tag
        self.form   = form
        self.tclass = tclass
        return ret
