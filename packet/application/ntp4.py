#===============================================================================
# Copyright 2016 NetApp, Inc. All Rights Reserved,
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
NTP module

Decode NTP layer.

RFC 1059 Network Time Protocol (Version 1)
RFC 1119 Network Time Protocol (Version 2)
RFC 1305 Network Time Protocol (Version 3)
RFC 5905 Network Time Protocol (Version 4)
"""
import nfstest_config as c
from packet.utils import *
from baseobj import BaseObj

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2016 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

UINT16     = 0xffff
UINT32     = 0xffffffff
UNIX_EPOCH = 2208988800

class ntp4_mode(Enum):
    """enum ntp4_mode"""
    _enumdict = {1 : "sym_active", 2 : "sym_passive", 3 : "client",
                 4 : "server",     5 : "broadcast",   6 : "NTP_cntl"}

class NTPExtField(BaseObj):
    """NTP extension field"""
    # Class attributes
    _attrlist = ("ftype", "length", "value")

    def __init__(self, unpack):
        """Constructor which takes the Unpack object as input"""
        ulist = unpack.unpack(4, "!HH")
        self.ftype  = ulist[0]
        self.length = ulist[1]
        self.value  = unpack.read(self.length-4)

class NTP_TimeStamp(DateStr):
    """NTP timestamp"""
    _strfmt = "{0:date:%Y-%m-%d %H:%M:%S.%q}"

def ntp_timestamp(unpack):
    """Get NTP timestamp"""
    secs, fraction = unpack.unpack(8, "!II")
    if secs > 0:
        secs = secs - UNIX_EPOCH
    secs += float(fraction)/UINT32
    return NTP_TimeStamp(secs)

class NTP4(BaseObj):
    """NTP4 object

       Usage:
           from packet.application.ntp4 import NTP4

           # Decode NTP4 layer
           x = NTP4(pktt)

       Object definition:

       NTP4(
           leap       = int,    # Leap Indicator
           version    = int,    # NTP version
           mode       = int,    # Leap Indicator
           stratum    = int,    # Packet Stratum
           poll       = int,    # Maximum interval between successive messages
           precision  = float,  # Precision of system clock
           delay      = float,  # Root delay
           dispersion = float,  # Root dispersion
           refid      = string, # Reference ID
           tstamp     = float,  # Reference timestamp
           org_tstamp = float,  # Origin timestamp
           rec_tstamp = float,  # Receive timestamp
           xmt_tstamp = float,  # Transit timestamp
           fields     = list,   # Extension fields
           keyid      = int,    # Key identifier
           digest     = string, # Message digest
       )
    """
    # Class attributes
    _strfmt1  = "NTP{1} {2} {12}"
    _attrlist = ("leap", "version", "mode", "stratum", "poll", "precision",
                 "delay", "dispersion", "refid", "tstamp", "org_tstamp",
                 "rec_tstamp", "xmt_tstamp", "fields", "keyid", "digest")

    def __init__(self, pktt):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
        """
        unpack = pktt.unpack
        ulist = unpack.unpack(16, "!BBbbHHHH4s")
        self.leap       = (ulist[0]>>6)&0x3
        self.version    = (ulist[0]>>3)&0x7
        self.mode       = ntp4_mode(ulist[0]&0x7)
        self.stratum    = ulist[1]
        self.poll       = 2**ulist[2]
        self.precision  = 2**ulist[3]
        self.delay      = ulist[4] + float(ulist[5])/UINT16
        self.dispersion = ulist[6] + float(ulist[7])/UINT16
        self.refid      = ulist[8]
        self.tstamp     = ntp_timestamp(unpack)
        self.org_tstamp = ntp_timestamp(unpack)
        self.rec_tstamp = ntp_timestamp(unpack)
        self.xmt_tstamp = ntp_timestamp(unpack)
        self.fields     = []
        self.keyid      = 0
        self.digest     = ""

        if self.version == 4:
            # Only NTP version 4 has extension fields
            while len(unpack) > 24:
                self.fields.append(NTPExtField(unpack))

        if self.version == 4 and len(unpack) == 20:
            # Digest is 16 bytes for NTP version 4
            self.keyid, self.digest = unpack.unpack(20, "!I16s")
        elif self.version in [2,3] and len(unpack) == 12:
            # Digest is 8 bytes for NTP version 2 and 3
            self.keyid, self.digest = unpack.unpack(12, "!I8s")

class NTP3(NTP4): pass
class NTP2(NTP4): pass
class NTP1(NTP4): pass

def NTP(pktt):
    """Wrapper function to select correct NTP object"""
    unpack = pktt.unpack
    # Check NTP version without consuming any bytes from the Unpack object
    offset = unpack.tell()
    tmp = unpack.unpack(1, "!B")[0]
    unpack.seek(offset)
    version = (tmp>>3)&0x7
    if version == 4:
        return NTP4(pktt)
    elif version == 3:
        return NTP3(pktt)
    elif version == 2:
        return NTP2(pktt)
    elif version == 1:
        return NTP1(pktt)
