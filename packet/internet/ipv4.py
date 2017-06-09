#===============================================================================
# Copyright 2012 NetApp, Inc. All Rights Reserved,
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
IPv4 module

Decode IP version 4 layer.
"""
import struct
import nfstest_config as c
from baseobj import BaseObj
from packet.utils import ShortHex
from packet.transport.tcp import TCP
from packet.transport.udp import UDP

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.1"

# Name of different protocols
_IP_map = {1:'ICMP(1)', 2:'IGMP(2)', 6:'TCP(6)', 17:'UDP(17)'}

class Flags(BaseObj):
    """Flags object"""
    # Class attributes
    _attrlist = ("DF", "MF")

    def __init__(self, data):
        """Constructor which takes a single byte as input"""
        self.DF = ((data >> 14) & 0x01) # Don't Fragment
        self.MF = ((data >> 13) & 0x01) # More Fragments

class IPv4(BaseObj):
    """IPv4 object

       Usage:
           from packet.internet.ipv4 import IPv4

           x = IPv4(pktt)

       Object definition:

       IPv4(
           version         = int,
           IHL             = int, # Internet Header Length (in 32bit words)
           header_size     = int, # IHL in actual bytes
           DSCP            = int, # Differentiated Services Code Point
           ECN             = int, # Explicit Congestion Notification
           total_size      = int, # Total length
           id              = int, # Identification
           flags = Flags(         # Flags:
               DF = int,          #   Don't Fragment
               MF = int,          #   More Fragments
           )
           fragment_offset = int, # Fragment offset (in 8-byte blocks)
           TTL             = int, # Time to Live
           protocol        = int, # Protocol of next layer (RFC790)
           checksum        = int, # Header checksum
           src             = "%d.%d.%d.%d", # source IP address
           dst             = "%d.%d.%d.%d", # destination IP address
           options = string, # IP options if available
           data = string,    # Raw data of payload if protocol
                             # is not supported
       )
    """
    # Class attributes
    _attrlist = ("version", "IHL", "header_size", "DSCP", "ECN", "total_size",
                 "id", "flags", "fragment_offset", "TTL", "protocol",
                 "checksum", "src", "dst", "options", "data")

    def __init__(self, pktt):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
        """
        # Decode IP header
        unpack = pktt.unpack
        ulist = unpack.unpack(20, "!BBHHHBBH4B4B")
        self.version         = (ulist[0] >> 4)
        self.IHL             = (ulist[0] & 0x0F)
        self.header_size     = 4*self.IHL
        self.DSCP            = (ulist[1] >> 2)
        self.ECN             = (ulist[1] & 0x03)
        self.total_size      = ulist[2]
        self.id              = ShortHex(ulist[3])
        self.flags           = Flags(ulist[4])
        self.fragment_offset = (ulist[4] & 0x1FFF)
        self.TTL             = ulist[5]
        self.protocol        = ulist[6]
        self.checksum        = ShortHex(ulist[7])
        self.src             = "%d.%d.%d.%d" % ulist[8:12]
        self.dst             = "%d.%d.%d.%d" % ulist[12:]

        pktt.pkt.ip = self

        if self.header_size > 20:
            # Save IP options
            osize = self.header_size - 20
            self.options = unpack.read(osize)

        if self.protocol == 6:
            # Decode TCP
            TCP(pktt)
        elif self.protocol == 17:
            # Decode UDP
            UDP(pktt)
        else:
            self.data = unpack.getbytes()

    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of the object is condensed:
               '192.168.0.20 -> 192.168.0.61 '

           If set to 2 the representation of the object also includes the
           protocol and length of payload:
               '192.168.0.20 -> 192.168.0.61, protocol: 17(UDP), len: 84'
        """
        rdebug = self.debug_repr()
        if rdebug == 1:
            out = "%s -> %s " % (self.src, self.dst)
        elif rdebug == 2:
            proto = _IP_map.get(self.protocol, self.protocol)
            out = "%s -> %s, protocol: %s, len: %d" % (self.src, self.dst, proto, self.total_size)
        else:
            out = BaseObj.__str__(self)
        return out
