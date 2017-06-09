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
ARP module

Decode ARP and RARP layers.

RFC 826 An Ethernet Address Resolution Protocol
RFC 903 A Reverse Address Resolution Protocol
"""
import arp_const as const
import nfstest_config as c
from packet.utils import *
from baseobj import BaseObj
from ipv6addr import IPv6Addr
from packet.link.macaddr import MacAddr

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2016 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

class arp_oper(Enum):
    """enum arp_oper"""
    _enumdict = const.arp_oper

class ARP(BaseObj):
    """ARP object

       Usage:
           from packet.internet.arp import ARP

           x = ARP(pktt)

       Object definition:

       ARP(
           htype = int,    # Hardware type
           ptype = int,    # Protocol type
           hlen  = int,    # Byte length for each hardware address
           plen  = int,    # Byte length for each protocol address
           oper  = int,    # Opcode
           sha   = string, # Hardware address of sender of this packet
           spa   = string, # Protocol address of sender of this packet
           tha   = string, # Hardware address of target of this packet
           tpa   = string, # Protocol address of target of this packet
       )
    """
    # Class attributes
    _attrlist = ("htype", "ptype", "hlen", "plen", "oper",
                 "sha", "spa", "tha", "tpa")

    def __init__(self, pktt):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
        """
        unpack = pktt.unpack
        ulist = unpack.unpack(8, "!HHBBH")
        self.htype = ulist[0]
        self.ptype = ulist[1]
        self.hlen  = ulist[2]
        self.plen  = ulist[3]
        self.oper  = arp_oper(ulist[4])
        self.sha   = self._getha(unpack)
        self.spa   = self._getpa(unpack)
        self.tha   = self._getha(unpack)
        self.tpa   = self._getpa(unpack)

        if self.oper == const.REQUEST:
            self._strfmt1 = "ARP {4} {8}"
            self._strfmt2 = "{4}: Who is {8}? Tell {6}"
        elif self.oper == const.REPLY:
            self._strfmt1 = "ARP {4} {5}"
            self._strfmt2 = "{4}: {6} is {5}"
        elif self.oper == const.RARP_REQUEST:
            self._strfmt1 = "RARP {4} {7}"
            self._strfmt2 = "{4}: Who is {7}? Tell {5}"
        elif self.oper == const.RARP_REPLY:
            self._strfmt1 = "RARP {4} {8}"
            self._strfmt2 = "{4}: {7} is {8}"

        # Set packet layer
        setattr(pktt.pkt, self.__class__.__name__.lower(), self)

    def _getha(self, unpack):
        """Get hardware address"""
        ret = None
        if self.htype == const.HTYPE_ETHERNET:
            ret = MacAddr(unpack.read(6).encode('hex'))
        else:
            ret = unpack.read(self.hlen)
        return ret

    def _getpa(self, unpack):
        """Get protocol address"""
        ret = None
        if self.ptype == const.PTYPE_IPV4:
            ret = "%d.%d.%d.%d" % unpack.unpack(4, "!4B")
        elif self.ptype == const.PTYPE_IPV6:
            ret = IPv6Addr(unpack.read(16).encode('hex'))
        else:
            ret = unpack.read(self.plen)
        return ret

class RARP(ARP): pass
