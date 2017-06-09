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
Pkt module

Provides the object for a packet and the string representation of the packet.
This object has an attribute for each of the layers in the packet so each layer
can be accessed directly instead of going through each layer. To access the nfs
layer object you can use 'x.nfs' instead of using 'x.ethernet.ip.tcp.rpc.nfs'
which would be very cumbersome to use. Also, since NFS can be used with either
TCP or UDP it would be harder to access the nfs object independently of
the protocol.

Packet object attributes:
    Pkt(
        record   = Record information (frame number, etc.)
        ethernet = ETHERNET II (RFC 894) object
        ip       = IPv4 object
        tcp      = TCP object
        rpc      = RPC object
        nfs      = NFS object
    )
"""
import nfstest_config as c
from baseobj import BaseObj

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.1"

# The order in which to display all layers in the packet
PKT_layers = [
    'record',
    'ethernet',
    'ip', 'arp', 'rarp',
    'tcp', 'udp',
    'rpc', 'ntp', 'dns', 'krb',
    'gssd', 'nfs', 'mount', 'portmap', 'nlm', 'gssc',
]
# Required layers for debug_repr(1)
_PKT_rlayers = ['record', 'ip']
# Do not display these layers for debug_repr(1)
_PKT_nlayers = ['gssd', 'gssc']
# Packet layers to display as debug_repr(2) for debug_repr(1) if last layer
_PKT_mlayers = ['record', 'ethernet', 'ip']
_maxlen = len(max(PKT_layers, key=len))

class Pkt(BaseObj):
    """Packet object

       Usage:
           from packet.pkt import Pkt

           x = Pkt()

           # Check if this is an NFS packet
           if x == 'nfs':
               print x.nfs
    """
    _attrlist = tuple(PKT_layers)

    # Do not use BaseObj constructor to have a little bit of
    # performance improvement
    def __init__(self): pass

    def __eq__(self, other):
        """Comparison method used to determine if object has a given layer"""
        if type(other) is str:
            return getattr(self, other.lower(), None) is not None
        return False

    def __ne__(self, other):
        """Comparison method used to determine if object does not have a given layer"""
        return not self.__eq__(other)

    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of is condensed into a single line.
           It contains, the frame number, IP source and destination and/or the
           last layer:
               '1 0.386615 192.168.0.62 -> 192.168.0.17 TCP 2049 -> 708, seq: 3395733180, ack: 3294169773, ACK,SYN'
               '5 0.530957 00:0c:29:54:09:ef -> ff:ff:ff:ff:ff:ff, type: 0x806'
               '19 0.434370 192.168.0.17 -> 192.168.0.62 NFS v4 COMPOUND4 call  SEQUENCE;PUTFH;GETATTR'

           If set to 2 the representation of the object is a line for each layer:
               'Pkt(
                    RECORD:   frame 19 @ 0.434370 secs, 238 bytes on wire, 238 bytes captured
                    ETHERNET: 00:0c:29:54:09:ef -> e4:ce:8f:58:9f:f4, type: 0x800(IPv4)
                    IP:       192.168.0.17 -> 192.168.0.62, protocol: 6(TCP), len: 224
                    TCP:      src port 708 -> dst port 2049, seq: 3294170673, ack: 3395734137, len: 172, flags: ACK,PSH
                    RPC:      CALL(0), program: 100003, version: 4, procedure: 1, xid: 0x1437d3d5
                    NFS:      COMPOUND4args(tag='', minorversion=1, argarray=[nfs_argop4(argop=OP_SEQUENCE, ...), ...])
                )'
        """
        rdebug = self.debug_repr()
        if rdebug > 0:
            out = "Pkt(\n" if rdebug == 2 else ''
            klist = []
            for key in PKT_layers:
                if getattr(self, key, None) is not None and (rdebug > 1 or key not in _PKT_nlayers):
                    klist.append(key)
            index = 0
            lastkey = len(klist) - 1
            for key in klist:
                value = getattr(self, key, None)
                if value is not None and (rdebug > 1 or index == lastkey or key in _PKT_rlayers or (self != "ip" and key == "ethernet")):
                    if rdebug == 1:
                        if index == lastkey and key in _PKT_mlayers:
                            # Display level 2 if last layer is in _PKT_mlayers
                            self.debug_repr(2)
                            out += str(value)
                            self.debug_repr(1)
                        else:
                            out += str(value)
                    else:
                        sps = " " * (_maxlen - len(key))
                        out += "    %s:%s %s\n" % (key.upper(), sps, str(value))
                        if index == lastkey and hasattr(value, "data") and value.data is not None and key != "nfs":
                            sps = " " * (_maxlen - 4)
                            out += "    DATA:%s 0x%s\n" % (sps, value.data.encode("hex"))
                index += 1
            out += ")\n" if rdebug == 2 else ""
        else:
            out = BaseObj.__str__(self)
        return out
