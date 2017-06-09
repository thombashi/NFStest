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
DNS module

Decode DNS layer.

RFC 1035 Domain Names - Implementation and Specification
RFC 2671 Extension Mechanisms for DNS (EDNS0)
RFC 4034 Resource Records for the DNS Security Extensions
RFC 4035 Protocol Modifications for the DNS Security Extensions
RFC 4255 Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints
"""
import dns_const as const
import nfstest_config as c
from packet.utils import *
from baseobj import BaseObj
from packet.unpack import Unpack
from packet.internet.ipv6addr import IPv6Addr

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2014 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

class dns_query(Enum):
    """enum dns_query"""
    _enumdict = const.dns_query

class dns_opcode(Enum):
    """enum dns_opcode"""
    _enumdict = const.dns_opcode

class dns_rcode(Enum):
    """enum dns_rcode"""
    _enumdict = const.dns_rcode

class dns_type(Enum):
    """enum dns_type"""
    _enumdict = const.dns_type

class dns_class(Enum):
    """enum dns_class"""
    _enumdict = const.dns_class

class dns_algorithm(Enum):
    """enum dns_algorithm"""
    _enumdict = const.dns_algorithm

class dns_fptype(Enum):
    """enum dns_fptype"""
    _enumdict = const.dns_fptype

class Query(BaseObj):
    """Query object"""
    # Class attributes
    _strfmt1  = "{1} {0} {2}"
    _strfmt2  = "{1} {0} {2}"
    _attrlist = ("qname", "qtype", "qclass")

class Resource(BaseObj):
    """Resource object"""
    # Class attributes
    _strfmt1 = "{5}"
    _strfmt2 = "{5}({1})"

class Option(BaseObj):
    """Option object"""
    # Class attributes
    _strfmt1  = "{0}"
    _strfmt2  = "{0}:{2}"
    _attrlist = ("option", "optlen", "data")

class DNS(BaseObj):
    """DNS object

       Usage:
           from packet.application.dns import DNS

           # Decode DNS layer
           x = DNS(pktt, proto)

       Object definition:

       DNS(
           id          = int,  # Query Identifier
           QR          = int,  # Packet Type (QUERY or REPLY)
           opcode      = int,  # Query Type
           AA          = int,  # Authoritative Answer
           TC          = int,  # Truncated Response
           RD          = int,  # Recursion Desired
           RA          = int,  # Recursion Available
           AD          = int,  # Authentic Data
           CD          = int,  # Checking Disabled
           rcode       = int,  # Response Code
           version     = int,  # Version (EDNS0)
           udpsize     = int,  # UDP Payload Size (EDNS0)
           options     = list, # Options (EDNS0)
           qdcount     = int,  # Number of Queries
           ancount     = int,  # Number of Answers
           nscount     = int,  # Number of Authority Records
           arcount     = int,  # Number of Additional Records
           queries     = list, # List of Queries
           answers     = list, # List of Answers
           authorities = list, # List of Authority Records
           additional  = list, # List of Additional Records
       )
    """
    # Class attributes
    _attrlist = ("id", "QR", "opcode", "AA", "TC", "RD", "RA", "rcode",
                 "version", "udpsize",
                 "qdcount", "ancount", "nscount", "arcount",
                 "queries", "answers", "authorities", "additional")

    def __init__(self, pktt, proto):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
           proto:
               Transport layer protocol.
        """
        self.proto   = proto
        self._dns    = False  # This object is valid when True
        self._ncache = {}     # Cache for domain names within this packet
        unpack = pktt.unpack
        if len(unpack) < 12:
            return

        try:
            if self.proto == 6:
                # Get the length of the TCP record
                length = unpack.unpack_ushort()
                if length < len(unpack):
                    return
            # Save reference offset
            # All names are referenced with respect to this offset
            self._offset = unpack.tell()
            ulist = unpack.unpack(12, "!6H")

            self.id          = ShortHex(ulist[0])
            self.QR          = dns_query(ulist[1] >> 15)
            self.opcode      = dns_opcode((ulist[1] >> 11) & 0x0f)
            self.AA          = (ulist[1] >> 10) & 0x01 # Authoritative Answer
            self.TC          = (ulist[1] >> 9) & 0x01  # Truncated Response
            self.RD          = (ulist[1] >> 8) & 0x01  # Recursion Desired
            self.RA          = (ulist[1] >> 7) & 0x01  # Recursion Available
            self.AD          = (ulist[1] >> 5) & 0x01  # Authentic Data
            self.CD          = (ulist[1] >> 4) & 0x01  # Checking Disabled
            self.rcode       = dns_rcode(ulist[1] & 0x0f)
            self.version     = 0  # Set with DNS EDNS0 Option Code (OPT)
            self.udpsize     = 0  # Set with DNS EDNS0 Option Code (OPT)
            self.options     = [] # Set with DNS EDNS0 Option Code (OPT)
            self.qdcount     = ulist[2]
            self.ancount     = ulist[3]
            self.nscount     = ulist[4]
            self.arcount     = ulist[5]
            self.queries     = unpack.unpack_array(self._query,    self.qdcount)
            self.answers     = unpack.unpack_array(self._resource, self.ancount)
            self.authorities = unpack.unpack_array(self._resource, self.nscount)
            self.additional  = unpack.unpack_array(self._resource, self.arcount)
            if self.QR == const.QUERY:
                self.set_strfmt(1, "DNS call  id={0} {14}")
            else:
                if self.rcode == const.NOERROR:
                    self.set_strfmt(1, "DNS reply id={0} {15}")
                else:
                    # Display error
                    self.set_strfmt(1, "DNS reply id={0} {7}")
        except Exception as e:
            return
        if len(unpack) > 0:
            return
        self._dns = True

    def __nonzero__(self):
        """Truth value testing for the built-in operation bool()"""
        return self._dns

    def _qname(self, unpack):
        """Get compressed domain name"""
        labels = []
        # Starting offset of label
        offset = unpack.tell() - self._offset
        while True:
            count = unpack.unpack_uchar()
            if count == 0:
                # End of domain name
                break
            elif count & 0xc0 == 0xc0:
                # Label begins with two one bits
                # This is a pointer to a previous qname
                # Lower bits give the offset
                poffset = unpack.unpack_uchar() + ((count & 0x3f) << 8)
                for off in reversed(sorted(self._ncache.keys())):
                    if poffset >= off:
                        # Found label in cache
                        doff = poffset - off
                        labels.append(self._ncache[off][doff:])
                        break
                break
            elif count & 0xc0 == 0x00:
                # Label begins with two zero bits
                # Lower bits give the number of octets in the uncompressed label
                labels.append(unpack.read(count))
        if len(labels) > 0:
            # Join all labels and save label in cache
            qname = ".".join(labels)
            self._ncache[offset] = qname
        else:
            # Empty label is the root
            qname = "<root>"
        return qname

    def _query(self, unpack):
        """Wrapper for Query object"""
        return Query(
            qname  = self._qname(unpack),
            qtype  = dns_type(unpack.unpack_short()),
            qclass = dns_class(unpack.unpack_ushort()),
        )

    def _address(self, unpack, size):
        """Get address"""
        if size == 4:
            return ".".join([str(x) for x in unpack.unpack(4, "!4B")])
        elif size == 16:
            return IPv6Addr(unpack.unpack(16, "!16s")[0].encode('hex'))
        else:
            return unpack.read(size)

    def _resource(self, unpack):
        """Wrapper for Resource object"""
        ret = Resource()
        ret.set_attr("qname",    self._qname(unpack))
        ret.set_attr("qtype",    dns_type(unpack.unpack_short()))
        ret.set_attr("qclass",   dns_class(unpack.unpack_ushort()))
        ret.set_attr("ttl",      unpack.unpack_uint())
        ret.set_attr("rdlength", unpack.unpack_ushort())
        offset = unpack.tell()
        if ret.qtype == const.A and ret.qclass == const.IN:
            # Host address IPv4
            ret.set_attr("address", self._address(unpack, ret.rdlength))
        elif ret.qtype == const.AAAA and ret.qclass == const.IN:
            # Host address IPv6
            ret.set_attr("address", self._address(unpack, ret.rdlength))
        elif ret.qtype == const.CNAME:
            # Canonical name for an alias
            ret.set_attr("cname", self._qname(unpack))
        elif ret.qtype == const.NS:
            # Authoritative name server
            ret.set_attr("ns", self._qname(unpack))
        elif ret.qtype == const.SOA:
            # SOA (Start of zone of authority)
            ret.set_attr("mname",   self._qname(unpack))
            ret.set_attr("rname",   self._qname(unpack))
            ret.set_attr("serial",  unpack.unpack_uint())
            ret.set_attr("refresh", unpack.unpack_uint())
            ret.set_attr("retry",   unpack.unpack_uint())
            ret.set_attr("expire",  unpack.unpack_uint())
            ret.set_attr("minimum", unpack.unpack_uint())
        elif ret.qtype == const.PTR:
            # Domain name pointer
            ret.set_attr("ptr", self._qname(unpack))
        elif ret.qtype == const.TXT:
            # Text string
            ret.set_attr("text", [])
            while ret.rdlength > (unpack.tell() - offset):
                text = unpack.unpack_string(Unpack.unpack_uchar)
                ret.text.append(text)
            ret.set_strfmt(1, "{5!r}")
            ret.set_strfmt(2, "text:{5!r}")
        elif ret.qtype == const.MX:
            # Mail exchange
            ret.set_attr("preference", unpack.unpack_short())
            ret.set_attr("exchange",   self._qname(unpack))
            ret.set_strfmt(1, "{6}({5})")
            ret.set_strfmt(2, "{1}:{6}({5})")
        elif ret.qtype == const.HINFO:
            ret.set_attr("cpu", unpack.unpack_string(Unpack.unpack_uchar))
            ret.set_attr("os",  unpack.unpack_string(Unpack.unpack_uchar))
        elif ret.qtype == const.OPT:
            # RFC 2671 Extension Mechanisms for DNS (EDNS0)
            # CLASS: sender's UDP payload size
            self.udpsize = ret.qclass
            # TTL: extended RCODE and flags
            ext_rcode = ret.ttl >> 24 # Upper 8 bits of extended 12-bit rcode
            self.rcode = dns_rcode((ext_rcode << 4) + self.rcode)
            self.version = (ret.ttl >> 16) & 0xff
            # RDATA: list of options
            while ret.rdlength > (unpack.tell() - offset):
                opt = Option()
                opt.option = unpack.unpack_ushort()
                opt.optlen = unpack.unpack_ushort()
                opt.data   = unpack.read(opt.optlen)
                self.options.append(opt)
            ret.set_strfmt(1, "{1}")
            ret.set_strfmt(2, "{1}:{0}")
        elif ret.qtype == const.SSHFP:
            # Secure Shell Fingerprint
            ret.set_attr("algorithm",   dns_algorithm(unpack.unpack_uchar()))
            ret.set_attr("fptype",      dns_fptype(unpack.unpack_uchar()))
            ret.set_attr("fingerprint", unpack.read(ret.rdlength-2))
            ret.set_strfmt(1, "{1}:{0}({5}/{6})")
            ret.set_strfmt(2, "{1}:{0}({5}/{6})")
        elif ret.qtype == const.RRSIG:
            # Resource Record Digital Signature
            ret.set_attr("ctype",     dns_type(unpack.unpack_ushort()))
            ret.set_attr("algorithm", dns_algorithm(unpack.unpack_uchar()))
            ret.set_attr("labels",    unpack.unpack_uchar())
            ret.set_attr("ottl",      unpack.unpack_uint())
            ret.set_attr("expsig",    unpack.unpack_uint())
            ret.set_attr("incsig",    unpack.unpack_uint())
            ret.set_attr("keytag",    unpack.unpack_ushort())
            ret.set_attr("sname",     self._qname(unpack))
            ret.set_attr("signature", unpack.read(ret.rdlength - unpack.tell() + offset))
            ret.set_strfmt(1, "{1}:{0}({5})")
            ret.set_strfmt(2, "{1}:{0}({5})")
        else:
            # Unsupported type, so just get the number of bytes of resource
            ret.set_attr("data", unpack.read(ret.rdlength))
        return ret
