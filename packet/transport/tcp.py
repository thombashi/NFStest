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
TCP module

Decode TCP layer.

RFC  793 TRANSMISSION CONTROL PROTOCOL
RFC 2018 TCP Selective Acknowledgment Options
RFC 7323 TCP Extensions for High Performance
"""
import nfstest_config as c
from baseobj import BaseObj
from packet.unpack import Unpack
from packet.application.dns import DNS
from packet.application.rpc import RPC
from packet.application.krb5 import KRB5
from packet.utils import OptionFlags, ShortHex

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.5"

TCPflags = {
    0: "FIN",
    1: "SYN",
    2: "RST",
    3: "PSH",
    4: "ACK",
    5: "URG",
    6: "ECE",
    7: "CWR",
    8: "NS",
}

class Stream(BaseObj):
    """TCP stream buffer object"""
    # Printing of this object is used for debugging only so don't display buffer
    _attrlist = ("last_seq", "next_seq", "seq_wrap", "seq_base", "frag_off")

    def __init__(self, seqno):
        self.buffer   = "" # Keep track of RPC packets spanning multiple TCP packets
        self.frag_off = 0  # Keep track of multiple RPC packets within a single TCP packet
        self.last_seq = 0  # Last sequence number processed
        self.next_seq = 0  # Next sequence number expected
        self.seq_wrap = 0  # Keep track when sequence number has wrapped around
        self.seq_base = seqno # Base sequence number to convert to relative sequence numbers
        self.segments = [] # Array of missing fragments, item: [start seq, end seq]

    def add_fragment(self, data, seq):
        """Add fragment data to stream buffer"""
        if len(data) == 0:
            return
        if seq == self.next_seq or len(self.buffer) == 0:
            # Append fragment data to stream buffer
            self.buffer += data
            self.segments = []
        elif seq > self.next_seq:
            # Previous fragment is missing so fill previous fragment with zeros
            size = seq - self.next_seq
            self.segments.append([self.next_seq, seq])
            self.buffer += "\x00" * size
            self.buffer += data
        else:
            # Fragment is out of order -- found previous missing fragment
            off  = len(self.buffer) - self.next_seq + seq
            datalen = len(data)
            size = datalen + off
            # Insert fragment where it belongs
            self.buffer = self.buffer[:off] + data + self.buffer[size:]

            # Remove fragment from segments list
            index = 0
            for frag in self.segments:
                if seq >= frag[0] and seq < frag[1]:
                    if seq == frag[0] and seq+datalen == frag[1]:
                        # Full segment matched, so just remove it
                        self.segments.pop(index)
                    elif seq == frag[0]:
                        # Start of segment matched, set new missing start
                        frag[0] = seq+datalen
                    elif seq+datalen == frag[1]:
                        # End of segment matched, set new missing end
                        frag[1] = seq
                    else:
                        # Full segment is within missing segment,
                        # set new missing end and create a new segment
                        newfrag = [seq+datalen, frag[1]]
                        frag[1] = seq
                        self.segments.insert(index+1, newfrag)
                    break
                index += 1

    def missing_fragment(self, seq):
        """Check if given sequence number is within a missing fragment"""
        for frag in self.segments:
            if seq >= frag[0] and seq < frag[1]:
                return True
        return False

class Flags(OptionFlags):
    """TCP Option flags"""
    _rawfunc  = ShortHex
    _bitnames = TCPflags
    __str__ = OptionFlags.str_flags

class Option(BaseObj):
    """Option object"""
    def __init__(self, unpack):
        """Constructor which takes an unpack object as input"""
        self.kind = None
        try:
            self.kind = unpack.unpack_uchar()
            if self.kind not in (0,1):
                length = unpack.unpack_uchar()
                if length > 2:
                    if self.kind == 2:
                        # Maximum Segment Size (MSS)
                        self.mss = unpack.unpack_ushort()
                        self._attrlist = ("kind", "mss")
                    elif self.kind == 3:
                        # Window Scale option (WSopt)
                        self.wsopt = unpack.unpack_uchar()
                        self._attrlist = ("kind", "wsopt")
                    elif self.kind == 5:
                        # Sack Option Format
                        self.blocks = []
                        for i in range((length-2)/8):
                            left_edge  = unpack.unpack_uint()
                            right_edge = unpack.unpack_uint()
                            self.blocks.append([left_edge, right_edge])
                        self._attrlist = ("kind", "blocks")
                    elif self.kind == 8:
                        # Timestamps option (TSopt)
                        self.tsval = unpack.unpack_uint()
                        self.tsecr = unpack.unpack_uint()
                        self._attrlist = ("kind", "tsval", "tsecr")
                    else:
                        self.data = unpack.read(length-2)
                        self._attrlist = ("kind", "data")
        except:
            pass

class TCP(BaseObj):
    """TCP object

       Usage:
           from packet.transport.tcp import TCP

           x = TCP(pktt)

       Object definition:

       TCP(
           src_port    = int, # Source port
           dst_port    = int, # Destination port
           seq_number  = int, # Sequence number
           ack_number  = int, # Acknowledgment number
           hl          = int, # Data offset or header length (32bit words)
           header_size = int, # Data offset or header length in bytes
           flags = Flags(     # TCP flags:
               rawflags = int,#   Raw flags
               FIN = int,     #   No more data from sender
               SYN = int,     #   Synchronize sequence numbers
               RST = int,     #   Synchronize sequence numbers
               PSH = int,     #   Push function. Asks to push the buffered
                              #     data to the receiving application
               ACK = int,     #   Acknowledgment field is significant
               URG = int,     #   Urgent pointer field is significant
               ECE = int,     #   ECN-Echo has a dual role:
                              #     SYN=1, the TCP peer is ECN capable.
                              #     SYN=0, packet with Congestion Experienced
                              #     flag in IP header set is received during
                              #     normal transmission
               CWR = int,     #   Congestion Window Reduced
               NS  = int,     #   ECN-nonce concealment protection
           ),
           window_size = int, # Window size
           checksum    = int, # Checksum
           urgent_ptr  = int, # Urgent pointer
           seq         = int, # Relative sequence number
           options = list,    # List of TCP options
           data = string,     # Raw data of payload if unable to decode
       )
    """
    # Class attributes
    _attrlist = ("src_port", "dst_port", "seq_number", "ack_number", "hl",
                 "header_size", "flags", "window_size", "checksum",
                 "urgent_ptr", "options", "length", "data")

    def __init__(self, pktt):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
        """
        # Decode the TCP layer header
        unpack = pktt.unpack
        ulist = unpack.unpack(20, "!HHIIHHHH")
        self.src_port    = ulist[0]
        self.dst_port    = ulist[1]
        self.seq_number  = ulist[2]
        self.ack_number  = ulist[3]
        self.hl          = ulist[4] >> 12
        self.header_size = 4*self.hl
        self.flags       = Flags(ulist[4] & 0x1FF)
        self.window_size = ulist[5]
        self.checksum    = ShortHex(ulist[6])
        self.urgent_ptr  = ulist[7]

        pktt.pkt.tcp = self

        # Stream identifier
        ip = pktt.pkt.ip
        streamid = "%s:%d-%s:%d" % (ip.src, self.src_port, ip.dst, self.dst_port)

        if streamid not in pktt._tcp_stream_map:
            # Create TCP stream object
            pktt._tcp_stream_map[streamid] = Stream(self.seq_number)

        # De-reference stream map
        stream = pktt._tcp_stream_map[streamid]

        if self.flags.SYN:
            # Reset seq_base on SYN
            stream.seq_base = self.seq_number
            stream.last_seq = stream.seq_wrap

        # Convert sequence numbers to relative numbers
        seq = self.seq_number - stream.seq_base + stream.seq_wrap
        if seq < stream.seq_wrap:
            # Sequence number has reached the maximum and wrapped around
            stream.seq_wrap += 4294967296
            seq += 4294967296
        self.seq = seq

        if self.header_size > 20:
            self.options = []
            osize = self.header_size - 20
            optunpack = Unpack(unpack.read(osize))
            while optunpack.size():
                optobj = Option(optunpack)
                if optobj.kind == 0:
                    # End of option list
                    break
                elif optobj.kind > 0:
                    # Valid option
                    self.options.append(optobj)

        # Save length of TCP segment
        self.length = unpack.size()

        if seq < stream.last_seq and not stream.missing_fragment(seq):
            # This is a re-transmission, do not process
            return

        self._decode_payload(pktt, stream)

        if self.length > 0:
            stream.last_seq = seq
            stream.next_seq = seq + self.length

    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of the object is condensed:
               'TCP 708 -> 2049, seq: 3294175829, ack: 3395739041, ACK,FIN'

           If set to 2 the representation of the object also includes the
           length of payload and a little bit more verbose:
               'src port 708 -> dst port 2049, seq: 3294175829, ack: 3395739041, len: 0, flags: FIN,ACK'
        """
        rdebug = self.debug_repr()
        if rdebug == 1:
            out = "TCP %d -> %d, seq: %d, ack: %d, %s" % \
                  (self.src_port, self.dst_port, self.seq_number, self.ack_number, self.flags)
        elif rdebug == 2:
            out = "src port %d -> dst port %d, seq: %d, ack: %d, len: %d, flags: %s" % \
                  (self.src_port, self.dst_port, self.seq_number, self.ack_number, self.length, self.flags)
        else:
            out = BaseObj.__str__(self)
        return out

    def _decode_payload(self, pktt, stream):
        """Decode TCP payload."""
        rpc = None
        pkt = pktt.pkt
        unpack = pktt.unpack

        if 53 in [self.src_port, self.dst_port]:
            # DNS on port 53
            dns = DNS(pktt, proto=6)
            if dns:
                pkt.dns = dns
            return
        elif 88 in [self.src_port, self.dst_port]:
            # KRB5 on port 88
            krb = KRB5(pktt, proto=6)
            if krb:
                pkt.krb = krb
            return

        if stream.frag_off > 0 and len(stream.buffer) == 0:
            # This RPC packet lies within previous TCP packet,
            # Re-position the offset of the data
            unpack.seek(unpack.tell() + stream.frag_off)

        # Get the total size
        sid = unpack.save_state()
        size = unpack.size()

        # Try decoding the RPC header before using the stream buffer data
        # to re-sync the stream
        if len(stream.buffer) > 0:
            rpc = RPC(pktt, proto=6)
            if not rpc:
                unpack.restore_state(sid)
                sid = unpack.save_state()

        if rpc or (size == 0 and len(stream.buffer) > 0 and self.flags.rawflags != 0x10):
            # There has been some data lost in the capture,
            # to continue decoding next packets, reset stream
            # except if this packet is just a TCP ACK (flags = 0x10)
            stream.buffer = ""
            stream.frag_off = 0

        if not rpc:
            if len(stream.buffer):
                # Concatenate previous fragment
                unpack.insert(stream.buffer)
            ldata = unpack.size() - 4

            # Get RPC header
            rpc = RPC(pktt, proto=6)
        else:
            ldata = size - 4

        if not rpc:
            return

        rpcsize = rpc.fragment_hdr.size

        truncbytes = pkt.record.length_orig - pkt.record.length_inc
        if truncbytes == 0 and ldata < rpcsize:
            # An RPC fragment is missing to decode RPC payload
            unpack.restore_state(sid)
            stream.add_fragment(unpack.getbytes(), self.seq)
        else:
            if len(stream.buffer) > 0 or ldata == rpcsize:
                stream.frag_off = 0
            stream.buffer = ""
            # Save RPC layer on packet object
            pkt.rpc = rpc
            if rpc.type:
                # Remove packet call from the xid map since reply has
                # already been decoded
                pktt._rpc_xid_map.pop(rpc.xid, None)

            # Decode NFS layer
            rpcload = rpc.decode_payload()
            rpcbytes = ldata - unpack.size()
            if not rpcload and rpcbytes != rpcsize:
                pass
            elif unpack.size():
                # Save the offset of next RPC packet within this TCP packet
                # Data offset is cumulative
                stream.frag_off += size - unpack.size()
                sid = unpack.save_state()
                ldata = unpack.size() - 4
                try:
                    rpc_header = RPC(pktt, proto=6, state=False)
                except Exception:
                    rpc_header = None
                if not rpc_header or ldata < rpc_header.fragment_hdr.size:
                    # Part of next RPC packet is within this TCP packet
                    # Save the multi-span fragment data
                    unpack.restore_state(sid)
                    stream.add_fragment(unpack.getbytes(), self.seq)
                else:
                    # Next RPC packet is entirely within this TCP packet
                    # Re-position the file pointer to the current offset
                    pktt.seek(pktt.boffset)
            else:
                stream.frag_off = 0
