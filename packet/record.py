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
Record module

Provides the object for a record and the string representation of the record
in a tcpdump trace file.
"""
import time
import struct
import nfstest_config as c
from baseobj import BaseObj

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "2.1"

FRAME  = 0
INDEX  = 1
TSTAMP = 1

class Record(BaseObj):
    """Record object

       Usage:
           from packet.record import Record

           x = Record(pktt, data)

       Object definition:

       Record(
           frame       = int,   # Frame number
           index       = int,   # Packet number
           seconds     = int,   # Seconds
           usecs       = int,   # Microseconds
           length_inc  = int,   # Number of bytes included in trace
           length_orig = int,   # Number of bytes in packet
           secs        = float, # Absolute seconds including microseconds
           rsecs       = float, # Seconds relative to first packet
       )
    """
    # Class attributes
    _attrlist = ("frame", "index", "seconds", "usecs",
                 "length_inc", "length_orig", "secs", "rsecs")

    def __init__(self, pktt, data):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
           data:
               Raw packet data for this layer.
        """
        # Decode record header
        ulist = struct.unpack(pktt.header_rec, data)
        self.frame       = pktt.frame
        self.index       = pktt.index
        self.seconds     = ulist[0]
        self.usecs       = ulist[1]
        self.length_inc  = ulist[2]
        self.length_orig = ulist[3]
        pktt.pkt.record = self
        # Seconds + microseconds
        self.secs = float(self.seconds) + float(self.usecs)/1000000.0

        if pktt.tstart is None:
            # This is the first packet
            pktt.tstart = self.secs
        # Seconds relative to first packet
        self.rsecs = self.secs - pktt.tstart

    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of the object is condensed to display
           either or both the frame or packet numbers and the timestamp:
               '57 2014-03-16 13:42:56.530957 '

           If set to 2 the representation of the object also includes the number
           of bytes on the wire, number of bytes captured and a little bit more
           verbose:
               'frame 57 @ 2014-03-16 13:42:56.530957, 42 bytes on wire, 42 packet bytes'
        """
        idxstr = ""
        tstamp = ""
        rdebug = self.debug_repr()
        if TSTAMP and rdebug in [1,2]:
            tstamp = "%s.%06d" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.seconds)), self.usecs)
        if rdebug == 1:
            if FRAME and INDEX:
                idxstr = "%d,%d " % (self.frame, self.index)
            elif FRAME:
                idxstr = "%d " % self.frame
            elif INDEX:
                idxstr = "%d " % self.index
            out = "%s%s " % (idxstr, tstamp)
        elif rdebug == 2:
            if FRAME and INDEX:
                idxstr = "frame %d,%d @ " % (self.frame, self.index)
            elif FRAME:
                idxstr = "frame %d @ " % self.frame
            elif INDEX:
                idxstr = "index %d @ " % self.index
            out = "%s%s, %d bytes on wire, %d packet bytes" % (idxstr, tstamp, self.length_inc, self.length_orig)
        else:
            out = BaseObj.__str__(self)
        return out
