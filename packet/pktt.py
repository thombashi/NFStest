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
Packet trace module

The Packet trace module is a python module that takes a trace file created
by tcpdump and unpacks the contents of each packet. You can decode one packet
at a time, or do a search for specific packets. The main difference between
these modules and other tools used to decode trace files is that you can use
this module to completely automate your tests.

How does it work? It opens the trace file and reads one record at a time
keeping track where each record starts. This way, very large trace files
can be opened without having to wait for the file to load and avoid loading
the whole file into memory.

Packet layers supported:
    - ETHERNET II (RFC 894)
    - IP layer (supports IPv4 and IPv6)
    - UDP layer
    - TCP layer
    - RPC layer
    - NFS v4.0
    - NFS v4.1 including pNFS file layouts
    - NFS v4.2
    - PORTMAP v2
    - MOUNT v3
    - NLM v4
"""
import os
import re
import sys
import gzip
import time
import fcntl
import token
import struct
import parser
import symbol
import termios
from formatstr import *
import nfstest_config as c
from baseobj import BaseObj
from packet.unpack import Unpack
from packet.record import Record
from packet.pkt import Pkt, PKT_layers
from packet.link.ethernet import ETHERNET

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "2.3"

BaseObj.debug_map(0x100000000, 'pkt1', "PKT1: ")
BaseObj.debug_map(0x200000000, 'pkt2', "PKT2: ")
BaseObj.debug_map(0x400000000, 'pkt3', "PKT3: ")
BaseObj.debug_map(0x800000000, 'pkt4', "PKT4: ")
BaseObj.debug_map(0xF00000000, 'pktt', "PKTT: ")

# Map of tokens
_token_map = dict(token.tok_name.items() + symbol.sym_name.items())
# Map of items not in the array of the compound
_nfsopmap = {'status': 1, 'tag': 1}
# Match function map
_match_func_map = dict(zip(PKT_layers,["self._match_%s"%x for x in PKT_layers]))

# Read size -- the amount of data read at a time from the file
# The read ahead buffer actual size is always >= 2*READ_SIZE
READ_SIZE = 64*1024

# Show progress if stderr is a tty and stdout is not
SHOWPROG = os.isatty(2) and not os.isatty(1)

class Header(BaseObj):
    # Class attributes
    _attrlist = ("major", "minor", "zone_offset", "accuracy",
                 "dump_length", "link_type")

    def __init__(self, pktt):
        ulist = struct.unpack(pktt.header_fmt, pktt._read(20))
        self.major       = ulist[0]
        self.minor       = ulist[1]
        self.zone_offset = ulist[2]
        self.accuracy    = ulist[3]
        self.dump_length = ulist[4]
        self.link_type   = ulist[5]

class Pktt(BaseObj, Unpack):
    """Packet trace object

       Usage:
           from packet.pktt import Pktt

           x = Pktt("/traces/tracefile.cap")

           # Iterate over all packets found in the trace file
           for pkt in x:
               print pkt
    """
    def __init__(self, tfile, live=False, state=True):
        """Constructor

           Initialize object's private data, note that this will not check the
           file for existence nor will open the file to verify if it is a valid
           tcpdump file. The tcpdump trace file will be opened the first time a
           packet is retrieved.

           tracefile:
               Name of tcpdump trace file or a list of trace file names
               (little or big endian format)
           live:
               If set to True, methods will not return if encountered <EOF>,
               they will keep on trying until more data is available in the
               file. This is useful when running tcpdump in parallel,
               especially when tcpdump is run with the '-C' option, in which
               case when <EOF> is encountered the next trace file created by
               tcpdump will be opened and the object will be re-initialized,
               all private data referencing the previous file is lost.
        """
        self.tfile   = tfile  # Current trace file name
        self.bfile   = tfile  # Base trace file name
        self.live    = live   # Set to True if dealing with a live tcpdump file
        self.offset  = 0      # Current file offset
        self.boffset = 0      # File offset of current packet
        self.ioffset = 0      # File offset of first packet
        self.index   = 0      # Current packet index
        self.frame   = 1      # Current frame number
        self.mindex  = 0      # Maximum packet index for current trace file
        self.findex  = 0      # Current tcpdump file index (used with self.live)
        self.pindex  = 0      # Current packet index (for pktlist)
        self.pktlist = None   # Match from this packet list instead
        self.fh      = None   # Current file handle
        self.eof     = False  # End of file marker for current packet trace
        self.serial  = False  # Processing trace files serially
        self.pkt     = None   # Current packet
        self.pkt_call  = None # The current packet call if self.pkt is a reply
        self.pktt_list = []   # List of Pktt objects created
        self.tfiles    = []   # List of packet trace files
        self.rdbuffer  = ""   # Read buffer
        self.rdoffset  = 0    # Read buffer offset
        self.filesize  = 0    # Size of packet trace file
        self.prevprog  = -1.0 # Previous progress percentage
        self.prevtime  = 0.0  # Previous segment time
        self.prevdone  = -1   # Previous progress bar units done so far
        self.prevoff   = 0    # Previous offset
        self.showprog  = 0    # If this is true the progress will be displayed
        self.progdone  = 0    # Display last progress only once
        self.timestart = time.time() # Time reference base
        self.reply_matched = False   # Matching a reply

        # TCP stream map: to keep track of the different TCP streams within
        # the trace file -- used to deal with RPC packets spanning multiple
        # TCP packets or to handle a TCP packet having multiple RPC packets
        self._tcp_stream_map = {}

        # RPC xid map: to keep track of packet calls
        self._rpc_xid_map = {}
        # List of outstanding xids to match
        self._match_xid_list = []

        # Process tfile argument
        if isinstance(tfile, list):
            # The argument tfile is given as a list of packet trace files
            self.tfiles = tfile
            if len(self.tfiles) == 1:
                # Only one file is given
                self.tfile = self.tfiles[0]
            else:
                # Create all packet trace objects
                for tfile in self.tfiles:
                    self.pktt_list.append(Pktt(tfile))

    def __del__(self):
        """Destructor

           Gracefully close the tcpdump trace file if it is opened.
        """
        if self.fh:
            self.fh.close()

    def __iter__(self):
        """Make this object iterable."""
        return self

    def __contains__(self, expr):
        """Implement membership test operator.
           Return true if expr matches a packet in the trace file,
           false otherwise.

           The packet is also stored in the object attribute pkt.

           Examples:
               # Find the next READ request
               if ("NFS.argop == 25" in x):
                   print x.pkt.nfs

           See match() method for more information
        """
        pkt = self.match(expr)
        return (pkt is not None)

    def __getitem__(self, index):
        """Get the packet from the trace file given by the index
           or raise IndexError.

           The packet is also stored in the object attribute pkt.

           Examples:
               pkt = x[index]
        """
        self.dprint('PKT4', ">>> __getitem__(%d)" % index)
        if index < 0:
            # No negative index is allowed
            raise IndexError

        try:
            if index == self.pkt.record.index:
                # The requested packet is in memory, just return it
                return self.pkt
        except:
            pass

        if index < self.index:
            # Reset the current packet index and offset
            # The index is less than the current packet offset so position
            # the file pointer to the offset of the packet given by index
            self.rewind(index)

        # Move to the packet specified by the index
        pkt = None
        while self.index <= index:
            try:
                pkt = self.next()
            except:
                break

        if pkt is None:
            raise IndexError
        return pkt

    def next(self):
        """Get the next packet from the trace file or raise StopIteration.

           The packet is also stored in the object attribute pkt.

           Examples:
               # Iterate over all packets found in the trace file using
               # the iterable properties of the object
               for pkt in x:
                   print pkt

               # Iterate over all packets found in the trace file using it
               # as a method and using the object variable as the packet
               # Must use the try statement to catch StopIteration exception
               try:
                   while (x.next()):
                       print x.pkt
               except StopIteration:
                   pass

               # Iterate over all packets found in the trace file using it
               # as a method and using the return value as the packet
               # Must use the try statement to catch StopIteration exception
               while True:
                   try:
                       print x.next()
                   except StopIteration:
                       break

           NOTE:
               Supports only single active iteration
        """
        self.dprint('PKT4', ">>> %d: next()" % self.index)
        # Initialize next packet
        self.pkt = Pkt()

        if len(self.pktt_list) > 1:
            # Dealing with multiple trace files
            minsecs  = None
            pktt_obj = None
            for obj in self.pktt_list:
                if obj.pkt is None:
                    # Get first packet for this packet trace object
                    try:
                        obj.next()
                    except StopIteration:
                        obj.mindex = self.index
                if obj.eof:
                    continue
                if minsecs is None or obj.pkt.record.secs < minsecs:
                    minsecs = obj.pkt.record.secs
                    pktt_obj = obj
            if self.filesize == 0:
                # Calculate total bytes to process
                for obj in self.pktt_list:
                    self.filesize += obj.filesize
            if pktt_obj is None:
                # All packet trace files have been processed
                self.offset = self.filesize
                self.show_progress(True)
                raise StopIteration
            elif len(self._tcp_stream_map):
                # This packet trace file should be processed serially
                # Have all state transferred to next packet object
                pktt_obj.rewind()
                pktt_obj._tcp_stream_map = self._tcp_stream_map
                pktt_obj._rpc_xid_map    = self._rpc_xid_map
                self._tcp_stream_map = {}
                self._rpc_xid_map    = {}
                pktt_obj.next()

            # Overwrite attributes seen by the caller with the attributes
            # from the current packet trace object
            self.pkt = pktt_obj.pkt
            self.pkt_call = pktt_obj.pkt_call
            self.tfile = pktt_obj.tfile
            self.pkt.record.index = self.index  # Use a cumulative index
            self.offset += pktt_obj.offset - pktt_obj.boffset

            try:
                # Get next packet for this packet trace object
                pktt_obj.next()
            except StopIteration:
                # Set maximum packet index for this packet trace object to
                # be used by rewind to select the proper packet trace object
                pktt_obj.mindex = self.index
                # Check if objects should be serially processed
                pktt_obj.serial = False
                for obj in self.pktt_list:
                    if not obj.eof:
                        if obj.index > 1:
                            pktt_obj.serial = False
                            break
                        elif obj.index == 1:
                            pktt_obj.serial = True
                if pktt_obj.serial:
                    # Save current state
                    self._tcp_stream_map = pktt_obj._tcp_stream_map
                    self._rpc_xid_map    = pktt_obj._rpc_xid_map

            self.show_progress()

            # Increment cumulative packet index
            self.index += 1
            return self.pkt

        if self.boffset != self.offset:
            # Frame number is one for every record header on the pcap trace
            # On the other hand self.index is the packet number. Since there
            # could be multiple packets on a single frame self.index could
            # be larger the self.frame except that self.index start at 0
            # while self.frame starts at 1.
            # The frame number can be used to match packets with other tools
            # like wireshark
            self.frame += 1

        # Save file offset for this packet
        self.boffset = self.offset

        # Get record header
        data = self._read(16)
        if len(data) < 16:
            self.eof = True
            self.offset = self.filesize
            self.show_progress(True)
            raise StopIteration
        # Decode record header
        record = Record(self, data)

        # Get record data and create Unpack object
        self.unpack = Unpack(self._read(record.length_inc))
        if self.unpack.size() < record.length_inc:
            # Record has been truncated, stop iteration
            self.eof = True
            self.offset = self.filesize
            self.show_progress(True)
            raise StopIteration

        if self.header.link_type == 1:
            # Decode ethernet layer
            ETHERNET(self)
        else:
            # Unknown link layer
            record.data = self.unpack.getbytes()

        self.show_progress()

        # Increment packet index
        self.index += 1

        return self.pkt

    def rewind(self, index=0):
        """Rewind the trace file by setting the file pointer to the start of
           the given packet index. Returns False if unable to rewind the file,
           e.g., when the given index is greater than the maximum number
           of packets processed so far.
        """
        self.dprint('PKT1', ">>> rewind(%d)" % index)
        if self.pktlist is not None:
            self.pindex = index
            return True
        if index >= 0 and index < self.index:
            if len(self.pktt_list) > 1:
                # Dealing with multiple trace files
                self.index = 0
                for obj in self.pktt_list:
                    if not obj.eof or index <= obj.mindex:
                        obj.rewind()
                        try:
                            obj.next()
                        except StopIteration:
                            pass
                    elif obj.serial and index > obj.mindex:
                        self.index = obj.mindex + 1
            else:
                # Reset the current packet index and offset to the first packet
                self.offset = self.ioffset
                self.index  = 0
                self.eof    = False

                # Position the file pointer to the offset of the first packet
                self.seek(self.ioffset)

                # Clear state
                self._tcp_stream_map = {}
                self._rpc_xid_map    = {}

            # Move to the packet before the specified by the index so the
            # next packet fetched will be the one given by index
            while self.index < index:
                try:
                    pkt = self.next()
                except:
                    break

            # Rewind succeeded
            return True
        return False

    def seek(self, offset, whence=os.SEEK_SET, hard=False):
        """Position the read offset correctly
           If new position is outside the current read buffer then clear the
           buffer so a new chunk of data will be read from the file instead
        """
        soffset = self.fh.tell() - len(self.rdbuffer)
        if hard or offset < soffset or whence != os.SEEK_SET:
            # Seek is before the read buffer, do the actual seek
            self.rdbuffer = ""
            self.rdoffset = 0
            self.fh.seek(offset, whence)
            self.offset = self.fh.tell()
        else:
            # Seek is not before the read buffer
            self.rdoffset = offset - soffset
            self.offset = offset

    def _getfh(self):
        """Get the filehandle of the trace file, open file if necessary."""
        if self.fh == None:
            # Check size of file
            fstat = os.stat(self.tfile)
            if fstat.st_size == 0:
                raise Exception("Packet trace file is empty")

            # Open trace file
            self.fh = open(self.tfile, 'rb')
            self.filesize = fstat.st_size

            iszip = False
            self.header_fmt = None
            while self.header_fmt is None:
                # Initialize offset
                self.offset = 0

                # Get file identifier
                try:
                    self.ident = self._read(4)
                except:
                    self.ident = ""

                if self.ident == '\324\303\262\241':
                    # Little endian
                    self.header_fmt = '<HHIIII'
                    self.header_rec = '<IIII'
                elif self.ident == '\241\262\303\324':
                    # Big endian
                    self.header_fmt = '>HHIIII'
                    self.header_rec = '>IIII'
                else:
                    if iszip:
                        raise Exception('Not a tcpdump file')
                    iszip = True
                    # Get the size of the uncompressed file, this only works
                    # for uncompressed files less than 4GB
                    self.fh.seek(-4, os.SEEK_END)
                    self.filesize = struct.unpack("<I", self.fh.read(4))[0]
                    # Do a hard seek -- clear read ahead buffer
                    self.seek(0, hard=True)
                    # Try if this is a gzip compress file
                    self.fh = gzip.GzipFile(fileobj=self.fh)

            # Get header information
            self.header = Header(self)

            # Initialize packet number
            self.index   = 0
            self.tstart  = None
            self.ioffset = self.offset

        return self.fh

    def _read(self, count):
        """Wrapper for read in order to increment the object's offset. It also
           takes care of <EOF> when 'live' option is set which keeps on trying
           to read and switching files when needed.
        """
        # Open packet trace if needed
        self._getfh()
        while True:
            # Get the number of bytes specified
            rdsize = len(self.rdbuffer) - self.rdoffset
            if count > rdsize:
                # Not all bytes needed are in the read buffer
                if self.rdoffset > READ_SIZE:
                    # If the read offset is on the second half of the
                    # 2*READ_SIZE buffer discard the first bytes so the
                    # new read offset is right at the middle of the buffer
                    # This is done in case there is a seek behind the current
                    # offset so data is not read from the file again
                    self.rdbuffer = self.rdbuffer[self.rdoffset-READ_SIZE:]
                    self.rdoffset = READ_SIZE
                # Read next chunk from file
                self.rdbuffer += self.fh.read(max(count, READ_SIZE))
            # Get the bytes requested and increment read offset accordingly
            data = self.rdbuffer[self.rdoffset:self.rdoffset+count]
            self.rdoffset += count

            ldata = len(data)
            if self.live and ldata != count:
                # Not all data was read (<EOF>)
                tracefile = "%s%d" % (self.bfile, self.findex+1)
                # Check if next trace file exists
                if os.path.isfile(tracefile):
                    # Save information that keeps track of the next trace file
                    basefile = self.bfile
                    findex = self.findex + 1
                    # Re-initialize the object
                    self.__del__()
                    self.__init__(tracefile, live=self.live)
                    # Overwrite next trace file info
                    self.bfile = basefile
                    self.findex = findex
                # Re-position file pointer to last known offset
                self.seek(self.offset)
                time.sleep(1)
            else:
                break

        # Increment object's offset by the amount of data read
        self.offset += ldata
        return data

    def _split_match(self, uargs):
        """Split match arguments and return a tuple (lhs, opr, rhs)
           where lhs is the left hand side of the given argument expression,
           opr is the operation and rhs is the right hand side of the given
           argument expression:

               <lhs> <opr> <rhs>

           Valid opr values are: ==, !=, <, >, <=, >=, in
        """
        m = re.search(r"([^!=<>]+)\s*([!=<>]+|in)\s*(.*)", uargs)
        lhs = m.group(1).rstrip()
        opr = m.group(2)
        rhs = m.group(3)
        return (lhs, opr, rhs)

    def _process_match(self, obj, lhs, opr, rhs):
        """Process "regex" and 'in' operator on match expression.
           Regular expression is given as re('regex') and converted to a
           proper regex re.search('regex', data), where data is the object
           compose of obj and lhs|rhs depending on opr. The argument obj
           is an object prefix.

           If opr is a comparison operation (==, !=, etc.), both obj and lhs
           will be the actual LHS and rhs will be the actual RHS.
           If opr is 'in', lhs will be the actual LHS and both obj and rhs
           will be the actual RHS.

           Return the processed match expression.

           Examples:
               # Regular expression processing
               expr = x._process_match('self.pkt.ip.', 'src', '==', "re(r'192\.*')")

               Returns the following expression ready to be evaluated:
               expr = "re.search(r'192\.*', str(self.pkt,ip.src))"

               # Object prefix processing
               expr = x._process_match('item.', 'argop', '==', '25')

               Returns the following expression ready to be evaluated:
               expr = "item.argop==25"

               # Membership (in) processing
               expr = x._process_match('item.', '62', 'in', 'attributes')

               Returns the following expression ready to be evaluated:
               expr = "62 in item.attributes"
        """
        func = None
        if opr != 'in':
            regex = re.search(r"(\w+)\((.*)\)", lhs)
            if regex:
                lhs = regex.group(2)
                func = regex.group(1)

        if rhs[:3] == 're(':
            # Regular expression, it must be in rhs
            rhs = "re.search" + rhs[2:]
            if opr == "!=":
                rhs = "not " + rhs
            LHS = rhs[:-1] + ", str(" + obj + lhs +  "))"
            RHS = ""
            opr = ""
        elif opr == 'in':
            opr = " in "
            if self.inlhs:
                LHS = obj + lhs
                RHS = rhs
            else:
                LHS = lhs
                RHS = obj + rhs
        else:
            LHS = obj + lhs
            RHS = rhs

        if func is not None:
            LHS = "%s(%s)" % (func, LHS)

        return LHS + opr + RHS

    def _match(self, layer, uargs):
        """Default match function."""
        if not hasattr(self.pkt, layer):
            return False

        if layer == "nfs":
            # Use special matching function for NFS
            texpr = self.match_nfs(uargs)
        else:
            # Use general match
            obj = "self.pkt.%s." % layer.lower()
            lhs, opr, rhs = self._split_match(uargs)
            expr = self._process_match(obj, lhs, opr, rhs)
            texpr = eval(expr)
        self.dprint('PKT2', "    %d: match_%s(%s) -> %r" % (self.pkt.record.index, layer, uargs, texpr))
        return texpr

    def get_index(self):
        """Get current packet index"""
        if self.pktlist is None:
            return self.index
        else:
            return self.pindex

    def set_pktlist(self, pktlist=None):
        """Set the current packet list for buffered matching in which the
           match method will only use this list instead of getting the next
           packet from the packet trace file.
           This could be used when there is a lot of matching going back
           and forth but only on a particular set of packets.
           See the match() method for an example of buffered matching.
        """
        self.pindex  = 0
        self.pktlist = pktlist

    def clear_xid_list(self):
        """Clear list of outstanding xids"""
        self._match_xid_list = []

    def _match_nfs(self, uargs):
        """Match NFS values on current packet."""
        array = None
        isarg = True
        lhs, opr, rhs = self._split_match(uargs)

        if self.pkt.rpc.version == 3 or _nfsopmap.get(lhs):
            try:
                # Top level NFSv4 packet info or NFSv3 packet
                expr = self._process_match("self.pkt.nfs.", lhs, opr, rhs)
                if eval(expr):
                    # Set NFSop and NFSidx
                    self.pkt.NFSop = self.pkt.nfs
                    self.pkt.NFSidx = 0
                    return True
                return False
            except Exception:
                return False

        idx = 0
        obj_prefix = "item."
        for item in self.pkt.nfs.array:
            try:
                # Get expression to eval
                expr = self._process_match(obj_prefix, lhs, opr, rhs)
                if eval(expr):
                    self.pkt.NFSop = item
                    self.pkt.NFSidx = idx
                    return True
            except Exception:
                # Continue searching
                pass
            idx += 1
        return False

    def match_nfs(self, uargs):
        """Match NFS values on current packet.

           In NFSv4, there is a single compound procedure with multiple
           operations, matching becomes a little bit tricky in order to make
           the matching expression easy to use. The NFS object's name space
           gets converted into a flat name space for the sole purpose of
           matching. In other words, all operation objects in array are
           treated as being part of the NFS object's top level attributes.

           Consider the following NFS object:
               nfsobj = COMPOUND4res(
                   status=NFS4_OK,
                   tag='NFSv4_tag',
                   array = [
                       nfs_resop4(
                           resop=OP_SEQUENCE,
                           opsequence=SEQUENCE4res(
                               status=NFS4_OK,
                               resok=SEQUENCE4resok(
                                   sessionid='sessionid',
                                   sequenceid=29,
                                   slotid=0,
                                   highest_slotid=179,
                                   target_highest_slotid=179,
                                   status_flags=0,
                               ),
                           ),
                       ),
                       nfs_resop4(
                           resop=OP_PUTFH,
                           opputfh = PUTFH4res(
                               status=NFS4_OK,
                           ),
                       ),
                       ...
                   ]
               ),

           The result for operation PUTFH is the second in the list:
               putfh = nfsobj.array[1]

           From this putfh object the status operation can be accessed as:
               status = putfh.opputfh.status

           or simply as (this is how the NFS object works):
               status = putfh.status

           In this example, the following match expression 'NFS.status == 0'
           could match the top level status of the compound (nfsobj.status)
           or the putfh status (nfsobj.array[1].status)

           The following match expression 'NFS.sequenceid == 25' will also
           match this packet as well, even though the actual expression should
           be 'nfsobj.array[0].opsequence.resok.sequenceid == 25' or
           simply 'nfsobj.array[0].sequenceid == 25'.

           This approach makes the match expressions simpler at the expense of
           having some ambiguities on where the actual match occurred. If a
           match is desired on a specific operation, a more qualified name can
           be given. In the above example, in order to match the status of the
           PUTFH operation the match expression 'NFS.opputfh.status == 0' can
           be used. On the other hand, consider a compound having multiple
           PUTFH results the above match expression will always match the first
           occurrence of PUTFH where the status is 0. There is no way to tell
           the match engine to match the second or Nth occurrence of an
           operation.
        """
        texpr = self._match_nfs(uargs)
        self.dprint('PKT2', "    %d: match_nfs(%s) -> %r" % (self.pkt.record.index, uargs, texpr))
        return texpr

    def _convert_match(self, ast):
        """Convert a parser list match expression into their corresponding
           function calls.

           Example:
               expr = "TCP.flags.ACK == 1 and NFS.argop == 50"
               st = parser.expr(expr)
               ast = parser.st2list(st)
               data =  self._convert_match(ast)

               Returns:
               data = "(self._match('tcp','flags.ACK==1'))and(self._match('nfs','argop==50'))"
        """
        ret = ''
        isin = False
        if not isinstance(ast, list):
            if ast.lower() in _match_func_map:
                # Replace name by its corresponding function name
                return _match_func_map[ast.lower()]
            return ast
        if len(ast) == 2:
            return self._convert_match(ast[1])

        for a in ast[1:]:
            data = self._convert_match(a)
            if data == 'in':
                data = ' in '
                isin = True
                if ret[:5] == "self.":
                    # LHS in the 'in' operator is a packet object
                    self.inlhs = True
                else:
                    # LHS in the 'in' operator is a constant value
                    self.inlhs = False
            ret += data

        if _token_map[ast[0]] == "comparison":
            # Comparison
            if isin:
                regex = re.search(r'(.*)(self\._match)_(\w+)\.(.*)', ret)
                data  = regex.groups()
                func  = data[1]
                layer = data[2]
                uargs = data[0] + data[3]
            else:
                regex = re.search(r"^((\w+)\()?(self\._match)_(\w+)\.(.*)", ret)
                data  = regex.groups()
                func  = data[2]
                layer = data[3]
                if data[0] is None:
                    uargs = data[4]
                else:
                    uargs = data[0] + data[4]
            # Escape all single quotes since the whole string will be quoted
            uargs = re.sub(r"'", "\\'", uargs)
            ret = "(%s('%s','%s'))" % (func, layer, uargs)

        return ret

    def match(self, expr, maxindex=None, rewind=True, reply=False):
        """Return the packet that matches the given expression, also the packet
           index points to the next packet after the matched packet.
           Returns None if packet is not found and the packet index points
           to the packet at the beginning of the search.

           expr:
               String of expressions to be evaluated
           maxindex:
               The match fails if packet index hits this limit
           rewind:
               Rewind to index where matching started if match fails
           reply:
               Match RPC replies of previously matched calls as well

           Examples:
               # Find the packet with both the ACK and SYN TCP flags set to 1
               pkt = x.match("TCP.flags.ACK == 1 and TCP.flags.SYN == 1")

               # Find the next NFS EXCHANGE_ID request
               pkt = x.match("NFS.argop == 42")

               # Find the next NFS EXCHANGE_ID or CREATE_SESSION request
               pkt = x.match("NFS.argop in [42,43]")

               # Find the next NFS OPEN request or reply
               pkt = x.match("NFS.op == 18")

               # Find all packets coming from subnet 192.168.1.0/24 using
               # a regular expression
               while x.match(r"IP.src == re('192\.168\.1\.\d*')"):
                   print x.pkt.tcp

               # Find packet having a GETATTR asking for FATTR4_FS_LAYOUT_TYPES(bit 62)
               pkt_call = x.match("NFS.attr_request & 0x4000000000000000L != 0")
               if pkt_call:
                   # Find GETATTR reply
                   xid = pkt_call.rpc.xid
                   # Find reply where the number 62 is in the array NFS.attributes
                   pkt_reply = x.match("RPC.xid == %d and 62 in NFS.attributes" % xid)

               # Find the next WRITE request
               pkt = x.match("NFS.argop == 38")
               if pkt:
                   print pkt.nfs

               # Same as above, but using membership test operator instead
               if ("NFS.argop == 38" in x):
                   print x.pkt.nfs

               # Get a list of all OPEN and CLOSE packets then use buffered
               # matching to process each OPEN and its corresponding CLOSE
               # at a time including both requests and replies
               pktlist = []
               while x.match("NFS.op in [4,18]"):
                   pktlist.append(x.pkt)
               # Enable buffered matching
               x.set_pktlist(pktlist)
               while x.match("NFS.argop == 18"): # Find OPEN request
                   print x.pkt
                   index = x.get_index()
                   # Find OPEN reply
                   x.match("RPC.xid == %d and NFS.resop == 18" % x.pkt.rpc.xid)
                   print x.pkt
                   # Find corresponding CLOSE request
                   stid = x.escape(x.pkt.NFSop.stateid.other)
                   x.match("NFS.argop == 4 and NFS.stateid == '%s'" % stid)
                   print x.pkt
                   # Find CLOSE reply
                   x.match("RPC.xid == %d and NFS.resop == 4" % x.pkt.rpc.xid)
                   print x.pkt
                   # Rewind to right after the OPEN request
                   x.rewind(index)
               # Disable buffered matching
               x.set_pktlist()

           See also:
               match_ethernet(), match_ip(), match_tcp(), match_rpc(), match_nfs()
        """
        # Parse match expression
        st = parser.expr(expr)
        smap = parser.st2list(st)
        pdata = self._convert_match(smap)
        self.dprint('PKT1', ">>> %d: match(%s)" % (self.index, expr))
        self.reply_matched = False
        if self.pktlist is None:
            pkt_list   = self
            save_index = self.index
        else:
            pkt_list   = self.pktlist
            save_index = self.pindex

        # Search one packet at a time
        for pkt in pkt_list:
            if maxindex and self.index > maxindex:
                # Hit maxindex limit
                break
            if self.pktlist is not None:
                if pkt.record.index < self.pindex:
                    continue
                else:
                    self.pindex = pkt.record.index + 1
                    self.pkt = pkt
            try:
                if reply and pkt == "rpc" and pkt.rpc.type == 1 and pkt.rpc.xid in self._match_xid_list:
                    self.dprint('PKT1', ">>> %d: match() -> True: reply" % pkt.record.index)
                    self._match_xid_list.remove(pkt.rpc.xid)
                    self.reply_matched = True
                    return pkt
                if eval(pdata):
                    # Return matched packet
                    self.dprint('PKT1', ">>> %d: match() -> True" % pkt.record.index)
                    if reply and pkt == "rpc" and pkt.rpc.type == 0:
                        # Save xid of matched call
                        self._match_xid_list.append(pkt.rpc.xid)
                    return pkt
            except Exception:
                pass

        if rewind:
            # No packet matched, re-position the file pointer back to where
            # the search started
            if self.pktlist is None:
                self.rewind(save_index)
            else:
                self.pindex = save_index
        self.pkt = None
        self.dprint('PKT1', ">>> match() -> False")
        return None

    def show_progress(self, done=False):
        """Display progress bar if enabled and if running on correct terminal"""
        if SHOWPROG and self.showprog and (done or self.index % 500 == 0) \
          and (os.getpgrp() == os.tcgetpgrp(sys.stderr.fileno())):
            rows, columns = struct.unpack('hh', fcntl.ioctl(2, termios.TIOCGWINSZ, "1234"))
            if columns < 100:
                sps = 30
            else:
                # Terminal is wide enough, include bytes/sec
                sps = 42
            # Progress bar length
            wlen = int(columns) - len(str_units(self.filesize)) - sps
            # Number of bytes per progress bar unit
            xunit = float(self.filesize)/wlen
            # Progress bar units done so far
            xdone = int(self.offset/xunit)
            xtime = time.time()
            progress = 100.0*self.offset/self.filesize

            # Display progress only if there is some change in progress
            if (done and not self.progdone) or (self.prevdone != xdone or \
               int(self.prevtime) != int(xtime) or \
               round(self.prevprog) != round(progress)):
                if done:
                    # Do not display progress again when done=True
                    self.progdone = 1
                otime  = xtime - self.timestart # Overall time
                tdelta = xtime - self.prevtime  # Segment time
                self.prevprog = progress
                self.prevdone = xdone
                self.prevtime = xtime
                # Number of progress bar units for completion
                slen = wlen - xdone
                if done:
                    # Overall average bytes/sec
                    bps = self.offset / otime
                else:
                    # Segment average bytes/sec
                    bps = (self.offset - self.prevoff) / tdelta
                self.prevoff = self.offset
                # Progress bar has both foreground and background colors
                # as green and in case the terminal does not support colors
                # then a "=" is displayed instead instead of a green block
                pbar = " [\033[32m\033[42m%s\033[m%s] " % ("="*xdone, " "*slen)
                # Add progress percentage and how many bytes have been
                # processed so far relative to the total number of bytes
                pbar += "%5.1f%% %9s/%s" % (progress, str_units(self.offset), str_units(self.filesize))
                if columns < 100:
                    sys.stderr.write("%s %-6s\r" % (pbar, str_time(otime)))
                else:
                    # Terminal is wide enough, include bytes/sec
                    sys.stderr.write("%s %9s/s %-6s\r" % (pbar, str_units(bps), str_time(otime)))
                if done:
                    sys.stderr.write("\n")

    @staticmethod
    def escape(data):
        """Escape special characters.

           Examples:
               # Call as an instance
               escaped_data = x.escape(data)

               # Call as a class
               escaped_data = Pktt.escape(data)
        """
        # repr() can escape or not a single quote depending if a double
        # quote is present, just make sure both quotes are escaped correctly
        rdata = repr(data)
        if rdata[0] == '"':
            # Double quotes are escaped
            dquote = r'x22'
            squote = r'\x27'
        else:
            # Single quotes are escaped
            dquote = r'\x22'
            squote = r'x27'
        # Replace all double quotes to its corresponding hex value
        data = re.sub(r'"', dquote, rdata[1:-1])
        # Replace all single quotes to its corresponding hex value
        data = re.sub(r"'", squote, data)
        # Escape all backslashes
        data = re.sub(r'\\', r'\\\\', data)
        return data

    @staticmethod
    def ip_tcp_src_expr(ipaddr, port):
        """Return a match expression to find a packet coming from ipaddr:port.

           Examples:
               # Call as an instance
               expr = x.ip_tcp_src_expr('192.168.1.50', 2049)

               # Call as a class
               expr = Pktt.ip_tcp_src_expr('192.168.1.50', 2049)

               # Returns "IP.src == '192.168.1.50' and TCP.src_port == 2049"
               # Expression ready for x.match()
               pkt = x.match(expr)
        """
        return "IP.src == '%s' and TCP.src_port == %d" % (ipaddr, port)

    @staticmethod
    def ip_tcp_dst_expr(ipaddr, port):
        """Return a match expression to find a packet going to ipaddr:port.

           Examples:
               # Call as an instance
               expr = x.ip_tcp_dst_expr('192.168.1.50', 2049)

               # Call as a class
               expr = Pktt.ip_tcp_dst_expr('192.168.1.50', 2049)

               # Returns "IP.dst == '192.168.1.50' and TCP.dst_port == 2049"
               # Expression ready for x.match()
               pkt = x.match(expr)
        """
        return "IP.dst == '%s' and TCP.dst_port == %d" % (ipaddr, port)

if __name__ == '__main__':
    # Self test of module
    l_escape = [
        "hello",
        "\x00\\test",
        "single'quote",
        'double"quote',
        'back`quote',
        'single\'double"quote',
        'double"single\'quote',
        'single\'double"back`quote',
        'double"single\'back`quote',
    ]
    ntests = 2*len(l_escape)

    tcount = 0
    for quote in ["'", '"']:
        for data in l_escape:
            expr = "data == %s%s%s" % (quote, Pktt.escape(data), quote)
            expr = re.sub(r'\\\\', r'\\', expr)
            if eval(expr):
                tcount += 1

    if tcount == ntests:
        print "All tests passed!"
        exit(0)
    else:
        print "%d tests failed" % (ntests-tcount)
        exit(1)
