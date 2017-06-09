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
RPC module

Decode RPC layer.
"""
import struct
import traceback
from gss import GSS
from rpc_const import *
import nfstest_config as c
from baseobj import BaseObj
from packet.nfs.nfs import NFS
from packet.utils import IntHex
from rpc_creds import rpc_credential
from packet.nfs.nlm4 import NLM4args,NLM4res
from packet.nfs.mount3 import MOUNT3args,MOUNT3res
from packet.nfs.portmap2 import PORTMAP2args,PORTMAP2res

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.3"

class Header(BaseObj):
    """Header object"""
    # Class attributes
    _attrlist = ("size", "last_fragment")

    def __init__(self, size, last_fragment):
        """Constructor which takes the size and last fragment as inputs"""
        self.size          = size
        self.last_fragment = last_fragment

class Prog(BaseObj):
    """Prog object"""
    # Class attributes
    _attrlist = ("low", "high")

    def __init__(self, unpack):
        """Constructor which takes the Unpack object as input"""
        self.low  = unpack.unpack_uint()
        self.high = unpack.unpack_uint()

class RPC(GSS):
    """RPC object

       Usage:
           from packet.application.rpc import RPC

           # Decode the RPC header
           x = RPC(pktt_obj, proto=6)

           # Decode NFS layer
           nfs = x.decode_payload()

       Object definition:

       RPC(
           [
               # If TCP
               fragment_hdr = Header(
                   last_fragment = int,
                   size          = int,
               ),
           ]
           xid  = int,
           type = int,

           [
               # If type == 0 (RPC call)
               rpc_version = int,
               program     = int,
               version     = int,
               procedure   = int,
               credential  = Credential(
                   data   = string,
                   flavor = int,
                   size   = int,
               ),
               verifier = Credential(
                   data   = string,
                   flavor = int,
                   size   = int,
               ),
           ] | [
               # If type == 1 (RPC reply)
               reply_status = int,
               [
                   # If reply_status == 0
                   verifier = Credential(
                       data   = string,
                       flavor = int,
                       size   = int,
                   ),
                   accepted_status = int,
                   [
                       # If accepted_status == 2
                       prog_mismatch = Prog(
                           low  = int,
                           high = int,
                       )
                   ]
               ] | [
                   # If reply_status != 0
                   rejected_status = int,
                   [
                       # If rejected_status == 0
                       prog_mismatch = Prog(
                           low  = int,
                           high = int,
                       )
                   ] | [
                       # If rejected_status != 0
                       auth_status = int,
                   ]
               ]
           ]
           [data = string] # raw data of payload if unable to decode
       )
    """
    # Class attributes
    _attrlist = ("xid", "type", "rpc_version", "program", "version",
                 "procedure", "reply_status", "credential", "verifier",
                 "accepted_status", "prog_mismatch", "rejected_status",
                 "rpc_mismatch", "auth_status")

    def __init__(self, pktt, proto, state=True):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
           proto:
               Transport layer protocol.
           state:
               Save call state. [default: True]
        """
        self._rpc = False
        self._pktt = pktt
        self._proto = proto
        self._state = state

        try:
            self._rpc_header()
        except:
            pass

    def _rpc_header(self):
        """Internal method to decode RPC header"""
        pktt = self._pktt
        unpack = pktt.unpack
        init_size = unpack.size()
        if self._proto == 6:
            # TCP packet
            save_data = ''
            while True:
                # Decode fragment header
                psize = unpack.unpack_uint()
                size = (psize & 0x7FFFFFFF) + len(save_data)
                last_fragment = (psize >> 31)
                if size == 0:
                    return
                if last_fragment == 0 and size < unpack.size():
                    # Save RPC fragment
                    save_data += unpack.read(size)
                else:
                    if len(save_data):
                        # Concatenate RPC fragments
                        unpack.insert(save_data)
                    break
            self.fragment_hdr = Header(size, last_fragment)
        elif self._proto == 17:
            # UDP packet
            pass
        else:
            return

        # Decode XID and RPC type
        self.xid  = IntHex(unpack.unpack_uint())
        self.type = unpack.unpack_uint()

        if self.type == CALL:
            # RPC call
            self.rpc_version = unpack.unpack_uint()
            self.program     = unpack.unpack_uint()
            self.version     = unpack.unpack_uint()
            self.procedure   = unpack.unpack_uint()
            self.credential  = rpc_credential(unpack)
            if not self.credential:
                return
            self.verifier = rpc_credential(unpack, True)
            if self.rpc_version != 2 or (self.credential.flavor in [0,1] and not self.verifier):
                return
        elif self.type == REPLY:
            # RPC reply
            self.reply_status = unpack.unpack_uint()
            if self.reply_status == MSG_ACCEPTED:
                self.verifier = rpc_credential(unpack, True)
                if not self.verifier:
                    return
                self.accepted_status = unpack.unpack_uint()
                if self.accepted_status == PROG_MISMATCH:
                    self.prog_mismatch = Prog(unpack)
                elif accept_stat.get(self.accepted_status) is None:
                    # Invalid accept_stat
                    return
            elif self.reply_status == MSG_DENIED:
                self.rejected_status = unpack.unpack_uint()
                if self.rejected_status == RPC_MISMATCH:
                    self.rpc_mismatch = Prog(unpack)
                elif self.rejected_status == AUTH_ERROR:
                    self.auth_status = unpack.unpack_uint()
                    if auth_stat.get(self.auth_status) is None:
                        # Invalid auth_status
                        return
                elif reject_stat.get(self.rejected_status) is None:
                    # Invalid rejected status
                    return
            elif reply_stat.get(self.reply_status) is None:
                # Invalid reply status
                return
        else:
            return

        if self._proto == 6:
            hsize = init_size - unpack.size() - 4
            self.fragment_hdr.data_size = self.fragment_hdr.size - hsize

        self._rpc = True
        if not self._state:
            # Do not save state
            return

        xid = self.xid
        if self.type == CALL:
            # Save call packet in the xid map
            pktt._rpc_xid_map[xid] = pktt.pkt
            pktt.pkt_call = None
        elif self.type == REPLY:
            try:
                pkt_call = pktt._rpc_xid_map.get(self.xid, None)
                pktt.pkt_call = pkt_call
                rpc_header = pkt_call.rpc

                self.program   = rpc_header.program
                self.version   = rpc_header.version
                self.procedure = rpc_header.procedure
                if rpc_header.credential.flavor == RPCSEC_GSS:
                    self.verifier.gss_proc    = rpc_header.credential.gss_proc
                    self.verifier.gss_service = rpc_header.credential.gss_service
                    self.verifier.gss_version = rpc_header.credential.gss_version
            except Exception:
                pass

    def __nonzero__(self):
        """Truth value testing for the built-in operation bool()"""
        return self._rpc

    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of the object is:
               'RPC call   program: 100003, version: 4, procedure: 0, xid: 0xe37d3d5 '

           If set to 2 the representation of the object is as follows:
               'CALL(0), program: 100003, version: 4, procedure: 0, xid: 0xe37d3d5'
        """
        rdebug = self.debug_repr()
        if rdebug > 0:
            prog = ''
            for item in ['program', 'version', 'procedure']:
                value = getattr(self, item, None)
                if value != None:
                    prog += " %s: %d," % (item, value)
        if rdebug == 1:
            rtype = "%-5s" % msg_type.get(self.type, 'Unknown').lower()
            out = "RPC %s %s xid: %s" % (rtype, prog, self.xid)
        elif rdebug == 2:
            rtype = "%-5s(%d)" % (msg_type.get(self.type, 'Unknown'), self.type)
            if self.type == CALL:
                creds = ", %s" % self.credential
            else:
                creds = ", %s" % self.verifier
            out = "%s,%s xid: %s%s" % (rtype, prog, self.xid, creds)
        else:
            out = BaseObj.__str__(self)
        return out

    def decode_payload(self):
        """Decode RPC load

           For RPC calls it is easy to decide if the RPC payload is an NFS packet
           since the RPC program is in the RPC header, which for NFS the
           program number is 100003. On the other hand, for RPC replies the RPC
           header does not have any information on what the payload is, so the
           transaction ID (xid) is used to map the replies to their calls and
           thus deciding if RPC payload is an NFS packet or not.
           This is further complicated when trying to decode callbacks, since
           the program number for callbacks could be any number in the transient
           program range [0x40000000, 0x5FFFFFFF]. Therefore, any program number
           in the transient range is considered a callback and if the decoding
           succeeds then this is an NFS callback, otherwise it is not.

           Since the RPC replies do not contain any information about what type
           of payload, when they are decoded correctly as NFS replies this
           information is inserted in the RPC (pkt.rpc) object.
           This information includes program number, RPC version, procedure
           number as well as the call_index which is the packet index of its
           corresponding call for each reply.

           x.pkt.nfs = <NFSobject>

           where <NFSobject> is an object of type COMPOUND4args or COMPOUND4res

           class COMPOUND4args(
               tag          = string,
               minorversion = int,
               argarray     = [],
           )

           The argarray is a list of nfs_argop4 objects:

           class nfs_argop4(
               argop = int,
               [<opobject> = <opargobject>,]
           )

           where opobject could be opsequence, opgetattr, etc., and opargobject
           is the object which has the arguments for the given opobject, e.g.,
           SEQUENCE4args, GETATTR4args, etc.

           class COMPOUND4res(
               tag      = string,
               status   = int,
               resarray = [],
           )

           The resarray is a list of nfs_resop4 objects:

           class nfs_resop4(
               resop = int,
               [<opobject> = <opresobject>,]
           )

           where opobject could be opsequence, opgetattr, etc., and opresobject
           is the object which has the results for the given opobject, e.g.,
           SEQUENCE4res, GETATTR4res, etc.
        """
        ret = None
        layer = None
        pktt = self._pktt
        unpack = pktt.unpack
        self.decode_gss_data()

        # Make sure to catch any errors
        try:
            if self.program == 100003:
                # Decode NFS layer
                layer = "nfs"
                ret = NFS(self, False)
            elif self.program == 100005:
                # MOUNT protocol
                layer = "mount"
                if self.type == 0:
                    ret = MOUNT3args(unpack, self.procedure)
                else:
                    ret = MOUNT3res(unpack, self.procedure)
            elif self.program == 100021:
                # NLM protocol
                layer = "nlm"
                if self.type == 0:
                    ret = NLM4args(unpack, self.procedure)
                else:
                    ret = NLM4res(unpack, self.procedure)
            elif self.program == 100000:
                # PORTMAP protocol
                layer = "portmap"
                if self.type == 0:
                    ret = PORTMAP2args(unpack, self.procedure)
                else:
                    ret = PORTMAP2res(unpack, self.procedure)
            elif self.program >= 0x40000000 and self.program < 0x60000000:
                # This is a crude way to figure out if call/reply is a callback
                # based on the fact that NFS is always program 100003 and anything
                # in the transient program range is considered a callback
                layer = "nfs"
                ret = NFS(self, True)
            else:
                # Unable to decode RPC load so just get the load bytes
                if self._proto == 6:
                    self.data = unpack.read(self.fragment_hdr.data_size)
                else:
                    self.data = unpack.read(unpack.size())

            if ret:
                ret._rpc = self
                self.decode_gss_checksum()
                setattr(pktt.pkt, layer, ret)
        except Exception:
            # Could not decode RPC load
            self.dprint('PKT3', traceback.format_exc())
            return
        return ret
