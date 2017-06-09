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
NFS utilities module

Provides a set of tools for testing NFS including methods for starting a packet
trace, stopping the packet trace and then open the packet trace for analysis.
It also provides a mechanism to enable NFS/RPC kernel debug and saving the
log messages for further analysis.

Furthermore, methods for finding specific NFSv4 operations within the packet
trace are also included.
"""
import os
from host import Host
from formatstr import *
import nfstest_config as c
from packet.nfs.nfs3_const import *
from packet.nfs.nfs4_const import *
from nfstest.utils import split_path

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "2.7"

class NFSUtil(Host):
    """NFSUtil object

       NFSUtil() -> New NFSUtil object

       Usage:
           from nfstest.nfs_util import NFSUtil

           # Create object for local host
           x = NFSUtil()

           # Create client host object
           clientobj = x.create_host('192.168.0.11')

           # Use buffered matching on packets
           x.set_pktlist()

           # Get the next LOOKUP packets
           pktcall, pktreply = x.find_nfs_op(OP_LOOKUP)

           # Get OPEN information for the given file name
           fh, open_stid, deleg_stid = x.find_open(filename="file1")

           # Get address and port number from universal address string
           ipaddr, port = x.get_addr_port(addr)

           # Get packets and DS list for GETDEVICEINFO
           pktcall, pktreply, dslist = x.find_getdeviceinfo()

           # Get packets for EXCHANGE_ID
           pktcall, pktreply = x.find_exchange_id()

           # Get the NFS operation object from the given packet
           getfh = x.getop(x.pktreply, OP_GETFH)

           # Get the stateid which must be used by I/O operations
           stateid = x.get_stateid("file1")

           # Get the client id
           clientid = x.get_clientid()

           # Get the session id for the given clientid
           sessionid = x.get_sessionid(clientid=clientid)

           # Get the root file handle from PUTROOTFH for the given session id
           x.get_rootfh(sessionid=sessionid)

           # Get the file handle for the given path
           dirfh = x.get_pathfh("/vol1/data")

           # Display the state id in CRC16 format
           stidstr = x.stid_str(stateid)

           # Get the number of bytes available in the given directory
           freebytes = x.get_freebytes("/mnt/t")
    """
    def __init__(self, **kwargs):
        """Constructor

           Initialize object's private data.
        """
        # Arguments
        self.pktcall   = None
        self.pktreply  = None
        self.opencall  = None
        self.openreply = None

        # Initialize object variables
        self.clients = []
        self.clientobj = None
        self.nii_name = ''    # nii_name for the client
        self.nii_server = ''  # nii_name for the server
        self.device_info = {}
        self.dslist = []
        self.stateid = None
        self.rootfh  = None
        self.rootfsid = None
        self.rootfh_map = {} # Root fh map {key:sessionid, value:rootfh}
        self.sessionid_map = {} # Session id map {key:exchangeid, value:sessionid}
        self.sessionid = None # Session ID returned from CREATE_SESSION
        self.clientid = None # Client ID returned from EXCHANGE_ID

        # State id to string mapping
        self.stid_map = {}

        # Call base class constructor
        super(NFSUtil, self).__init__()

        # Initialize all test variables
        self.writeverf    = None
        self.test_seqid   = True
        self.test_stateid = True
        self.test_pattern = True
        self.test_niomiss = 0
        self.test_stripe  = True
        self.test_verf    = True
        self.need_commit  = False
        self.need_lcommit = False
        self.mdsd_lcommit = False
        self.max_iosize   = 0
        self.error_hash   = {}
        self.test_commit_full = True
        self.test_no_commit   = False
        self.test_commit_verf = True

    def __del__(self):
        """Destructor

           Gracefully stop the packet trace and un-reference all client
           objects
        """
        self.clientobj = None
        while self.clients:
            self.clients.pop()
        # Call base class destructor
        super(NFSUtil, self).__del__()

    def create_host(self, host, **kwargs):
        """Create client host object and set defaults."""
        self.clientobj = Host(
            host         = host,
            user         = kwargs.pop("user", ""),
            server       = kwargs.pop("server",       self.server),
            nfsversion   = kwargs.pop("nfsversion",   self.nfsversion),
            proto        = kwargs.pop("proto",        self.proto),
            port         = kwargs.pop("port",         self.port),
            sec          = kwargs.pop("sec",          self.sec),
            export       = kwargs.pop("export",       self.export),
            mtpoint      = kwargs.pop("mtpoint",      self.mtpoint),
            datadir      = kwargs.pop("datadir",      self.datadir),
            mtopts       = kwargs.pop("mtopts",       self.mtopts),
            nomount      = kwargs.pop("nomount",      self.nomount),
            tracename    = kwargs.pop("tracename",    self.tracename),
            trcdelay     = kwargs.pop("trcdelay",     self.trcdelay),
            tcpdump      = kwargs.pop("tcpdump",      self.tcpdump),
            tbsize       = kwargs.pop("tbsize",       self.tbsize),
            notrace      = kwargs.pop("notrace",      self.notrace),
            rpcdebug     = kwargs.pop("rpcdebug",     self.rpcdebug),
            nfsdebug     = kwargs.pop("nfsdebug",     self.nfsdebug),
            dbgname      = kwargs.pop("dbgname",      self.dbgname),
            messages     = kwargs.pop("messages",     self.messages),
            tmpdir       = kwargs.pop("tmpdir",       self.tmpdir),
            iptables     = kwargs.pop("iptables",     self.iptables),
            sudo         = kwargs.pop("sudo",         self.sudo),
        )

        self.clients.append(self.clientobj)
        return self.clientobj

    def set_pktlist(self, ops=None, cbs=None, procs=None, maxindex=None, pktdisp=False):
        """Set the current packet list for buffered matching in which the
           match method will only use this list instead of getting the next
           packet from the packet trace file. The default is to get all
           packets unless any of the arguments is given.

           NOTE: all READ reply data and all WRITE request data is discarded
           to avoid having memory issues.

           ops:
               List of NFSv4 operations to include in the packet list
           cbs:
               List of NFSv4 callback operations to include in the packet list
           procs:
               List of NFSv3 procedures to include in the packet list
           maxindex:
               Include packets up to but not including the packet indexed
               by this argument [default: None]
               A value of None means there is no limit
           pktdisp:
               Display all cached packets [default: False]
        """
        pktlist = []
        # Default behavior when no list is given
        defexpr = ops is None and cbs is None and procs is None
        # Boolean expressions for each of the lists
        ops_expr   = not defexpr and ops   is not None
        cbs_expr   = not defexpr and cbs   is not None
        procs_expr = not defexpr and procs is not None
        for pkt in self.pktt:
            # Get list of NFS packets
            if pkt == "nfs":
                if maxindex is not None and pkt.record.index >= maxindex:
                    break

                rpc = pkt.rpc
                if rpc.procedure == 0:
                    # NULL procedure
                    if not defexpr and (not procs_expr or 0 not in procs):
                        continue
                elif (rpc.version == 4 and not pkt.nfs.callback) or \
                     (rpc.version == 1 and pkt.nfs.callback):
                    # NFSv4 COMPOUND and callback
                    incl_pkt = False
                    for item in pkt.nfs.array:
                        op = item.op
                        # Discard data from read and write packets so memory
                        # is not an issue. Do this before selecting operations
                        # in case a READ or WRITE packet is selected by any
                        # of the other operations in the array
                        if op == OP_READ and rpc.type == 1:
                            item.opread.resok.data = ""
                        elif op == OP_WRITE and rpc.type == 0:
                            item.opwrite.data = ""
                        if not defexpr:
                            # If any of the lists is given, make sure to
                            # include only operations in the given lists
                            if pkt.nfs.callback:
                                if not cbs_expr or op not in cbs:
                                    continue
                            else:
                                if not ops_expr or op not in ops:
                                    continue
                        incl_pkt = True
                    if not incl_pkt:
                        continue
                elif rpc.version == 3:
                    # NFSv3 procedures
                    procedure = pkt.nfs.procedure
                    # If the procs list is given, make sure to include only
                    # procedures given in the list
                    if not defexpr and (not procs_expr or procedure not in procs):
                        continue
                    # Discard data from read and write packets
                    # so memory is not an issue
                    if procedure == NFSPROC3_READ and rpc.type == 1:
                        pkt.nfs.opread.resok.data = ""
                    elif procedure == NFSPROC3_WRITE and rpc.type == 0:
                        pkt.nfs.opwrite.data = ""
                pktlist.append(pkt)
                if pktdisp:
                    self.test_info(str(pkt))
        self.pktt.set_pktlist(pktlist)

    def find_nfs_op(self, op, **kwargs):
        """Find the call and its corresponding reply for the specified NFSv4
           operation going to the server specified by the ipaddr and port.
           The reply must also match the given status. Also the following
           object attributes are defined: pktcall referencing the packet call
           while pktreply referencing the packet reply.

           op:
               NFS operation to find
           ipaddr:
               Destination IP address [default: self.server_ipaddr]
               A value of None matches any IP address
           port:
               Destination port [default: self.port]
               A value of None matches any destination port
           match:
               Match string to include [default: '']
           status:
               Match the status of the operation [default: 0]
               A value of None matches any status.
           src_ipaddr:
               Source IP address [default: None]
               A value of None matches any IP address
           maxindex:
               The match fails if packet index hits this limit [default: None]
               A value of None means there is no limit
           call_only:
               Find the call only [default: False]

           Return a tuple: (pktcall, pktreply).
        """
        ipaddr       = kwargs.get("ipaddr",       self.server_ipaddr)
        port         = kwargs.get("port",         self.port)
        match        = kwargs.get("match",        "")
        status       = kwargs.get("status",       0)
        src_ipaddr   = kwargs.get("src_ipaddr",   None)
        maxindex     = kwargs.get("maxindex",     None)
        call_only    = kwargs.get("call_only",    False)

        mstatus = "" if status is None else "NFS.status == %d and " % status
        src = "IP.src == '%s' and " % src_ipaddr if src_ipaddr != None else ''
        dst = "IP.dst == '%s' and " % ipaddr if ipaddr is not None else ""
        if len(match):
            match += " and "
        if port != None:
            dst += "TCP.dst_port == %d and " % port
        pktcall  = None
        pktreply = None
        while True:
            # Find request
            pktcall = self.pktt.match(src + dst + match + "NFS.argop == %d" % op, maxindex=maxindex)
            if pktcall and not call_only:
                # Find reply
                xid = pktcall.rpc.xid
                # Include OP_ILLEGAL in case server does not know about the
                # operation in question
                pktreply = self.pktt.match("RPC.xid == %d and %s NFS.resop in (%d,%d)" % (xid, mstatus, op, OP_ILLEGAL), maxindex=maxindex)
                if pktreply:
                    break
            else:
                break
        self.pktcall  = pktcall
        self.pktreply = pktreply
        return (pktcall, pktreply)

    def find_open(self, **kwargs):
        """Find the call and its corresponding reply for the NFSv4 OPEN of the
           given file going to the server specified by the ipaddr and port.
           The following object attributes are defined: opencall and pktcall
           both referencing the packet call while openreply and pktreply both
           referencing the packet reply.

           filename:
               Find open call and reply for this file [default: None]
           claimfh:
               Find open call and reply for this file handle using CLAIM_FH
               [default: None]
           ipaddr:
               Destination IP address [default: self.server_ipaddr]
           port:
               Destination port [default: self.port]
           deleg_type:
               Expected delegation type on reply [default: None]
           deleg_stateid:
               Delegation stateid expected on call in delegate_cur_info [default: None]
           fh:
               Find open call and reply for this file handle when using
               deleg_stateid or as the directory FH when deleg_stateid
               is not set [default: None]
           src_ipaddr:
               Source IP address [default: any IP address]
           maxindex:
               The match fails if packet index hits this limit [default: no limit]
           anyclaim:
               Find open for either regular open or using delegate_cur_info [default: False]

           Must specify either filename, claimfh or both.
           Return a tuple: (filehandle, open_stateid, deleg_stateid).
        """
        filename      = kwargs.pop('filename', None)
        claimfh       = kwargs.pop('claimfh', None)
        fh            = kwargs.pop('fh', None)
        ipaddr        = kwargs.pop('ipaddr', self.server_ipaddr)
        port          = kwargs.pop('port', self.port)
        deleg_type    = kwargs.pop('deleg_type', None)
        deleg_stateid = kwargs.pop('deleg_stateid', None)
        src_ipaddr    = kwargs.pop('src_ipaddr', None)
        maxindex      = kwargs.pop('maxindex', None)
        anyclaim      = kwargs.pop('anyclaim', False)
        self.pktcall  = None
        self.pktreply = None
        self.opencall  = None
        self.openreply = None

        src = "IP.src == '%s' and " % src_ipaddr if src_ipaddr is not None else ''
        dst = self.pktt.ip_tcp_dst_expr(ipaddr, port)

        file_str = ""
        deleg_str = ""
        claimfh_str = ""
        str_list = []
        if filename is not None:
            file_str = "NFS.claim.name == '%s'" % filename
            str_list.append(file_str)
        if claimfh is not None:
            claimfh_str = "(NFS.fh == '%s' and NFS.claim.claim == %d)" % (self.pktt.escape(claimfh), CLAIM_FH)
            str_list.append(claimfh_str)
        if deleg_stateid is not None:
            deleg_str  = "(NFS.claim.claim == %d" % CLAIM_DELEGATE_CUR
            deleg_str += " and NFS.claim.deleg_info.name == '%s'" % filename
            deleg_str += " and NFS.claim.deleg_info.stateid == '%s')" % self.pktt.escape(deleg_stateid)
            if fh is not None:
                deleg_str += " or (NFS.claim.claim == %d" % CLAIM_DELEG_CUR_FH
                deleg_str += " and NFS.fh == '%s' and NFS.claim.stateid == '%s')" % (self.pktt.escape(fh), self.pktt.escape(deleg_stateid))
            str_list.append("(" + deleg_str + ")")
        if claimfh is None and deleg_stateid is None and fh is not None:
            dirfh_str = "NFS.fh == '%s'" % self.pktt.escape(fh)
            file_str = dirfh_str + " and " + file_str
            str_list.append(dirfh_str)

        if anyclaim:
            file_str = " or ".join(str_list)
        elif claimfh is not None:
            file_str = claimfh_str
        elif deleg_stateid is not None:
            file_str = deleg_str
        elif len(file_str) == 0:
            raise Exception("Must specify either filename or claimfh")

        while True:
            pktcall = self.pktt.match(src + dst + " and NFS.argop == %d and %s" % (OP_OPEN, file_str), maxindex=maxindex)
            if not pktcall:
                return (None, None, None)
            xid = pktcall.rpc.xid
            open_str = "RPC.xid == %d and NFS.status == 0 and NFS.resop == %d" % (xid, OP_OPEN)
            if deleg_type is not None:
                open_str += " and NFS.delegation.deleg_type == %d" % deleg_type

            # Find OPEN reply to get filehandle of file
            pktreply = self.pktt.match(open_str, maxindex=maxindex)
            if not pktreply:
                continue

            if claimfh is None:
                # GETFH should be the operation following the OPEN,
                # but look for it just in case it is not
                idx = pktreply.NFSidx + 1
                resarray = pktreply.nfs.array
                while (idx < len(resarray) and resarray[idx].resop != OP_GETFH):
                    idx += 1
                if idx >= len(resarray):
                    # Could not find GETFH
                    if fh is None:
                        return (None, None, None)
                    else:
                        filehandle = fh
                else:
                    filehandle = pktreply.nfs.array[idx].fh
            else:
                # No need to find GETFH, the filehandle is already known
                filehandle = claimfh

            open_stateid = pktreply.NFSop.stateid.other
            if pktreply.NFSop.delegation.deleg_type in [OPEN_DELEGATE_READ, OPEN_DELEGATE_WRITE]:
                deleg_stateid = pktreply.NFSop.delegation.stateid.other
            else:
                deleg_stateid = None

            self.pktcall  = pktcall
            self.pktreply = pktreply
            self.opencall  = pktcall
            self.openreply = pktreply
            return (filehandle, open_stateid, deleg_stateid)

    def find_layoutget(self, filehandle):
        """Find the call and its corresponding reply for the NFSv4 LAYOUTGET
           of the given file handle going to the server specified by the
           ipaddr for self.server and port given by self.port.

           Return a tuple: (layoutget, layoutget_res, loc_body).
        """
        dst = self.pktt.ip_tcp_dst_expr(self.server_ipaddr, self.port)

        # Find LAYOUTGET request
        pkt = self.pktt.match(dst + " and NFS.fh == '%s' and NFS.argop == %d" % (self.pktt.escape(filehandle), OP_LAYOUTGET))
        if not pkt:
            return (None, None, None)
        xid = pkt.rpc.xid
        layoutget = pkt.NFSop

        # Find LAYOUTGET reply
        pkt = self.pktt.match("RPC.xid == %d and NFS.resop == %d" % (xid, OP_LAYOUTGET))
        if pkt is None:
            return (layoutget, None, None)
        layoutget_res = pkt.NFSop
        if layoutget_res.status:
            return (layoutget, layoutget_res, None)
        # XXX Using first layout segment only
        layout = layoutget_res.layout[0]

        # Get layout content
        loc_body = layout.content.body
        if layoutget.type == LAYOUT4_NFSV4_1_FILES:
            nfl_util = loc_body.nfl_util

            # Decode loc_body
            loc_body = {
                'type':               layoutget.type,
                'dense':              (nfl_util & NFL4_UFLG_DENSE > 0),
                'commit_mds':         (nfl_util & NFL4_UFLG_COMMIT_THRU_MDS > 0),
                'stripe_size':        nfl_util & NFL4_UFLG_STRIPE_UNIT_SIZE_MASK,
                'first_stripe_index': loc_body.first_stripe_index,
                'offset':             loc_body.pattern_offset,
                'filehandles':        loc_body.fh_list,
                'deviceid':           loc_body.deviceid,
                'stateid':            layoutget_res.stateid.other,
                'iomode':             layout.iomode,
            }
        else:
            loc_body = {
                'type':               layoutget.type,
                'stateid':            layoutget_res.stateid.other,
                'iomode':             layout.iomode,
            }

        return (layoutget, layoutget_res, loc_body)

    def get_addr_port(self, addr):
        """Get address and port number from universal address string"""
        addr_list = addr.split('.')
        if len(addr_list) == 6:
            # IPv4 address
            ipaddr = '.'.join(addr_list[:4])
        else:
            # IPv6 address
            ipaddr = addr_list[0]
        port = (int(addr_list[-2])<<8) + int(addr_list[-1])
        return ipaddr, port

    def find_getdeviceinfo(self, deviceid=None):
        """Find the call and its corresponding reply for the NFSv4 GETDEVICEINFO
           going to the server specified by the ipaddr for self.server and port
           given by self.port.

           deviceid:
               Look for an specific deviceid [default: any deviceid]

           Return a tuple: (pktcall, pktreply, dslist).
        """
        dslist = []
        # Find GETDEVICEINFO request and reply
        match = "NFS.deviceid == '%s'" % self.pktt.escape(deviceid) if deviceid is not None else ''
        (pktcall, pktreply) = self.find_nfs_op(OP_GETDEVICEINFO, match=match, status=None)
        if pktreply and pktreply.nfs.status == 0:
            self.gdir_device = pktreply.NFSop.device_addr
            if self.gdir_device.type == LAYOUT4_NFSV4_1_FILES:
                da_addr_body = self.gdir_device.body
                self.stripe_indices = da_addr_body.stripe_indices
                multipath_ds_list = da_addr_body.multipath_ds_list

                for ds_list in multipath_ds_list:
                    dslist.append([])
                    for item in ds_list:
                        # Get ip address and port for DS
                        ipaddr, port = self.get_addr_port(item.addr)
                        dslist[-1].append({'ipaddr': ipaddr, 'port': port})
            # Save device info for future reference
            self.device_info[pktcall.NFSop.deviceid] = {
                'call':  pktcall,
                'reply': pktreply,
            }
        if len(dslist) > 0:
            self.dslist = dslist
        return (pktcall, pktreply, dslist)

    def find_exchange_id(self, **kwargs):
        """Find the call and its corresponding reply for the NFSv4 EXCHANGE_ID
           going to the server specified by the ipaddr and port.

           ipaddr:
               Destination IP address [default: self.server_ipaddr]
           port:
               Destination port [default: self.port]

           Store the callback IP/TCP expression in object attribute cb_dst

           Return a tuple: (pktcall, pktreply).
        """
        # Find EXCHANGE_ID request and reply
        (pktcall, pktreply) = self.find_nfs_op(OP_EXCHANGE_ID, **kwargs)
        self.src_ipaddr = pktcall.ip.src
        self.src_port   = pktcall.tcp.src_port
        self.cb_dst     = self.pktt.ip_tcp_dst_expr(self.src_ipaddr, self.src_port)

        if pktcall is not None and pktcall.NFSop.client_impl_id is not None:
            self.nii_name = pktcall.NFSop.client_impl_id.name
        if pktreply is not None and pktreply.NFSop.server_impl_id is not None:
            self.nii_server = pktreply.NFSop.server_impl_id.name

        return (pktcall, pktreply)

    def find_layoutrecall(self, status=0):
        """Find NFSv4 CB_LAYOUTRECALL call and return its reply.
           The reply must also match the given status.
        """
        # Find CB_LAYOUTRECALL request
        pktcall = self.pktt.match(self.cb_dst + " and NFS.argop == %d" % OP_CB_LAYOUTRECALL)
        if pktcall:
            # Find reply
            xid = pktcall.rpc.xid
            pktreply = self.pktt.match("RPC.xid == %d and NFS.resop == %d and NFS.status == %d" % (xid, OP_CB_LAYOUTRECALL, status))
        else:
            self.test(False, "CB_LAYOUTRECALL was not found")
            return
        return pktreply

    def get_abs_offset(self, offset, ds_index=None):
        """Get real file offset given by the (read/write) offset on the given
           data server index, taking into account the type of layout
           (dense/sparse), the stripe_size, first stripe index and the number
           of filehandles. The layout information is taken from object
           attribute layout.
        """
        if ds_index is None:
            return offset
        nfhs = len(self.dslist)
        stripe_size = self.layout['stripe_size']
        first_stripe_index = self.layout['first_stripe_index']
        ds_index -= first_stripe_index;
        if ds_index < 0:
            ds_index += nfhs
        # Get real file offset given by the read/write offset to the given DS index
        if self.layout['dense']:
            # Dense layout
            n = int(offset / stripe_size)
            r = offset % stripe_size
            file_offset = (n*nfhs + ds_index)*stripe_size + r
        else:
            # Sparse layout
            file_offset = offset
        return file_offset

    def get_filehandle(self, ds_index):
        """Return filehandle from the layout list of filehandles."""
        if len(self.layout['filehandles']) > 1:
            filehandle = self.layout['filehandles'][ds_index]
        else:
            filehandle = self.layout['filehandles'][0]
        return filehandle

    def verify_stripe(self, offset, size, ds_index):
        """Verify if read/write is sent to the correct data server according
           to stripe size, first stripe index and the number of filehandles.
           The layout information is taken from object attribute layout.

           offset:
               Real file offset
           size:
               I/O size
           ds_index:
               Data server index

           Return True if stripe is correctly verified, False otherwise.
        """
        nfhs = len(self.dslist)
        if self.layout is None or ds_index is None:
            return False
        stripe_size = self.layout['stripe_size']
        first_stripe_index = self.layout['first_stripe_index']
        n = int(offset / stripe_size)
        m = int((offset + size - 1) / stripe_size)
        idx = n % nfhs
        ds_index -= first_stripe_index;
        if ds_index < 0:
            ds_index += nfhs
        return n == m and idx == ds_index

    def getop(self, pkt, op):
        """Get the NFS operation object from the given packet"""
        if pkt:
            # Start looking for the operation after NFSidx if it exists
            if hasattr(pkt, "NFSidx"):
                idx = pkt.NFSidx + 1
            else:
                idx = 0
            array = pkt.nfs.array
            while (idx < len(array) and array[idx].op != op):
                idx += 1
            if idx < len(array):
                # Return the operation object
                return pkt.nfs.array[idx]
        return

    def verify_pnfs_supported(self, filehandle, server_type, path=None):
        """Verify pNFS is supported in the given server path.
           Finds the GETATTR asking for FATTR4_SUPPORTED_ATTRS(bit 0 and its
           reply to verify FATTR4_FS_LAYOUT_TYPES is supported for the path.
           Then it finds the GETATTR asking for FATTR4_FS_LAYOUT_TYPES(bit 62)
           to verify LAYOUT4_NFSV4_1_FILES is returned in fs_layout_types.
        """
        if path:
            pmsg = " for %s" % path
        else:
            pmsg = ""
        fhstr = self.pktt.escape(filehandle)
        # Find packet having a GETATTR asking for FATTR4_SUPPORTED_ATTRS(bit 0)
        attrmatch = "NFS.fh == '%s' and NFS.request & %s != 0" % (fhstr, hex(1 << FATTR4_SUPPORTED_ATTRS))
        pktcall, pktreply = self.find_nfs_op(OP_GETATTR, match=attrmatch)
        self.test(pktcall, "GETATTR should be sent to %s asking for FATTR4_SUPPORTED_ATTRS%s" % (server_type, pmsg))
        if pktreply:
            supported_attrs = pktreply.NFSop.attributes[FATTR4_SUPPORTED_ATTRS]
            fslt_supported = supported_attrs & (1<<FATTR4_FS_LAYOUT_TYPES) != 0
            self.test(fslt_supported, "NFS server should support pNFS layout types (FATTR4_FS_LAYOUT_TYPES)%s" % pmsg)
        elif pktcall:
            self.test(False, "GETATTR reply was not found")

        # Find packet having a GETATTR asking for FATTR4_FS_LAYOUT_TYPES(bit 62)
        attrmatch = "NFS.fh == '%s' and NFS.request & %s != 0" % (fhstr, hex(1 << FATTR4_FS_LAYOUT_TYPES))
        pktcall, pktreply = self.find_nfs_op(OP_GETATTR, match=attrmatch)
        self.test(pktcall, "GETATTR should be sent to %s asking for FATTR4_FS_LAYOUT_TYPES%s" % (server_type, pmsg))
        if pktreply:
            # Get list of fs layout types supported by the server
            fs_layout_types = pktreply.NFSop.attributes[FATTR4_FS_LAYOUT_TYPES]
            self.test(LAYOUT4_NFSV4_1_FILES in fs_layout_types, "NFS server should return LAYOUT4_NFSV4_1_FILES in fs_layout_types%s" % pmsg)
        elif pktcall:
            self.test(False, "GETATTR reply was not found")

    def verify_create_session(self, ipaddr, port, ds=False, nocreate=False, ds_index=None, exchid_status=0, cs_status=0):
        """Verify initial connection to the metadata server(MDS)/data server(DS).
           Verify if EXCHANGE_ID, CREATE_SESSION, RECLAIM_COMPLETE,
           GETATTR asking for FATTR4_LEASE_TIME, and GETATTR asking for
           FATTR4_FS_LAYOUT_TYPES are all sent or not to the server.

           ipaddr:
               Destination IP address of MDS or DS
           port:
               Destination port number of MDS or DS
           ds:
               True if ipaddr/port defines a DS, otherwise MDS [default: False]
           nocreate:
               True if expecting the client NOT to send EXCHANGE_ID,
               CREATE_SESSION, and RECLAIM_COMPLETE. Otherwise, verify all
               these operations are sent by the client [default: False]
           ds_index:
               DS index used for displaying purposes only [default: None]
           exchid_status:
               Expected status for EXCHANGE_ID [default: 0]
           cs_status:
               Expected status for CREATE_SESSION [default: 0]

           Return the sessionid and it is also stored in the object
           attribute sessionid.
        """
        self.sessionid = None
        if ds:
            pnfs_use_flag = EXCHGID4_FLAG_USE_PNFS_DS
            server_type = "DS"
            if ds_index is not None:
                server_type += "(%d)" % ds_index
        else:
            pnfs_use_flag = EXCHGID4_FLAG_USE_PNFS_MDS
            server_type = "MDS"

        dsmds = ""
        if ds_index != None and ipaddr == self.server_ipaddr and port == self.port:
            # DS == MDS, client does not connect to DS, it has a connection already
            nocreate = True
            dsmds = " since DS == MDS"

        if not ds:
            save_index = self.pktt.get_index()
            # Find PUTROOTFH having a GETFH operation
            getfhmatch = "NFS.argop == %d" % OP_GETFH
            pktcall, pktreply = self.find_nfs_op(OP_PUTROOTFH, ipaddr=ipaddr, port=port, match=getfhmatch)
            self.rootfh = getattr(self.getop(pktreply, OP_GETFH), "fh", None)
            attributes  = getattr(self.getop(pktreply, OP_GETATTR), "attributes", None)
            if attributes:
                self.rootfsid = attributes.get(FATTR4_FSID)
            self.pktt.rewind(save_index)

        # Find EXCHANGE_ID request and reply
        (pktcall, pktreply) = self.find_nfs_op(OP_EXCHANGE_ID, ipaddr=ipaddr, port=port, status=exchid_status)
        if nocreate:
            self.test(not pktcall, "EXCHANGE_ID should not be sent to %s%s" % (server_type, dsmds))
        else:
            self.test(pktcall, "EXCHANGE_ID should be sent to %s" % server_type)
            if pktreply:
                if exchid_status:
                    self.test(pktreply.NFSop.status == exchid_status, "EXCHANGE_ID reply should return %s(%d)" % (nfsstat4[exchid_status], exchid_status))
                    return
                else:
                    eir_flags = pktreply.NFSop.flags
                    if pktreply.NFSop.server_impl_id is not None:
                        self.nii_name = pktreply.NFSop.server_impl_id.name
                    self.test(eir_flags & pnfs_use_flag != 0, "EXCHGID4_FLAG_USE_PNFS_%s should be set" % server_type, terminate=True)
                    if not ds:
                        # Check for invalid combination of eir flags
                        self.test(eir_flags & EXCHGID4_FLAG_USE_NON_PNFS == 0, "EXCHGID4_FLAG_USE_NON_PNFS should not be set")
            else:
                self.test(False, "EXCHANGE_ID reply was not found")

        # Find CREATE_SESSION request
        (pktcall, pktreply) = self.find_nfs_op(OP_CREATE_SESSION, ipaddr=ipaddr, port=port, status=cs_status)
        if nocreate:
            self.test(not pktcall, "CREATE_SESSION should not be sent to %s%s" % (server_type, dsmds))
        else:
            self.test(pktcall, "CREATE_SESSION should be sent to %s" % server_type)
            if pktreply:
                if cs_status:
                    self.test(pktreply.NFSop.status == cs_status, "CREATE_SESSION reply should return %s(%d)" % (nfsstat4[cs_status], cs_status))
                    return
                else:
                    # Save the session id
                    self.sessionid = pktreply.NFSop.sessionid
                    # Save the max response size
                    self.ca_maxrespsz = pktreply.NFSop.fore_chan_attrs.maxresponsesize
                    self.dprint('DBG2', "CREATE_SESSION sessionid: %s" % self.sessionid)
                    self.dprint('DBG2', "CREATE_SESSION ca_maxrespsz: %s" % self.ca_maxrespsz)

                    fmsg = None
                    test_seq = True
                    slotid_map = {}
                    save_index = self.pktt.get_index()
                    while self.find_nfs_op(OP_SEQUENCE, ipaddr=ipaddr, port=port, call_only=True):
                        if self.pktcall is None:
                            break
                        slotid = self.pktcall.NFSop.slotid
                        seqid  = self.pktcall.NFSop.sequenceid
                        if slotid_map.get(slotid) is None:
                            # First occurrence of slot id
                            slotid_map[slotid] = seqid
                            if seqid != 1:
                                fmsg = ", slot id %d starts with sequence id %d" % (slotid, seqid)
                                test_seq = False
                                break
                    if len(slotid_map) > 0:
                        self.test(test_seq, "SEQUENCE request should start with a sequence id of 1", failmsg=fmsg)
                    else:
                        self.test(False, "SEQUENCE request was not found")
                    self.pktt.rewind(save_index)
            elif pktcall:
                self.test(False, "CREATE_SESSION reply was not found")

        # Find RECLAIM_COMPLETE request
        (pktcall, pktreply) = self.find_nfs_op(OP_RECLAIM_COMPLETE, ipaddr=ipaddr, port=port, status=None)
        if nocreate:
            self.test(not pktcall, "RECLAIM_COMPLETE should not be sent to %s%s" % (server_type, dsmds))
        else:
            self.test(pktcall, "RECLAIM_COMPLETE should be sent to %s" % server_type)
        if pktcall:
            # Make sure to start the next packet search right after the
            # RECLAIM_COMPLETE call
            self.pktt.rewind(pktcall.record.index)

        if not ds:
            # Find packet having a GETATTR asking for FATTR4_LEASE_TIME(bit 10)
            attrmatch = "NFS.request & %s != 0" % hex(1 << FATTR4_LEASE_TIME)
            (pktcall, pktreply) = self.find_nfs_op(OP_GETATTR, match=attrmatch)
            self.test(pktcall, "GETATTR should be sent to %s asking for FATTR4_LEASE_TIME" % server_type)
            if pktreply:
                lease_time = pktreply.NFSop.attributes[FATTR4_LEASE_TIME]
                self.test(lease_time > 0, "NFS server should return lease time(%d) > 0" % lease_time)
            elif pktcall:
                self.test(False, "GETATTR reply was not found")

            self.verify_pnfs_supported(self.rootfh, server_type)
            save_index = self.pktt.get_index()

            # Find if pNFS is supported for the mounted path including datadir
            path_list = []
            if len(self.datadir):
                path = os.path.join(self.export, self.datadir)
            else:
                path = self.export
            while True:
                plist = os.path.split(path)
                if plist[1] == "":
                    break
                path_list.insert(0, plist[1])
                path = plist[0]
            fullpath = "/"
            fsid_list = []
            if self.rootfsid is not None:
                fsid_list.append(self.rootfsid)
            for path in path_list:
                # Find the LOOKUP
                fullpath = os.path.join(fullpath, path)
                match = "NFS.name == '%s'" % path
                pktcall, pktreply = self.find_nfs_op(OP_LOOKUP, match=match)
                if pktreply:
                    getfh_obj   = self.getop(pktreply, OP_GETFH)
                    getattr_obj = self.getop(pktreply, OP_GETATTR)
                    if getfh_obj is None or getattr_obj is None:
                        # Could not find GETFH or GETATTR
                        continue
                    filehandle = getfh_obj.fh
                    attributes = getattr_obj.attributes
                    fsid = attributes.get(FATTR4_FSID)
                    for xfsid in fsid_list:
                        if fsid.major == xfsid.major and fsid.minor == xfsid.minor:
                            # This fsid has already been verified, so skip it
                            fsid = None
                            break
                    if fsid is not None:
                        # Save the fsid so it won't be verified again
                        fsid_list.append(fsid)
                        # Verify this path supports pNFS
                        self.verify_pnfs_supported(filehandle, server_type, path=fullpath)
            self.pktt.rewind(save_index)
        return self.sessionid

    def verify_layoutget(self, filehandle, iomode, riomode=None, status=0, offset=None, length=None):
        """Verify the client sends a LAYOUTGET for the given file handle.

           filehandle:
               Find LAYOUTGET for this file handle
           iomode:
               Expected I/O mode for LAYOUTGET call
           riomode:
               Expected I/O mode for LAYOUTGET reply if specified, else verify
               reply I/O mode is equal to call I/O mode if iomode == 2.
               If iomode == 1, the reply I/O mode could be equal to 1 or 2
           status:
               Expected status for LAYOUTGET reply [default: 0]
           offset:
               Expected layout range for LAYOUTGET reply [default: None]
           length:
               Expected layout range for LAYOUTGET reply [default: None]

           If both offset and length are not given, verify LAYOUTGET reply
           should be a full layout [0, NFS4_UINT64_MAX]. If only one is
           provided the following defaults are used: offset = 0,
           length = NFS4_UINT64_MAX.

           Layout information is stored in the object attribute layout.

           Return a tuple: (layoutget, layoutget_res, loc_body).
        """
        # Find LAYOUTGET for given filehandle
        layoutget, layoutget_res, loc_body = self.find_layoutget(filehandle)
        if layoutget is None:
            self.layout = None
            return (None, None, None)

        # Test layout type
        self.test(layoutget.type == LAYOUT4_NFSV4_1_FILES, "LAYOUTGET layout type should be LAYOUT4_NFSV4_1_FILES")

        # Test iomode
        self.test(layoutget.iomode == iomode, "LAYOUTGET iomode should be %s" % self.iomode_str(iomode))

        # Test for full file layout
        self.test(layoutget.offset == 0 and layoutget.length == NFS4_UINT64_MAX, "LAYOUTGET should ask for full file layout")

        if layoutget_res is None:
            self.test(False, "LAYOUTGET reply should be returned")
            return (layoutget, None, None)

        if status:
            self.test(layoutget_res.status == status, "LAYOUTGET reply should return error %s(%d)" % (nfsstat4[status], status))
            return (layoutget, layoutget_res, None)
        elif layoutget_res.status:
            self.test(False, "LAYOUTGET reply returned %s(%d)" % (nfsstat4[layoutget_res.status], layoutget_res.status))
            return (layoutget, layoutget_res, None)

        # Get layout from reply
        layout = layoutget_res.layout[0]

        # Test LAYOUTGET reply for correct layout type
        self.test(layout.content.type == LAYOUT4_NFSV4_1_FILES, "LAYOUTGET reply layout type should be LAYOUT4_NFSV4_1_FILES")

        # Test LAYOUTGET reply for correct iomode
        if riomode is not None:
            self.test(layout.iomode == riomode, "LAYOUTGET reply iomode is %s when asking for a %s layout" % (self.iomode_str(riomode), self.iomode_str(iomode)))
        elif iomode == LAYOUTIOMODE4_READ and layoutget.iomode in [LAYOUTIOMODE4_READ, LAYOUTIOMODE4_RW]:
            self.test(True, "LAYOUTGET reply iomode is %s when asking for a LAYOUTIOMODE4_READ layout" % self.iomode_str(layoutget.iomode))
        else:
            self.test(layout.iomode == iomode, "LAYOUTGET reply iomode should be %s" % self.iomode_str(iomode))

        if offset is None and length is None:
            # Test LAYOUTGET reply for full file layout
            self.test(layout.offset == 0 and layout.length == NFS4_UINT64_MAX, "LAYOUTGET reply should be full file layout")
        else:
            # Test LAYOUTGET reply for correct layout range
            if offset is None:
                offset = 0
            if length is None:
                length = NFS4_UINT64_MAX
            self.test(layout.offset == offset and layout.length == length, "LAYOUTGET reply should be: (offset=%d, length=%d)" % (offset, length))

        # Return layout
        self.layout = loc_body
        self.layout['return_on_close'] = layoutget_res.return_on_close
        return (layoutget, layoutget_res, loc_body)

    def verify_io(self, iomode, stateid, ipaddr=None, port=None, src_ipaddr=None, filehandle=None, ds_index=None, init=False, maxindex=None, pattern=None):
        """Verify I/O is sent to the server specified by the ipaddr and port.

           iomode:
               Verify reads (iomode == 1) or writes (iomode == 2)
           stateid:
               Expected stateid to use in all I/O requests
           ipaddr:
               Destination IP address of MDS or DS
               [default: do not match destination]
           port:
               Destination port number of MDS or DS
               [default: do not match destination port]
           src_ipaddr:
               Source IP address of request
               [default: do not match source]
           filehandle:
               Find I/O for this file handle. This option is used when
               verifying I/O sent to the MDS
               [default: use filehandle given by ds_index]
           ds_index:
               Data server index. This option is used when verifying I/O sent
               to the DS -- filehandle is taken from x.layout for this index
               [default: None]
           init:
               Initialized test variables [default: False]
           maxindex:
               The match fails if packet index hits this limit [default: no limit]
           pattern:
               Data pattern to compare [default: default data pattern]

           Return the number of I/O operations sent to the server.
        """
        if filehandle is None:
            filehandle = self.get_filehandle(ds_index)
        src = "IP.src == '%s' and " % src_ipaddr if src_ipaddr != None else ''
        dst = ''
        if ipaddr != None:
            dst = "IP.dst == '%s' and " % ipaddr
            if port != None:
                dst += "TCP.dst_port == %d and " % port
        fh = "NFS.fh == '%s'" % self.pktt.escape(filehandle)
        save_index = self.pktt.get_index()
        xids = []
        offsets = {}
        good_pattern = 0
        bad_pattern = 0
        self.test_offsets = []  # Save the offsets sent to the server on I/O
        self.test_counts = []   # Save the counts received from the server
        xid_counts = {}         # Map counts on I/O calls
        if init:
            self.test_seqid   = True
            self.test_stateid = True
            self.test_pattern = True
            self.test_niomiss = 0
            self.test_stripe  = True
            self.test_verf    = True
            self.need_commit  = False
            self.need_lcommit = False
            self.mdsd_lcommit = False
            self.stateid      = None
            self.max_iosize   = 0
            self.error_hash   = {}

        # Get I/O type: iomode == 1 (READ), else (WRITE)
        io_op = OP_READ if iomode == LAYOUTIOMODE4_READ else OP_WRITE

        # Find all I/O requests for MDS or current DS
        while True:
            # Find I/O request
            pkt = self.pktt.match(src + dst + fh + " and NFS.argop == %d" % io_op, maxindex=maxindex)
            if not pkt:
                break
            xids.append(pkt.rpc.xid)
            nfsop = pkt.NFSop
            self.test_offsets.append(nfsop.offset)
            xid_counts[pkt.rpc.xid] = nfsop.count
            if iomode == LAYOUTIOMODE4_READ:
                offsets[pkt.rpc.xid] = nfsop.offset

            if nfsop.stateid.seqid != 0:
                self.test_seqid = False
            if nfsop.stateid != stateid:
                self.test_stateid = False
            self.stateid = nfsop.stateid.other

            # Get real file offset
            file_offset = self.get_abs_offset(nfsop.offset, ds_index)

            size = nfsop.count
            if iomode != LAYOUTIOMODE4_READ:
                data = self.data_pattern(file_offset, len(nfsop.data), pattern=pattern)
                if data != nfsop.data:
                    bad_pattern += 1
                else:
                    good_pattern += 1
            if self.max_iosize < size:
                self.max_iosize = size

            # Check if I/O is sent to the MDS or correct DS according to stripe size
            if ds_index is not None and not self.verify_stripe(file_offset, size, ds_index):
                self.test_stripe = False

        # Rewind trace file to saved packet index
        self.pktt.rewind(save_index)

        if iomode == LAYOUTIOMODE4_RW:
            self.dprint('DBG7', "WRITE bad/good pattern %d/%d" % (bad_pattern, good_pattern))
            if good_pattern == 0 or float(bad_pattern)/good_pattern >= 0.25:
                self.test_pattern = False
            elif bad_pattern > 0:
                self.warning("Some WRITE packets were not capture properly")

        if len(xids) == 0:
            return 0

        # Flag showing if this DS is the same as the MDS
        dsismds = (ipaddr == self.server_ipaddr and port == self.port)

        # Find all I/O replies for MDS or current DS
        while True:
            # Find I/O reply
            pkt = self.pktt.match("NFS.resop == %d" % io_op, maxindex=maxindex)
            if not pkt:
                break
            xid = pkt.rpc.xid
            if xid in xids:
                xids.remove(xid)
                nfsop = pkt.NFSop

                self.test_counts.append(nfsop.count)
                xid_counts.pop(xid, None)
                if iomode == LAYOUTIOMODE4_READ:
                    offset = offsets[xid]

                    # Get real file offset
                    file_offset = self.get_abs_offset(offset, ds_index)

                    data = self.data_pattern(file_offset, len(nfsop.data), pattern=pattern)
                    if data != nfsop.data:
                        bad_pattern += 1
                    else:
                        good_pattern += 1
                else:
                    if pkt.nfs.status == NFS4_OK:
                        if not dsismds:
                            self.mdsd_lcommit = True
                        if nfsop.committed < FILE_SYNC4:
                            # Need layout commit if reply is not FILE_SYNC4
                            self.need_lcommit = True
                        if nfsop.committed == UNSTABLE4:
                            # Need commit if reply is UNSTABLE4
                            self.need_commit = True
                        if self.writeverf is None:
                            self.writeverf = nfsop.verifier
                        if self.writeverf != nfsop.verifier:
                            self.test_verf = False
                    else:
                        # Server returned error for this I/O operation
                        errstr = nfsstat4.get(pkt.nfs.status)
                        if self.error_hash.get(errstr) is None:
                            self.error_hash[errstr] = 1
                        else:
                            self.error_hash[errstr] += 1

                if len(xids) == 0:
                    break
            else:
                # Call was not found for this reply
                self.test_niomiss += 1
        # Add the number of calls with no replies
        self.test_niomiss += len(xids)
        nops = good_pattern + bad_pattern + self.test_niomiss

        # Append I/O call counts for those replies which were not found
        for count in xid_counts.values():
            self.test_counts.append(count)

        if iomode == LAYOUTIOMODE4_READ:
            self.dprint('DBG7', "READ bad/good pattern %d/%d" % (bad_pattern, good_pattern))
            if good_pattern == 0 or float(bad_pattern)/good_pattern >= 0.25:
                self.test_pattern = False
            elif bad_pattern > 0:
                self.warning("Some READ packets were not capture properly")

        if len(xids) > 0:
            self.warning("Could not find all replies to %s" % ('READ' if iomode == LAYOUTIOMODE4_READ else 'WRITE'))

        return nops

    def verify_commit(self, ipaddr, port, filehandle, init=False):
        """Verify commits are properly sent to the server specified by the
           given ipaddr and port.

           ipaddr:
               Destination IP address of MDS or DS
           port:
               Destination port number of MDS or DS
           filehandle:
               Find commits for this file handle
           init:
               Initialized test variables [default: False]

           Return the number of commits sent to the server.
        """
        dst = self.pktt.ip_tcp_dst_expr(ipaddr, port)
        fh = "NFS.fh == '%s'" % self.pktt.escape(filehandle)
        save_index = self.pktt.get_index()
        xids = []
        if init:
            self.test_commit_full = True
            self.test_no_commit   = False
            self.test_commit_verf = True

        while True:
            # Find COMMIT request for current DS
            pkt = self.pktt.match(dst + " and " + fh + " and NFS.argop == %d" % OP_COMMIT)
            if not pkt:
                break
            xids.append(pkt.rpc.xid)
            nfscommit = pkt.NFSop
            if nfscommit.offset != 0 or nfscommit.count != 0:
                self.test_commit_full = False

        ncommits = len(xids)
        if ncommits == 0:
            # No COMMIT was found
            self.test_no_commit = True
            return 0

        # Rewind trace file to saved packet index
        self.pktt.rewind(save_index)
        while True:
            # Find COMMIT reply for current DS
            pkt = self.pktt.match("NFS.resop == %d" % OP_COMMIT)
            if not pkt:
                break
            if pkt.rpc.xid in xids:
                nfscommit = pkt.NFSop
                if self.writeverf != nfscommit.verifier:
                    self.test_commit_verf = False

        return ncommits

    def verify_layoutcommit(self, filehandle, filesize):
        """Verify layoutcommit is properly sent to the server specified by
           the ipaddr for self.server and port given by self.port.
           Verify a GETATTR asking for file size is sent within the same
           compound as the LAYOUTCOMMIT.
           Verify GETATTR returns correct size for the file.

           filehandle:
               Find layoutcommit for this file handle
           filesize:
               Expected size of file
        """
        dst = self.pktt.ip_tcp_dst_expr(self.server_ipaddr, self.port)
        fh = "NFS.fh == '%s'" % self.pktt.escape(filehandle)

        # Find LAYOUTCOMMIT request
        pkt = self.pktt.match(dst + " and " + fh + " and NFS.argop == %d" % OP_LAYOUTCOMMIT)
        if self.layout['commit_mds']:
            self.test(not pkt, "LAYOUTCOMMIT should not be sent to MDS when NFL4_UFLG_COMMIT_THRU_MDS is set")
        else:
            if self.need_lcommit:
                if self.mdsd_lcommit:
                    self.test(pkt, "LAYOUTCOMMIT should be sent to MDS when NFL4_UFLG_COMMIT_THRU_MDS is not set")
                else:
                    self.test(not pkt, "LAYOUTCOMMIT should not be sent to MDS when DS == MDS")
            else:
                self.test(not pkt, "LAYOUTCOMMIT should not be sent to MDS (FILE_SYNC4)")
            if not pkt:
                return

            xid = pkt.rpc.xid
            layoutcommit = pkt.NFSop
            range_expr = layoutcommit.offset == 0 and layoutcommit.length in (filesize, NFS4_UINT64_MAX)
            self.test(range_expr, "LAYOUTCOMMIT should be sent to MDS with correct file range")
            self.test(layoutcommit.stateid == self.layout['stateid'], "LAYOUTCOMMIT should use the layout stateid")
            self.test(layoutcommit.last_write_offset.newoffset, "LAYOUTCOMMIT new offset should be set")
            self.test(layoutcommit.last_write_offset.offset == (filesize - 1),
                      "LAYOUTCOMMIT last write offset (%d) should be one less than the file size (%d)" % (layoutcommit.last_write_offset.offset, filesize))
            self.test(layoutcommit.layoutupdate.type == LAYOUT4_NFSV4_1_FILES, "LAYOUTCOMMIT layout type should be LAYOUT4_NFSV4_1_FILES")
            self.test(len(layoutcommit.layoutupdate.body) == 0, "LAYOUTCOMMIT layout update field should be empty for LAYOUT4_NFSV4_1_FILES")

            # Verify a GETATTR asking for file size is sent with LAYOUTCOMMIT
            idx = pkt.NFSidx
            getattr_arg = pkt.nfs.array[idx+1]
            self.test(getattr_arg.request & (1 << FATTR4_SIZE), "GETATTR asking for file size is sent within LAYOUTCOMMIT compound")

            # Find LAYOUTCOMMIT reply
            pkt = self.pktt.match("RPC.xid == %d and NFS.resop == %d" % (xid, OP_LAYOUTCOMMIT))
            layoutcommit = pkt.NFSop
            if layoutcommit.newsize.sizechanged:
                self.test(True, "LAYOUTCOMMIT reply file size changed should be set")
                ns_size = layoutcommit.newsize.size
                if ns_size == filesize:
                    self.test(True, "LAYOUTCOMMIT reply file size should be correct (%d)" % ns_size)
                else:
                    self.warning("LAYOUTCOMMIT reply file size is not correct (%d)" % ns_size)
            else:
                self.test(True, "LAYOUTCOMMIT reply file size changed is not set (ERRATA)")

            # Verify GETATTR returns correct file size
            idx = pkt.NFSidx
            getattr_res = pkt.nfs.array[idx+1]
            self.test(getattr_res.attributes[FATTR4_SIZE] == filesize, "GETATTR should return correct file size within LAYOUTCOMMIT compound")
        return

    def get_stateid(self, filename, **kwargs):
        """Search the packet trace for the file name given to get the OPEN
           so all related state ids can be searched. A couple of object
           attributes are defined, one is the correct state id that should
           be used by I/O operations. The second is a dictionary table
           which maps the state id to a string identifying if the state
           id is an open, lock or delegation state id.

           ipaddr:
               Destination IP address [default: self.server_ipaddr]
           port:
               Destination port [default: self.port]
           noreset:
               Do not reset the state id map [default: False]
        """
        noreset = kwargs.pop("noreset", False)
        if not noreset:
            self.stid_map = {}
        self.lock_stateid = None
        (self.filehandle, self.open_stateid, self.deleg_stateid) = self.find_open(filename=filename, **kwargs)
        if self.open_stateid:
            self.stid_map[self.open_stateid] = "OPEN stateid"
        if self.deleg_stateid:
            # Delegation stateid should be used for I/O
            self.stateid = self.deleg_stateid
            self.stid_map[self.deleg_stateid] = "DELEG stateid"
        else:
            # Look for a lock stateid
            save_index = self.pktt.get_index()
            argl = ("ipaddr", "port")
            args = dict((k, kwargs[k]) for k in kwargs if k in argl)
            args["match"] = "NFS.fh == '%s'" % self.pktt.escape(self.filehandle)
            (pktcall, pktreply) = self.find_nfs_op(OP_LOCK, **args)
            if pktreply:
                self.lock_stateid = pktreply.NFSop.stateid.other
                self.stid_map[self.lock_stateid] = "LOCK stateid"
                self.stateid = self.lock_stateid
            else:
                # Open stateid should be used for I/O
                self.stateid = self.open_stateid
            self.pktt.rewind(save_index)
        return self.stateid

    def get_clientid(self, **kwargs):
        """Return the client id for the given IP address and port number.

           ipaddr:
               Destination IP address [default: self.server_ipaddr]
           port:
               Destination port [default: self.port]
        """
        self.clientid = None
        if self.nfsversion > 4:
            # Find the EXCHANGE_ID packets
            self.find_nfs_op(OP_EXCHANGE_ID, **kwargs)
            if self.pktreply:
                self.clientid = self.pktreply.NFSop.clientid
        elif self.nfsversion == 4:
            # Find the SETCLIENTID packets
            self.find_nfs_op(OP_SETCLIENTID, **kwargs)
            if self.pktreply:
                self.clientid = self.pktreply.NFSop.clientid
        return self.clientid

    def get_sessionid(self, **kwargs):
        """Return the session id for the given IP address and port number.

           clientid:
               Search the CREATE_SESSION tied to this client id [default: None]
           ipaddr:
               Destination IP address [default: self.server_ipaddr]
           port:
               Destination port [default: self.port]
        """
        if self.nfsversion < 4.1:
            return
        self.sessionid = None
        clientid = kwargs.pop('clientid', None)
        if clientid is not None:
            # Get the session id tied to the client id from the cache
            self.sessionid = self.sessionid_map.get(clientid)
            kwargs["match"] = "NFS.clientid == %d" % clientid
        # Find the CREATE_SESSION packets for the exchange id if given
        self.find_nfs_op(OP_CREATE_SESSION, **kwargs)
        if self.pktreply:
            # Save the session id from the reply
            self.sessionid = self.pktreply.NFSop.sessionid
            self.sessionid_map[clientid] = self.sessionid
        return self.sessionid

    def get_rootfh(self, **kwargs):
        """Return the root file handle from PUTROOTFH

           sessionid:
               Search the PUTROOTFH tied to this session id [default: None]
           ipaddr:
               Destination IP address [default: self.server_ipaddr]
           port:
               Destination port [default: self.port]
        """
        self.rootfh = None
        sessionid = kwargs.pop('sessionid', None)
        if sessionid is not None:
            fh = self.rootfh_map.get(sessionid)
            if fh is not None:
                # Return root fh found in the cache
                self.rootfh = fh
                return fh
            kwargs["match"] = "str(NFS.sessionid) == '%s'" % sessionid
        # Find the PUTROOTFH packets for the session id if given
        self.find_nfs_op(OP_PUTROOTFH, **kwargs)
        if self.pktreply:
            # Get the GETFH object from the packet
            getfh = self.getop(self.pktreply, OP_GETFH)
            if getfh:
                self.rootfh = getfh.fh
                return getfh.fh

    def get_pathfh(self, path, dirfh=None):
        """Return the file handle for the given path by searching the packet
           trace for every component in the path.
           The file handle for each component is used to search for the file
           handle in the next component.

           path:
               File system path
           dirfh:
               Directory file handle to start with [default: None]
        """
        self.pktcall  = None
        self.pktreply = None
        # Break path into its directory components
        path_list = split_path(path)
        while len(path_list):
            # Get next path component
            name = path_list.pop(0)
            if dirfh is None:
                dirmatch = ""
            else:
                dirmatch = "crc32(nfs.fh) == %d and " % crc32(dirfh)
            # Match any operation with a name attribute,
            # e.g., LOOKUP, CREATE, etc.
            mstr = "%snfs.name == '%s'" % (dirmatch, name)
            while self.pktt.match(mstr, rewind=False, reply=True):
                pkt = self.pktt.pkt
                if pkt.rpc.type == 0:
                    # Save packet call
                    self.pktcall = pkt
                else:
                    # Save packet reply
                    self.pktreply = pkt
                    if hasattr(pkt.nfs, "status") and pkt.nfs.status == 0:
                        # Get GETFH from the packet reply where name was matched
                        getfh = self.getop(pkt, OP_GETFH)
                        if getfh:
                            # Set file handle for next iteration
                            dirfh = getfh.fh
                            break
            if self.pktt.pkt is None:
                # The name was not matched, so return None
                return
        return dirfh

    def stid_str(self, stateid):
        """Display the state id in CRC16 format"""
        stid = self.format("{0:crc16}", stateid)
        return self.stid_map.get(stateid, stid)

    def get_freebytes(self, dir=None):
        """Get the number of bytes available in the given directory.
           It takes into account the effective user running the test.
           The root user is allowed to use all the available disk space
           on the device, on the other hand a regular user is allowed a
           little bit less.
        """
        if dir is None:
            dir = self.mtdir
        statvfs = os.statvfs(dir)
        if os.getuid() == 0:
            # Use free blocks if root user
            return statvfs.f_bsize * (statvfs.f_bfree-1)
        else:
            # Use free blocks available for a non-root user
            return statvfs.f_bsize * (statvfs.f_bavail-1)

    @staticmethod
    def iomode_str(iomode):
        """Return a string representation of iomode.
           This could be run as an instance or class method.
        """
        if layoutiomode4.get(iomode):
            return layoutiomode4[iomode]
        else:
            return str(iomode)

    @staticmethod
    def bitmap_str(bitmap, count, bmap, blist):
        """Return the string representation of bitmap.

           bitmap:
               Bitmap to convert
           count:
               Number of occurrences of bitmap
           bmap:
               Dictionary mapping the bits to strings
           blist:
               List of all possible bit combinations
        """
        # Get number of instances of bitmap
        cnt = 0
        for item in blist:
            if bitmap & item == bitmap:
                cnt += 1
        plist = []
        bit = max(bmap.keys())

        # Convert bitmap to a string
        while bit > 0:
            if bitmap & bit:
                plist.append(bmap[bit])
            bit = bit >> 1
        if cnt == count:
            return " & ".join(plist)
        return
