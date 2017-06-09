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
NFS module

Process the NFS layer and return the correct NFS object. The function returns
either a NULL(), CB_NULL, COMPOUND or CB_COMPOUND object.
"""
import nfstest_config as c
from packet.utils import *
from packet.nfs.nfsbase import *
from packet.nfs.nfs3 import NFS3args,NFS3res
from packet.nfs.nfs4 import COMPOUND4args,COMPOUND4res,CB_COMPOUND4args,CB_COMPOUND4res

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2014 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.2"

def NFS(rpc, callback):
    """Process the NFS layer and return the correct NFS object"""
    ret = None
    unpack = rpc._pktt.unpack

    if rpc.procedure == 0:
        # NULL object
        if callback:
            ret = CB_NULL()
        else:
            ret = NULL()
    elif rpc.procedure == 1 and ((not callback and rpc.version == 4) or
                           (callback and rpc.version == 1)):
        # NFSv4.x object including callback objects
        if rpc.type == RPC_CALL:
            # RPC call
            if callback:
                ret = CB_COMPOUND4args(unpack)
            else:
                ret = COMPOUND4args(unpack)
        else:
            # RPC reply
            minorversion = None
            pkt_call = rpc._pktt.pkt_call
            if pkt_call is not None and hasattr(pkt_call, "nfs"):
                minorversion = getattr(pkt_call.nfs, "minorversion", None)
            if callback:
                ret = CB_COMPOUND4res(unpack, minorversion)
            else:
                ret = COMPOUND4res(unpack, minorversion)
    elif rpc.version == 3:
        if rpc.type == RPC_CALL:
            # RPC call
            ret = NFS3args(unpack, rpc.procedure)
        else:
            # RPC reply
            ret = NFS3res(unpack, rpc.procedure)

    ret.callback = callback
    return ret
