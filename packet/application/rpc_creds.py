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
RPC Credentials module

Decode RPC Credentials.
"""
import gss
import gss_const
import rpc_const
import nfstest_config as c
from packet.utils import *
from baseobj import BaseObj

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2014 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.2"

class auth_flavor(Enum):
    """enum auth_flavor"""
    _enumdict = rpc_const.auth_flavor

class rpc_gss_proc(Enum):
    """enum rpc_gss_proc"""
    _enumdict = gss_const.rpc_gss_proc

class rpc_gss_service(Enum):
    """enum rpc_gss_service"""
    _enumdict = gss_const.rpc_gss_service

class AuthNone(BaseObj):
    """AuthNone object"""
    # Class attributes
    flavor = auth_flavor(rpc_const.AUTH_NONE)
    _strfmt2  = "{0}"
    _attrlist = ("flavor",)

    def __init__(self, unpack):
        """Constructor which takes the Unpack object as input"""
        # Discard the length of data which should be 0
        unpack.unpack_uint()

class AuthSys(BaseObj):
    """AuthSys object"""
    # Class attributes
    flavor = auth_flavor(rpc_const.AUTH_SYS)
    _strfmt2  = "{0}({4}:{5})"
    _attrlist = ("flavor", "size", "stamp", "machine", "uid", "gid", "gids")

    def __init__(self, unpack):
        """Constructor which takes the Unpack object as input"""
        self.size    = unpack.unpack_uint()
        self.stamp   = unpack.unpack_uint()
        self.machine = unpack.unpack_opaque(maxcount=255)
        self.uid     = unpack.unpack_uint()
        self.gid     = unpack.unpack_uint()
        self.gids    = unpack.unpack_array(maxcount=16)

class GSS_Credential(BaseObj):
    """GSS_Credential object"""
    # Class attributes
    flavor = auth_flavor(rpc_const.RPCSEC_GSS)
    _strfmt2  = "{0}({3}:{5:@12})"
    _attrlist = ("flavor", "size", "gss_version", "gss_proc", "gss_seq_num",
                 "gss_service", "gss_context")

    def __init__(self, unpack):
        """Constructor which takes the Unpack object as input"""
        self.size        = unpack.unpack_uint()
        self.gss_version = unpack.unpack_uint()
        self.gss_proc    = rpc_gss_proc(unpack.unpack_uint())
        self.gss_seq_num = unpack.unpack_uint()
        self.gss_service = rpc_gss_service(unpack.unpack_uint())
        self.gss_context = unpack.unpack_opaque()

class GSS_Verifier(BaseObj):
    """GSS_Verifier object"""
    # Class attributes
    flavor = auth_flavor(rpc_const.RPCSEC_GSS)
    _strfmt2  = "{0}"
    _attrlist = ("flavor", "size", "gss_token")

    def __init__(self, unpack):
        """Constructor which takes the Unpack object as input"""
        self.gss_token = unpack.unpack_opaque()
        self.size      = len(self.gss_token)
        try:
            krb5 = gss.GSS_API(self.gss_token)
            if krb5:
                self.gss_token = krb5
        except:
            pass

def rpc_credential(unpack, verifier=False):
    """Process and return the credential or verifier"""
    try:
        # Get credential/verifier flavor
        flavor = unpack.unpack_uint()
        if flavor == rpc_const.AUTH_SYS:
            return AuthSys(unpack)
        elif flavor == rpc_const.AUTH_NONE:
            return AuthNone(unpack)
        elif flavor == rpc_const.RPCSEC_GSS:
            if verifier:
                return GSS_Verifier(unpack)
            else:
                return GSS_Credential(unpack)
    except:
        return None
